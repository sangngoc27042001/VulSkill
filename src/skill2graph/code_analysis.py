"""Lightweight intra-file taint analysis for skill scripts.

Each analyzer returns a :class:`ScriptSummary`: script inputs (argv positions, flags,
stdin), sources, operators (sinks / sanitizers / neutral), and flows between them, all
with line evidence. ``build.py`` turns a summary into graph nodes.

Backends implement :class:`CodeAnalyzer`; register new ones (e.g. a Semgrep backend)
with :func:`register_analyzer`.
"""

from __future__ import annotations

import ast
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

SECRET_NAME_RE = re.compile(r"TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH", re.I)
AGENT_CONFIG_RE = re.compile(
    r"(^|[/\\'\"\s])(CLAUDE\.md|CLAUDE\.local\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|"
    r"copilot-instructions\.md|\.claude[/\\]|\.cursor[/\\]rules|\.mcp\.json)",
)


def is_agent_config_path(text: str | None) -> bool:
    return bool(text) and bool(AGENT_CONFIG_RE.search(" " + text))


@dataclass
class Evidence:
    file: str
    lines: list[int]
    quote: str

    def to_dict(self) -> dict:
        return {"file": self.file, "lines": self.lines, "quote": self.quote}


@dataclass
class CInput:
    """A script input port (argv position, CLI flag, stdin)."""

    id: str
    name: str  # e.g. argv[1], --url, stdin, argv[*]
    position: int | None
    flag: str | None
    evidence: Evidence


@dataclass
class CSource:
    id: str
    category: str
    trust: str
    label: str
    evidence: Evidence
    found_in: str = "code"


@dataclass
class COperator:
    id: str
    role: str  # sink | sanitizer | neutral
    label: str
    evidence: Evidence
    sink_category: str | None = None


@dataclass
class ScriptSummary:
    path: str
    lang: str
    analyzer: str
    inputs: list[CInput] = field(default_factory=list)
    sources: list[CSource] = field(default_factory=list)
    operators: list[COperator] = field(default_factory=list)
    flows: set[tuple[str, str]] = field(default_factory=set)  # (from id, to id); ids are local
    refers: list[tuple[str, int]] = field(default_factory=list)  # (other file path/module, line)
    warnings: list[str] = field(default_factory=list)

    def input_by_position(self, pos: int) -> CInput | None:
        for i in self.inputs:
            if i.position == pos:
                return i
        for i in self.inputs:
            if i.name == "argv[*]":
                return i
        return None

    def input_by_flag(self, flag: str) -> CInput | None:
        norm = flag.lstrip("-").replace("-", "_")
        for i in self.inputs:
            if i.flag and i.flag.lstrip("-").replace("-", "_") == norm:
                return i
        return None


class CodeAnalyzer(ABC):
    """Interface for a code analysis backend."""

    name: str = "abstract"

    @abstractmethod
    def supports(self, path: Path, lang: str | None) -> bool: ...

    @abstractmethod
    def analyze(self, path: Path, rel: str) -> ScriptSummary: ...


class _Ids:
    def __init__(self):
        self.n = 0

    def __call__(self, prefix: str) -> str:
        self.n += 1
        return f"{prefix}{self.n}"


# --------------------------------------------------------------------------- Python


NET_SEND = {"post", "put", "patch", "delete", "request"}
NET_ALL = NET_SEND | {"get", "head", "options", "stream"}
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
SUBPROC = {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}


class _PyTaint(ast.NodeVisitor):
    MAX_DEPTH = 6

    def __init__(self, rel: str, src: str, summary: ScriptSummary, path: Path | None = None):
        self.rel = rel
        self.home_rel = rel
        self.src_lines = src.split("\n")
        self.path = path
        # skill root = the file's path with ``rel`` removed
        self.root = path.parents[len(Path(rel).parts) - 1] if path is not None else None
        self.mod_funcs: dict[str, dict[str, ast.FunctionDef]] = {}  # import alias -> functions of a local module
        self.fn_origin: dict[int, tuple[str, list[str]]] = {}  # id(fn) -> (rel, source lines) for imported functions
        self.s = summary
        self.ids = _Ids()
        self.aliases: dict[str, str] = {}  # local name -> dotted module path
        self.funcs: dict[str, ast.FunctionDef] = {}
        self.called: set[str] = set()
        self.memo: dict[tuple, set[str]] = {}
        self.argparse_vars: set[str] = set()
        self.argparse_dest: dict[str, CInput] = {}
        self.positional_count = 0
        self.realpath_vars: set[str] = set()
        self.handles: dict[str, str] = {}  # var -> write operator id / "socket"
        self.keyed: dict[tuple, str] = {}
        self.depth = 0
        self.returns: list[set[str]] = []

    # ---------------------------------------------------------------- helpers
    def ev(self, node: ast.AST) -> Evidence:
        ln = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", ln) or ln
        quote = self.src_lines[ln - 1].strip() if 0 < ln <= len(self.src_lines) else ""
        return Evidence(self.rel, sorted({ln, end}), quote)

    def _key(self, kind, node, extra=""):
        return (kind, self.rel, getattr(node, "lineno", 0), getattr(node, "col_offset", 0), extra)

    def input(self, node, name, position=None, flag=None) -> str:
        for i in self.s.inputs:
            if i.name == name:
                return i.id
        i = CInput(self.ids("in"), name, position, flag, self.ev(node))
        self.s.inputs.append(i)
        return i.id

    def source(self, node, category, trust, label) -> str:
        k = self._key("src", node, category)
        if k not in self.keyed:
            sid = self.ids("src")
            self.s.sources.append(CSource(sid, category, trust, label, self.ev(node),
                                          "environment" if category == "env_secret" else "code"))
            self.keyed[k] = sid
        return self.keyed[k]

    def operator(self, node, role, label, sink=None, taint: set[str] | None = None) -> str:
        if self.rel != self.home_rel:
            label = f"{label} (in {self.rel.rsplit('/', 1)[-1]})"
        k = self._key("op", node, label)
        if k not in self.keyed:
            oid = self.ids("op")
            self.s.operators.append(COperator(oid, role, label, self.ev(node), sink))
            self.keyed[k] = oid
        oid = self.keyed[k]
        for t in taint or ():
            self.s.flows.add((t, oid))
        return oid

    def dotted(self, node) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    @staticmethod
    def const_str(node) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        return None

    def kw(self, call: ast.Call, name: str):
        for k in call.keywords:
            if k.arg == name:
                return k.value
        return None

    # ---------------------------------------------------------------- expressions
    def taint(self, node, env) -> set[str]:
        if node is None:
            return set()
        m = getattr(self, "t_" + type(node).__name__, None)
        if m:
            return m(node, env)
        out: set[str] = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                out |= self.taint(child, env)
        return out

    def t_Constant(self, node, env):
        return set()

    def t_Name(self, node, env):
        return set(env.get(node.id, set()))

    def t_Subscript(self, node, env):
        d = self.dotted(node.value)
        if d == "sys.argv":
            sl = node.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, int):
                return {self.input(node, f"argv[{sl.value}]", position=sl.value)}
            return {self.input(node, "argv[*]")}
        if d == "os.environ":
            name = self.const_str(node.slice) or "?"
            return {self._env_source(node, name)}
        return self.taint(node.value, env) | self.taint(node.slice, env)

    def t_Attribute(self, node, env):
        if isinstance(node.value, ast.Name) and node.value.id in self.argparse_vars:
            inp = self.argparse_dest.get(node.attr)
            if inp:
                return {inp.id}
            return {self.input(node, f"--{node.attr}", flag=f"--{node.attr}")}
        d = self.dotted(node)
        if d == "sys.argv":
            return {self.input(node, "argv[*]")}
        if d == "sys.stdin":
            return {self.input(node, "stdin")}
        return self.taint(node.value, env)

    def t_Lambda(self, node, env):
        return set()

    def _comp(self, node, env):
        env2 = dict(env)
        for gen in node.generators:
            t = self.taint(gen.iter, env2)
            for n in ast.walk(gen.target):
                if isinstance(n, ast.Name):
                    env2[n.id] = t
        out = set()
        for part in ("elt", "key", "value"):
            if hasattr(node, part):
                out |= self.taint(getattr(node, part), env2)
        return out

    t_ListComp = t_SetComp = t_GeneratorExp = t_DictComp = _comp

    def _env_source(self, node, name: str) -> str:
        if SECRET_NAME_RE.search(name):
            return self.source(node, "env_secret", "secret", f"env {name}")
        return self.source(node, "env_var", "trusted", f"env {name}")

    def t_Call(self, node: ast.Call, env):
        f = node.func
        d = self.dotted(f) or ""
        last = d.rsplit(".", 1)[-1] if d else (f.attr if isinstance(f, ast.Attribute) else "")
        argt = set()
        for a in node.args:
            argt |= self.taint(a, env)
        for k in node.keywords:
            argt |= self.taint(k.value, env)
        recv = self.taint(f.value, env) if isinstance(f, ast.Attribute) else set()

        # --- argparse
        if last == "add_argument" and node.args:
            names = [self.const_str(a) for a in node.args]
            names = [n for n in names if n]
            if names:
                flags = [n for n in names if n.startswith("-")]
                dest_node = self.kw(node, "dest")
                if flags:
                    flag = max(flags, key=len)
                    dest = self.const_str(dest_node) if dest_node else flag.lstrip("-").replace("-", "_")
                    inp = CInput(self.ids("in"), flag, None, flag, self.ev(node))
                else:
                    self.positional_count += 1
                    dest = names[0]
                    inp = CInput(self.ids("in"), f"argv[{self.positional_count}]", self.positional_count,
                                 None, self.ev(node))
                    inp.name = f"argv[{self.positional_count}] ({dest})"
                self.s.inputs.append(inp)
                self.argparse_dest[dest] = inp
            return set()
        if last in ("parse_args", "parse_known_args"):
            return {"__argparse__"}

        # --- sources
        if d in ("input", "builtins.input"):
            return {self.source(node, "user_prompt", "trusted", "input()")}
        if d in ("os.getenv", "os.environ.get"):
            name = self.const_str(node.args[0]) if node.args else "?"
            return {self._env_source(node, name or "?")}
        if d.startswith("sys.stdin"):
            return {self.input(node, "stdin")}
        if d in ("open", "io.open", "codecs.open") or last in ("read_text", "read_bytes", "write_text", "write_bytes"):
            return self._file_call(node, d, last, argt, recv, env)
        mod = d.split(".", 1)[0]
        if mod in ("requests", "httpx", "aiohttp") or d.startswith(("urllib.request", "http.client")) or (
            last in NET_ALL and isinstance(f, ast.Attribute) and self.dotted(f.value) in ("session", "s", "client")
        ):
            if last in NET_SEND or last == "urlopen" and self.kw(node, "data") is not None or last == "Request":
                if argt:
                    self.operator(node, "sink", f"{d}(...) send", "network_egress", argt)
            if last in NET_ALL or last in ("urlopen", "Request"):
                return {self.source(node, "web_content", "untrusted", f"{d}() response")}
        if d.startswith("socket."):
            if last in ("socket", "create_connection"):
                return {"__socket__"}
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and self.handles.get(f.value.id) == "socket":
            if last in ("send", "sendall", "sendto", "connect"):
                self.operator(node, "sink", f"socket.{last}", "network_egress", argt)
            if last in ("recv", "recvfrom", "makefile"):
                return {self.source(node, "web_content", "untrusted", f"socket.{last}")}
            return set()

        # --- shell / exec sinks
        if d in ("os.system", "os.popen", "commands.getoutput"):
            self.operator(node, "sink", f"{d}", "shell_exec", argt)
            if d != "os.system":
                return {self.source(node, "other_script_output", "untrusted", f"{d} output")}
            return set()
        if mod == "subprocess" and last in SUBPROC:
            return self._subprocess(node, d, last, env)
        if d.startswith("os.exec") or d.startswith("os.spawn"):
            if argt:
                self.operator(node, "sanitizer", f"{d} (argv, no shell)", None, argt)
            return set()
        if d in ("eval", "exec", "compile", "builtins.eval", "builtins.exec"):
            self.operator(node, "sink", f"{d}()", "code_eval", argt)
            return set()

        # --- stdout / logging
        if d in ("print", "pprint.pprint", "sys.stdout.write", "sys.stderr.write") or (
            last in LOG_METHODS and (mod in ("logging", "logger", "log", "LOGGER", "LOG") or "logger" in d.lower())
        ):
            self.operator(node, "sink", f"{d or last}()", "context_output", argt)
            return set()

        # --- sanitizers
        if d in ("shlex.quote", "pipes.quote"):
            if argt:
                return {self.operator(node, "sanitizer", "shlex.quote", None, argt)}
            return set()
        if d in ("os.path.realpath", "os.path.abspath") or last == "resolve":
            return argt | recv

        # --- write handle methods
        if isinstance(f, ast.Attribute) and last in ("write", "writelines"):
            chained = [x.split(":", 1)[1] for x in recv if x.startswith("__handle__:")]  # open(p, "w").write(x)
            if chained:
                for op in chained:
                    for a in node.args:
                        for t in self.taint(a, env):
                            self._content_flow(t, op)
                return set()
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in self.handles:
            op = self.handles[f.value.id]
            if last in ("write", "writelines") and op != "socket":
                for t in argt:
                    self._content_flow(t, op)
            return set()

        # --- local functions
        if isinstance(f, ast.Name) and f.id in self.funcs:
            return self._call_local(f.id, node, env)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.attr in self.mod_funcs.get(f.value.id, {}):
            return self._call_local(f"{f.value.id}.{f.attr}", node, env, fn=self.mod_funcs[f.value.id][f.attr])
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in ("self", "cls") and f.attr in self.funcs:
            return self._call_local(f.attr, node, env)

        return argt | recv

    def _file_call(self, node, d, last, argt, recv, env):
        mode = "r"
        if d.endswith("open"):
            m = node.args[1] if len(node.args) > 1 else self.kw(node, "mode")
            mode = self.const_str(m) or "r"
            path_node = node.args[0] if node.args else None
        else:
            path_node = node.func.value if isinstance(node.func, ast.Attribute) else None
            mode = "w" if last.startswith("write") else "r"
        path_text = self.const_str(path_node) if path_node is not None else None
        if path_text is None and path_node is not None:
            path_text = ast.unparse(path_node)
        path_taint = self.taint(path_node, env) if path_node is not None else set()
        if any(c in mode for c in "wax+"):
            sink = "agent_config_write" if is_agent_config_path(path_text) else "file_write"
            op = self.operator(node, "sink", f"write {path_text}", sink, path_taint)
            if last.startswith("write"):
                for a in node.args:
                    for t in self.taint(a, env):
                        self._content_flow(t, op)
            return {f"__handle__:{op}"}
        if path_text and "__file__" in path_text:
            return {self.source(node, "skill_file", "trusted", f"read skill file {path_text}")} | path_taint
        return {self.source(node, "workspace_file_content", "untrusted", f"read {path_text}")} | path_taint

    def _subprocess(self, node, d, last, env):
        shell = self.kw(node, "shell")
        shell_true = isinstance(shell, ast.Constant) and shell.value is True
        cmd = node.args[0] if node.args else self.kw(node, "args")
        cmd_t = self.taint(cmd, env) if cmd is not None else set()
        string_cmd = isinstance(cmd, (ast.JoinedStr, ast.BinOp)) or (
            isinstance(cmd, ast.Constant) and isinstance(cmd.value, str)
        )
        if last in ("getoutput", "getstatusoutput") or shell_true or string_cmd:
            self.operator(node, "sink", f"{d}(shell)", "shell_exec", cmd_t)
        elif cmd_t:
            self.operator(node, "sanitizer", f"{d} list-form (no shell)", None, cmd_t)
        captures = last in ("check_output", "getoutput", "getstatusoutput") or self.kw(node, "capture_output") is not None or (
            self.kw(node, "stdout") is not None
        )
        if captures:
            return {self.source(node, "other_script_output", "untrusted", f"{d} output")}
        return set()

    def _call_local(self, name, node, env, fn=None):
        fn = fn or self.funcs[name]
        self.called.add(name)
        params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
        if params and params[0] in ("self", "cls"):
            params = params[1:]
        penv: dict[str, set[str]] = {}
        for p, a in zip(params, node.args):
            penv[p] = self.taint(a, env)
        for k in node.keywords:
            if k.arg:
                penv[k.arg] = self.taint(k.value, env)
        key = (id(fn), tuple(sorted((k, frozenset(v)) for k, v in penv.items())))
        if key in self.memo:
            return self.memo[key]
        if self.depth >= self.MAX_DEPTH:
            return set().union(*penv.values()) if penv else set()
        self.memo[key] = set()
        self.depth += 1
        fenv = dict(self.globals_env)
        fenv.update(penv)
        self.returns.append(set())
        origin = self.fn_origin.get(id(fn))
        saved = (self.rel, self.src_lines)
        if origin:  # evaluate an imported function with its own file for evidence
            self.rel, self.src_lines = origin
        try:
            self.block(fn.body, fenv)
        finally:
            self.rel, self.src_lines = saved
        ret = self.returns.pop()
        self.depth -= 1
        self.memo[key] = ret
        return ret

    # ---------------------------------------------------------------- local modules
    def _resolve_module(self, module: str) -> Path | None:
        """Find ``module`` as a .py file next to the importing script or under the skill root."""
        if self.path is None or not module:
            return None
        rel_mod = Path(*module.split("."))
        for base in (self.path.parent, self.root, self.root / "scripts"):
            for cand in (base / rel_mod.with_suffix(".py"), base / rel_mod / "__init__.py"):
                if cand.is_file() and cand.resolve() != self.path.resolve():
                    return cand
        return None

    def _load_module(self, file: Path) -> dict[str, ast.FunctionDef]:
        try:
            src = file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except (OSError, SyntaxError):
            return {}
        rel = file.resolve().relative_to(self.root.resolve()).as_posix()
        lines = src.split("\n")
        funcs = {}
        for st in tree.body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs[st.name] = st
                self.fn_origin[id(st)] = (rel, lines)
            elif isinstance(st, ast.Import):  # keep the module's own aliases (e.g. ``import subprocess as sp``)
                for a in st.names:
                    if a.asname:
                        self.aliases.setdefault(a.asname, a.name)
            elif isinstance(st, ast.ImportFrom) and st.module:
                for a in st.names:
                    self.aliases.setdefault(a.asname or a.name, f"{st.module}.{a.name}")
        return funcs

    def _import_local(self, st, a) -> None:
        """``from util import run`` / ``import util``: make the module's functions analyzable at call sites."""
        if isinstance(st, ast.ImportFrom):
            file = self._resolve_module(st.module or "")
            if file is None:
                return
            fn = self._load_module(file).get(a.name)
            if fn is not None:
                self.funcs[a.asname or a.name] = fn
                self.called.add(a.asname or a.name)  # never re-run as an uncalled local function
        else:
            file = self._resolve_module(a.name)
            if file is not None:
                self.mod_funcs[a.asname or a.name.split(".")[0]] = self._load_module(file)

    def _content_flow(self, t: str, op: str) -> None:
        """Data written as file *content*. Untrusted content in an ordinary file is not a finding (only its
        path is); secret content, or anything written to an agent config file, is."""
        sink = next((o.sink_category for o in self.s.operators if o.id == op), None)
        secret = any(x.id == t and x.trust == "secret" for x in self.s.sources)
        if sink == "agent_config_write" or secret:
            self.s.flows.add((t, op))

    # ---------------------------------------------------------------- statements
    def assign(self, target, t: set[str], env, value=None):
        special = {x for x in t if x.startswith("__")}
        plain = t - special
        for n in ast.walk(target) if not isinstance(target, ast.Name) else [target]:
            if isinstance(n, ast.Name):
                name = n.id
                if "__argparse__" in special:
                    self.argparse_vars.add(name)
                for s in special:
                    if s.startswith("__handle__:"):
                        self.handles[name] = s.split(":", 1)[1]
                    if s == "__socket__":
                        self.handles[name] = "socket"
                env[name] = set(plain) | (env.get(name, set()) if not isinstance(target, ast.Name) else set())
                if value is not None and isinstance(value, ast.Call):
                    dd = self.dotted(value.func) or ""
                    if dd in ("os.path.realpath", "os.path.abspath") or dd.endswith("resolve"):
                        self.realpath_vars.add(name)
                break

    def block(self, stmts, env):
        for st in stmts:
            self.stmt(st, env)

    def stmt(self, st, env):
        if isinstance(st, (ast.Import, ast.ImportFrom)):
            for a in st.names:
                full = f"{st.module}.{a.name}" if isinstance(st, ast.ImportFrom) and st.module else a.name
                self.aliases[a.asname or a.name.split(".")[0]] = full if (a.asname or isinstance(st, ast.ImportFrom)) else a.name.split(".")[0]
                self.s.refers.append((full, st.lineno))
                self._import_local(st, a)
            return
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.funcs[st.name] = st
            return
        if isinstance(st, ast.ClassDef):
            for b in st.body:
                if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.funcs[b.name] = b
            return
        if isinstance(st, ast.Assign):
            t = self.taint(st.value, env)
            for tg in st.targets:
                self.assign(tg, t, env, st.value)
            return
        if isinstance(st, (ast.AnnAssign, ast.AugAssign)):
            t = self.taint(st.value, env)
            if isinstance(st, ast.AugAssign):
                t |= self.taint(st.target, env)
            self.assign(st.target, t, env, st.value)
            return
        if isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                t = self.taint(item.context_expr, env)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, t, env)
            self.block(st.body, env)
            return
        if isinstance(st, (ast.For, ast.AsyncFor)):
            self.assign(st.target, self.taint(st.iter, env), env)
            self.block(st.body, env)
            self.block(st.body, env)  # second pass for loop-carried taint
            self.block(st.orelse, env)
            return
        if isinstance(st, ast.If):
            self.containment_check(st.test, env)
            self.taint(st.test, env)
            self.block(st.body, env)
            self.block(st.orelse, env)
            return
        if isinstance(st, ast.While):
            self.taint(st.test, env)
            self.block(st.body, env)
            self.block(st.orelse, env)
            return
        if isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
            self.block(st.body, env)
            for h in st.handlers:
                self.block(h.body, env)
            self.block(st.orelse, env)
            self.block(st.finalbody, env)
            return
        if isinstance(st, ast.Return):
            t = self.taint(st.value, env)
            if self.returns:
                self.returns[-1] |= {x for x in t if not x.startswith("__")}
            return
        if isinstance(st, ast.Expr):
            self.taint(st.value, env)
            return
        if isinstance(st, ast.Match):
            self.taint(st.subject, env)
            for c in st.cases:
                self.block(c.body, env)
            return
        for child in ast.iter_child_nodes(st):
            if isinstance(child, ast.expr):
                self.taint(child, env)

    def containment_check(self, test, env):
        """`if [not] p.startswith(base)` after realpath/abspath => sanitizer on p."""
        for n in ast.walk(test):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in (
                "startswith", "is_relative_to", "commonpath"
            ):
                v = n.func.value
                if isinstance(v, ast.Name) and v.id in self.realpath_vars and env.get(v.id):
                    san = self.operator(n, "sanitizer", "realpath containment check", None, env[v.id])
                    env[v.id] = {san}

    def run(self, tree: ast.Module):
        self.globals_env: dict[str, set[str]] = {}
        self.block(tree.body, self.globals_env)
        for name in list(self.funcs):
            if name not in self.called:
                fn = self.funcs[name]
                fake = ast.Call(func=ast.Name(id=name), args=[], keywords=[])
                ast.copy_location(fake, fn)
                self._call_local(name, fake, self.globals_env)


class PythonAstAnalyzer(CodeAnalyzer):
    name = "python-ast"

    def supports(self, path, lang):
        return lang == "python"

    def analyze(self, path: Path, rel: str) -> ScriptSummary:
        s = ScriptSummary(rel, "python", self.name)
        src = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            s.warnings.append(f"{rel}: syntax error, skipped ({e})")
            return s
        _PyTaint(rel, src, s, path).run(tree)
        s.flows = {(a, b) for a, b in s.flows if not a.startswith("__")}
        return s


# --------------------------------------------------------------------------- Shell

_VAR = r"\$(?:\{(\w+|[@*#]|\d)(?:[^}]*)\}|(\w+|[@*#]|\d))"
VAR_RE = re.compile(_VAR)
ASSIGN_RE = re.compile(r"^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w*)=(.*)$")
PURE_ASSIGN_RE = re.compile(
    r"""^\s*(?:export\s+|local\s+|readonly\s+)?\w+=("[^"]*"|'[^']*'|\$\([^)]*\)|`[^`]*`|\S*)\s*$"""
)
READ_RE = re.compile(r"^\s*read\s+(?:-\w+\s+)*([A-Za-z_]\w*)")
REDIRECT_RE = re.compile(r"(?:>>?|\btee\s+(?:-a\s+)?)\s*(['\"]?)([^\s'\";|&]+)\1")


class ShellRegexAnalyzer(CodeAnalyzer):
    """Regex-based, line-oriented approximation for POSIX shell scripts."""

    name = "shell-regex"

    def supports(self, path, lang):
        return lang == "shell"

    def analyze(self, path: Path, rel: str) -> ScriptSummary:
        s = ScriptSummary(rel, "shell", self.name)
        ids = _Ids()
        src = path.read_text(encoding="utf-8", errors="replace")
        taint: dict[str, set[str]] = {}
        inputs: dict[str, str] = {}

        def ev(ln, line):
            return Evidence(rel, [ln], line.strip())

        def var_taint(name: str, ln: int, line: str) -> set[str]:
            if name.isdigit() and name != "0" or name in ("@", "*"):
                key = f"argv[{name}]" if name.isdigit() else "argv[*]"
                if key not in inputs:
                    inp = CInput(ids("in"), key, int(name) if name.isdigit() else None, None, ev(ln, line))
                    s.inputs.append(inp)
                    inputs[key] = inp.id
                return {inputs[key]}
            if name in taint:
                return set(taint[name])
            if name.isupper() and SECRET_NAME_RE.search(name):
                sid = ids("src")
                s.sources.append(CSource(sid, "env_secret", "secret", f"env {name}", ev(ln, line), "environment"))
                taint[name] = {sid}
                return {sid}
            return set()

        def expr_taint(text: str, ln: int, line: str, unquoted_only=False) -> set[str]:
            out = set()
            for m in VAR_RE.finditer(text):
                if unquoted_only and _inside_quotes(text, m.start()):
                    continue
                out |= var_taint(m.group(1) or m.group(2), ln, line)
            return out

        def sink(ln, line, label, cat, t, role="sink"):
            oid = ids("op")
            s.operators.append(COperator(oid, role, label, ev(ln, line), cat))
            for x in t:
                s.flows.add((x, oid))
            return oid

        for ln, raw in enumerate(src.split("\n"), 1):
            line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
            if not line.strip():
                continue
            m = READ_RE.match(line)
            if m:
                inp = CInput(ids("in"), "stdin", None, None, ev(ln, line))
                s.inputs.append(inp)
                taint[m.group(1)] = {inp.id}
                continue
            cmdsubs = re.findall(r"\$\(([^)]*)\)|`([^`]*)`", line)
            sub_src: set[str] = set()
            for a, b in cmdsubs:
                body = a or b
                sid = ids("src")
                if re.search(r"\b(curl|wget|http)\b", body):
                    s.sources.append(CSource(sid, "web_content", "untrusted", f"$( {body.strip()[:40]} )", ev(ln, line)))
                else:
                    s.sources.append(CSource(sid, "other_script_output", "untrusted", f"$( {body.strip()[:40]} )", ev(ln, line)))
                sub_src.add(sid)
            am = ASSIGN_RE.match(line)
            if am and PURE_ASSIGN_RE.match(line):
                taint[am.group(1)] = expr_taint(am.group(2), ln, line) | sub_src
                # still analyze command substitution bodies as commands below
                if not cmdsubs:
                    continue
            words = line.strip().split()
            cmd = words[0] if words else ""
            t_all = expr_taint(line, ln, line)
            t_unq = expr_taint(line, ln, line, unquoted_only=True)
            for py in re.findall(r"([\w./-]+\.(?:py|sh))", line):
                s.refers.append((py, ln))
            red = REDIRECT_RE.search(line)
            if cmd in ("echo", "printf", "cat") and not red:
                sink(ln, line, f"{cmd} (stdout)", "context_output", t_all | sub_src)
                continue
            if red and red.group(2) not in ("/dev/null", "&1", "&2"):
                tgt = red.group(2)
                cat = "agent_config_write" if is_agent_config_path(tgt) else "file_write"
                sink(ln, line, f"write {tgt}", cat, t_all | sub_src)
            if cmd == "eval" or re.search(r"\b(bash|sh|zsh)\s+-c\b", line):
                sink(ln, line, "eval / sh -c", "code_eval" if cmd == "eval" else "shell_exec", t_all)
                continue
            if re.search(r"\b(curl|wget|nc|scp|rsync)\b", line) and t_all:
                sink(ln, line, f"{cmd} (network)", "network_egress", t_all)
                continue
            if t_unq:
                sink(ln, line, f"{cmd} (unquoted expansion)", "shell_exec", t_unq)
            elif t_all and not red:
                sink(ln, line, f"{cmd} (quoted argv)", None, t_all, role="sanitizer")
        return s


def _inside_quotes(text: str, pos: int) -> bool:
    dq = sq = False
    for i, ch in enumerate(text[:pos]):
        if ch == '"' and not sq and (i == 0 or text[i - 1] != "\\"):
            dq = not dq
        elif ch == "'" and not dq:
            sq = not sq
    return dq or sq


# --------------------------------------------------------------------------- registry

_ANALYZERS: list[CodeAnalyzer] = [PythonAstAnalyzer(), ShellRegexAnalyzer()]


def register_analyzer(a: CodeAnalyzer, first: bool = True) -> None:
    """Add a backend. ``first=True`` gives it priority over the built-ins."""
    if first:
        _ANALYZERS.insert(0, a)
    else:
        _ANALYZERS.append(a)


def analyze_script(root: Path, rel: str, lang: str | None) -> ScriptSummary:
    path = root / rel
    for a in _ANALYZERS:
        if a.supports(path, lang):
            return a.analyze(path, rel)
    s = ScriptSummary(rel, lang or "unknown", "none")
    s.warnings.append(f"{rel}: no analyzer for language '{lang}', registered as artifact only")
    return s
