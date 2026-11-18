"""Inventory a skill folder and parse its Markdown documents.

Produces a :class:`ParsedSkill` with:
- every file as an :class:`Artifact` (kind ``code`` or ``doc``),
- the SKILL.md frontmatter (PyYAML),
- each document split into line-numbered :class:`Segment` objects (prose vs fenced code),
- placeholders (``<x>``, ``{x}``, ``$X``) and references to files inside the skill.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

import yaml

CODE_EXT = {
    ".py": "python",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".pl": "perl",
    ".php": "php",
    ".ps1": "powershell",
}
DOC_EXT = {".md", ".markdown", ".txt", ".rst"}
SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".pytest_cache"}
JUNK_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}

PLACEHOLDER_RES = [
    ("angle", re.compile(r"<([A-Za-z_][\w\-]*)>")),
    ("brace", re.compile(r"(?<![{$])\{([A-Za-z_][\w\-]*)\}(?!\})")),
    ("dollar", re.compile(r"\$\{?([A-Z][A-Z0-9_]*)\}?")),
]
FENCE_RE = re.compile(r"^\s*(```|~~~)\s*([\w+\-]*)")


@dataclass
class Artifact:
    path: str  # relative to skill root, posix style
    kind: str  # code | doc | other
    lang: str | None = None


@dataclass
class Segment:
    file: str
    start_line: int  # 1-based, inclusive
    end_line: int
    kind: str  # prose | code
    text: str
    code_lang: str | None = None

    def lines(self) -> list[tuple[int, str]]:
        return [(self.start_line + i, t) for i, t in enumerate(self.text.split("\n"))]


@dataclass
class Placeholder:
    name: str
    raw: str
    style: str
    file: str
    line: int


@dataclass
class FileRef:
    """A mention of another skill file inside a document line."""

    file: str
    line: int
    target: str  # artifact path
    raw: str  # matched text
    argv: list[str] = field(default_factory=list)  # tokens after the script path
    in_code: bool = False
    col: int = 0


@dataclass
class DocInfo:
    path: str
    text: str
    lines: list[str]
    body_start_line: int
    segments: list[Segment]
    placeholders: list[Placeholder]
    refs: list[FileRef]


@dataclass
class ParsedSkill:
    root: Path
    name: str
    description: str
    frontmatter: dict
    artifacts: dict[str, Artifact]
    docs: dict[str, DocInfo]
    warnings: list[str] = field(default_factory=list)

    @property
    def skill_md(self) -> DocInfo:
        return self.docs["SKILL.md"]

    def code_artifacts(self) -> list[Artifact]:
        return [a for a in self.artifacts.values() if a.kind == "code"]

    def placeholder_names(self, file: str | None = None) -> set[str]:
        out = set()
        for d in self.docs.values():
            if file is None or d.path == file:
                out |= {p.name for p in d.placeholders}
        return out


def classify_file(path: Path) -> Artifact | None:
    ext = path.suffix.lower()
    if ext in CODE_EXT:
        return Artifact(path="", kind="code", lang=CODE_EXT[ext])
    if ext in DOC_EXT:
        return Artifact(path="", kind="doc")
    if path.is_file():
        try:
            head = path.read_text(errors="ignore")[:64]
        except OSError:
            return None
        if head.startswith("#!"):
            lang = "python" if "python" in head.splitlines()[0] else "shell"
            return Artifact(path="", kind="code", lang=lang)
    return Artifact(path="", kind="other")


def inventory(root: Path) -> dict[str, Artifact]:
    arts: dict[str, Artifact] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.name in JUNK_FILES or any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        a = classify_file(p)
        if a is None:
            continue
        a.path = p.relative_to(root).as_posix()
        arts[a.path] = a
    return arts


INLINE_KEY = re.compile(r"(?:^|\s)(name|description|metadata|license|allowed-tools|version):\s*", re.I)


def _balanced(text: str, start: int) -> str | None:
    """The {...} block starting at ``start`` (brace-matched, string-aware), or None."""
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            esc = (c == "\\") and not esc
            if c == '"' and not esc:
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def recover_inline_frontmatter(text: str) -> dict:
    """Best-effort fields from a header with no ``---`` fences, e.g. a frontmatter flattened onto one line:
    ``name: x description: ... metadata: { "openclaw": {...} }  # Title ...``. Only looks at the text before
    the first Markdown heading. Returns {} when the text does not start with ``name:``/``description:``."""
    head = re.split(r"(?:^|\s)#\s", text, maxsplit=1)[0]
    if not re.match(r"\s*(name|description):", head, re.I):
        return {}
    keys = list(INLINE_KEY.finditer(head))
    fm: dict = {}
    for k, nxt in zip(keys, keys[1:] + [None]):
        key = k.group(1).lower()
        if key == "metadata":
            # the JSON object may contain words like "name:"; take it by brace matching on the full text
            brace = text.find("{", k.end())
            blob = _balanced(text, brace) if brace >= 0 else None
            if blob:
                try:
                    fm[key] = json.loads(blob)
                except ValueError:
                    try:
                        fm[key] = yaml.safe_load(blob)
                    except yaml.YAMLError:
                        pass
            continue
        val = head[k.end() : nxt.start() if nxt else len(head)]
        val = re.sub(r"(\s*\.){2,}\s*$", "", val).strip()  # drop elision dots ". . ."
        if val:
            fm[key] = val
    return fm


def split_frontmatter(text: str) -> tuple[dict, int, list[str]]:
    """Return (frontmatter dict, 1-based line where body starts, warnings)."""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        fm = recover_inline_frontmatter(text)
        if fm:
            return fm, 1, ["SKILL.md has no YAML frontmatter fences; recovered fields from an inline header: "
                           + ", ".join(sorted(fm))]
        return {}, 1, ["SKILL.md has no YAML frontmatter"]
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            try:
                fm = yaml.safe_load("\n".join(lines[1:i])) or {}
            except yaml.YAMLError as e:
                return {}, i + 2, [f"invalid frontmatter YAML: {e}"]
            if not isinstance(fm, dict):
                return {}, i + 2, ["frontmatter is not a mapping"]
            return fm, i + 2, []
    return {}, 1, ["unterminated frontmatter"]


def segment_body(path: str, lines: list[str], start: int) -> list[Segment]:
    """Split lines[start-1:] into prose/code segments (blank-line separated prose blocks)."""
    segs: list[Segment] = []
    i = start - 1
    buf: list[str] = []
    buf_start = None

    def flush_prose():
        nonlocal buf, buf_start
        if buf and any(b.strip() for b in buf):
            segs.append(Segment(path, buf_start, buf_start + len(buf) - 1, "prose", "\n".join(buf)))
        buf, buf_start = [], None

    while i < len(lines):
        line = lines[i]
        m = FENCE_RE.match(line)
        if m:
            flush_prose()
            fence, lang = m.group(1), (m.group(2) or None)
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith(fence):
                j += 1
            body = lines[i + 1 : j]
            if body:
                segs.append(Segment(path, i + 2, i + 1 + len(body), "code", "\n".join(body), lang))
            i = j + 1
            continue
        if not line.strip():
            flush_prose()
        else:
            if buf_start is None:
                buf_start = i + 1
            buf.append(line)
        i += 1
    flush_prose()
    return segs


def find_placeholders(path: str, segs: list[Segment]) -> list[Placeholder]:
    out: list[Placeholder] = []
    for seg in segs:
        for ln, text in seg.lines():
            for style, rx in PLACEHOLDER_RES:
                if style == "dollar" and seg.kind == "prose" and "`" not in text:
                    continue  # "$X" in plain prose is usually currency, not a variable
                for m in rx.finditer(text):
                    if style == "angle" and m.group(1).lower() in {"br", "p", "div", "span", "img"}:
                        continue
                    out.append(Placeholder(m.group(1), m.group(0), style, path, ln))
    return out


def _tokens_after(text: str, start: int) -> list[str]:
    rest = text[start:]
    rest = re.split(r"[`|;&]|\s(?:and|then)\s", rest, maxsplit=1)[0]
    rest = rest.rstrip(".,:)")
    try:
        return shlex.split(rest)
    except ValueError:
        return rest.split()


def find_refs(path: str, segs: list[Segment], artifacts: dict[str, Artifact]) -> list[FileRef]:
    targets = [a for a in artifacts.values() if a.path != path and a.kind in ("code", "doc")]
    # longest paths first so "scripts/a.py" wins over "a.py"
    names: list[tuple[str, Artifact]] = []
    for a in targets:
        names.append((a.path, a))
        base = a.path.rsplit("/", 1)[-1]
        if base != a.path and base != "SKILL.md":
            names.append((base, a))
    names.sort(key=lambda x: -len(x[0]))
    out: list[FileRef] = []
    for seg in segs:
        for ln, text in seg.lines():
            taken: list[tuple[int, int]] = []
            for name, a in names:
                for m in re.finditer(r"(?<![\w/.\-])(?:\./)?" + re.escape(name) + r"(?![\w\-])", text):
                    if any(s <= m.start() < e for s, e in taken):
                        continue
                    taken.append((m.start(), m.end()))
                    argv = _tokens_after(text, m.end()) if a.kind == "code" else []
                    out.append(FileRef(path, ln, a.path, m.group(0), argv, seg.kind == "code", m.start()))
    out.sort(key=lambda r: (r.line, r.col))
    return out


def parse_doc(root: Path, rel: str, artifacts: dict[str, Artifact]) -> tuple[DocInfo, dict, list[str]]:
    text = (root / rel).read_text(encoding="utf-8", errors="replace")
    lines = text.split("\n")
    fm, body_start, warns = ({}, 1, [])
    if rel == "SKILL.md":
        fm, body_start, warns = split_frontmatter(text)
    segs = segment_body(rel, lines, body_start)
    info = DocInfo(rel, text, lines, body_start, segs, find_placeholders(rel, segs), find_refs(rel, segs, artifacts))
    return info, fm, warns


def parse_skill(root: str | Path) -> ParsedSkill:
    root = Path(root).resolve()
    if not (root / "SKILL.md").is_file():
        raise FileNotFoundError(f"{root} has no SKILL.md")
    artifacts = inventory(root)
    docs: dict[str, DocInfo] = {}
    fm: dict = {}
    warnings: list[str] = []
    for rel, a in artifacts.items():
        if a.kind != "doc":
            continue
        info, f, w = parse_doc(root, rel, artifacts)
        docs[rel] = info
        if rel == "SKILL.md":
            fm, warnings = f, w
    name = str(fm.get("name") or root.name)
    desc = str(fm.get("description") or "")
    if not desc:
        warnings.append("frontmatter has no description")
    return ParsedSkill(root, name, desc, fm, artifacts, docs, warnings)


def directory_tree(skill: "ParsedSkill", max_entries: int = 300, max_per_dir: int = 40) -> str:
    """Render the skill folder as an indented tree, each file tagged with its kind.

    Large folders are cut: at most ``max_per_dir`` files are listed per directory and ``max_entries``
    lines overall; a ``... (N more ...)`` line says what was left out. Docs and code are listed before
    other files so the cut drops data files first.
    """
    tree: dict = {}
    for path, art in skill.artifacts.items():
        node = tree
        *dirs, name = path.split("/")
        for d in dirs:
            node = node.setdefault(d + "/", {})
        node[name] = art

    rank = {"doc": 0, "code": 1, "other": 2}
    lines = ["./  (skill root)"]
    budget = [max_entries]

    def count(node) -> int:
        return sum(count(v) if isinstance(v, dict) else 1 for v in node.values())

    def walk(node, indent):
        dirs = sorted(k for k, v in node.items() if isinstance(v, dict))
        files = sorted((k for k, v in node.items() if not isinstance(v, dict)),
                       key=lambda k: (rank.get(node[k].kind, 3), k))
        if len(files) > max_per_dir:
            hidden = files[max_per_dir:]
            files = files[:max_per_dir]
        else:
            hidden = []
        for k in files:
            if budget[0] <= 0:
                break
            a = node[k]
            tag = a.kind + (f", {a.lang}" if a.lang else "")
            if a.kind == "doc":
                tag += ", content below"
            lines.append(f"{indent}{k}  [{tag}]  = {a.path}")
            budget[0] -= 1
        if hidden:
            lines.append(f"{indent}... ({len(hidden)} more files in this folder not listed)")
        for d in dirs:
            if budget[0] <= 0:
                lines.append(f"{indent}... ({count(node[d])} files under {d} not listed)")
                continue
            lines.append(f"{indent}{d}")
            budget[0] -= 1
            walk(node[d], indent + "    ")

    walk(tree, "    ")
    total = len(skill.artifacts)
    shown = sum(1 for ln in lines if "  [" in ln)
    if shown < total:
        lines.append(f"(listing truncated: {shown} of {total} files shown)")
    return "\n".join(lines)
