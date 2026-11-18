"""Turn skill documents into schema-constrained *instruction records*.

Record schema (plain dicts so the LLM backend can emit the same thing)::

    {
      "id": "i1",
      "action": "invoke_script|run_shell|fetch|write_file|follow_content|read_file|report_to_user|receive_messages|call_api",
      "target": "scripts/convert.py",
      "args": [{"slot": "filename", "position": 1, "flag": null, "filled_from": "each Markdown file ..."}],
      "input_from": null,          # id of an earlier record whose result this one consumes
      "evidence": {"file": "SKILL.md", "lines": [12, 12], "quote": "..."},
      "confidence": 0.9,
      "extractor": "heuristic"
    }

Two backends share :class:`DocExtractor`: :class:`HeuristicExtractor` (default, offline,
deterministic, lexical) and :class:`LLMExtractor` (OpenAI SDK on Azure AI Foundry, structured outputs, opt-in via ``--llm``).
Every record must pass ``validate.validate_records`` before it reaches the graph.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from abc import ABC, abstractmethod

from .parse_skill import PLACEHOLDER_RES, ParsedSkill, directory_tree
from .trust import normalize_phrase

ACTIONS = ["invoke_script", "run_shell", "fetch", "write_file", "follow_content", "read_file", "report_to_user",
           "receive_messages", "call_api"]
SHELL_LANGS = {None, "", "bash", "sh", "shell", "console", "zsh", "terminal", "cmd"}

RECORD_SCHEMA = {
    "type": "object",
    "properties": {
        "records": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ACTIONS},
                    "target": {"type": "string"},
                    "args": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "slot": {"type": "string"},
                                "position": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
                                "flag": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                                "filled_from": {"type": "string"},
                            },
                            "required": ["slot", "position", "flag", "filled_from"],
                            "additionalProperties": False,
                        },
                    },
                    "input_from_index": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
                    "evidence": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string"},
                            "lines": {"type": "array", "items": {"type": "integer"}},
                            "quote": {"type": "string"},
                        },
                        "required": ["file", "lines", "quote"],
                        "additionalProperties": False,
                    },
                    "confidence": {"type": "number"},
                },
                "required": ["action", "target", "args", "input_from_index", "evidence", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["records"],
    "additionalProperties": False,
}


def make_record(rid, action, target, evidence, args=None, confidence=0.5, input_from=None, extractor="heuristic"):
    return {
        "id": rid,
        "action": action,
        "target": target,
        "args": args or [],
        "input_from": input_from,
        "evidence": evidence,
        "confidence": confidence,
        "extractor": extractor,
    }


class DocExtractor(ABC):
    name = "abstract"

    @abstractmethod
    def extract(self, skill: ParsedSkill) -> list[dict]: ...


# --------------------------------------------------------------------------- heuristic

SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9*_\[(])")
CODE_SPAN = re.compile(r"`[^`]*`")
FOLLOW_RE = re.compile(
    r"\b(follow|execute|carry out|apply|perform|run)\s+(them|those|these|it|"
    r"the\s+(steps|instructions|commands)|any\s+(steps|instructions|commands)|"
    r"(the\s+)?(setup|installation|install)\s+(steps|instructions|commands))\b"
    r"|\bdo what (it|the \w+) says\b",
    re.I,
)
FETCH_RE = re.compile(
    r"\b(download|fetch|retrieve|grab|curl|wget|get|pull)\b(?P<obj>(?:[^.;]|\.(?=\w))*?)\b(from|at)\b"
    r"(?P<src>(?:[^.;]|\.(?=\w))*)",
    re.I,
)
WEBISH = re.compile(r"\b(url|urls|link|page|site|website|http|https|web|internet|online|gist|endpoint)\b", re.I)
WRITE_RE = re.compile(
    r"\b(save|write|store|append|put|copy|output|dump)\b(?P<obj>(?:[^.;]|\.(?=\w))*?)\b(as|to|into|in)\s+[`'\"]?"
    r"(?P<path>(?:[\w\-]+/)*\.?[\w\-]+\.[A-Za-z]{1,6}|\.[\w\-]+(?:/[\w.\-]+)*|(?:[\w\-]+/)+[\w.\-]+)",
    re.I,
)
READ_RE = re.compile(
    r"\b(read|open|look at|inspect|scan|review|check|go through|browse|parse)\b\s+(?P<obj>(?:[^.;,]|\.(?=\w))*)", re.I
)
ENV_DATA = re.compile(
    r"\b(files?|issues?|pull requests?|PRs?|README|config\w*|repo(sitory)?('s)?|logs?|pages?|docs?|documents?|"
    r"emails?|comments?|tickets?|messages?|codebase|source|changelog|diff)\b|\.[A-Za-z]{2,5}\b",
    re.I,
)
# inbound content written by other parties: "other agents DM you", "read every message", "check your inbox"
RECEIVE_RE = re.compile(
    r"\b(agents?|users?|people|anyone|customers?|peers?|bots?|members?)\b[^.]*?\b(dm|dms|message|messages|email|emails|"
    r"ping|pings|send|sends|contact|contacts)\s+you\b"
    r"|\b(read|check|process|handle|answer|respond to|reply to|monitor|poll)\b[^.]*\b(dms?|messages?|inbox|mentions|"
    r"direct messages|mail|emails?|notifications|requests from)\b",
    re.I,
)
# a state-changing HTTP call written in prose or a code span: "POST /agents/NAME/wallet/send"
API_RE = re.compile(r"\b(POST|PUT|PATCH|DELETE)\s+(?P<path>(?:https?://)?[\w.\-:]*/[\w/{}<>:.\-]*)")
CONTEXT_READ = re.compile(r"\b(it prints|printed|the output|its output|the result|returned)\b", re.I)
REPORT_RE = re.compile(r"\b(summari[sz]e|report|tell|show|explain|present)\b[^.]*\b(user|them)\b", re.I)
NEGATION = re.compile(r"\b(do not|don't|never|must not|mustn't|should not|shouldn't|avoid|refuse to)\b", re.I)
# a code span that is just a file name / path, e.g. `site.yaml` or `.cursorrules` (unwrapped for prose matching)
FILE_SPAN = re.compile(r"`(\.?[\w\-]+(?:[./][\w\-]+)*)`")
# "`<since>` is the start time written in the incident ticket"
PLACEHOLDER_DESC = re.compile(
    r"^[\s>*\-\d.)]*`?[<{](\w+)[>}]`?\s*(?:is|are|=|:|means|should be|comes from|holds|refers to)\s+(.+?)\s*[.,;]?\s*$",
    re.I,
)
CHAIN_OBJ = re.compile(r"^\s*(it|them|this|that|the (result|output|template|file|content|page|response|text)s?)\b", re.I)
CUT_OBJ = re.compile(r"\s+(to|and|then|so|for|before|after|in order)\s+", re.I)


def _is_placeholder(tok: str) -> str | None:
    for style, rx in PLACEHOLDER_RES:
        m = rx.fullmatch(tok)
        if m:
            return m.group(1)
    return None


def args_from_argv(argv: list[str], filled_from: str) -> list[dict]:
    args, pos, i = [], 0, 0
    while i < len(argv):
        tok = argv[i]
        if tok.startswith("-") and len(tok) > 1:
            flag, _, val = tok.partition("=")
            if val and _is_placeholder(val):
                args.append({"slot": _is_placeholder(val), "position": None, "flag": flag, "filled_from": filled_from})
            elif i + 1 < len(argv) and _is_placeholder(argv[i + 1]):
                args.append({"slot": _is_placeholder(argv[i + 1]), "position": None, "flag": flag, "filled_from": filled_from})
                i += 1
            i += 1
            continue
        pos += 1
        ph = _is_placeholder(tok)
        if ph:
            args.append({"slot": ph, "position": pos, "flag": None, "filled_from": filled_from})
        i += 1
    return args


def _sentences(line: str) -> list[tuple[str, int]]:
    """Split a line into sentences, returning (sentence, char offset); code spans are kept intact."""
    masked = CODE_SPAN.sub(lambda m: "x" * len(m.group(0)), line)
    out, start = [], 0
    for m in SENT_SPLIT.finditer(masked):
        out.append((line[start : m.start()].rstrip(), start))
        start = m.end()
    out.append((line[start:], start))
    return [(s, o) for s, o in out if s.strip()]


def _prose(text: str) -> str:
    """Sentence text for action matching: file-name code spans are unwrapped, command spans removed."""
    text = FILE_SPAN.sub(lambda m: m.group(1), text)
    return re.sub(r"\s+", " ", CODE_SPAN.sub("", text)).strip()


def _negated(prose: str, start: int) -> bool:
    """True if a negation ("do not", "never", ...) appears in the same clause before position ``start``."""
    clause = re.split(r"[;:]|\bbut\b|\bthen\b", prose[:start])[-1]
    return bool(NEGATION.search(clause))


def placeholder_descriptions(skill: ParsedSkill) -> dict[str, dict[str, str]]:
    """Per doc: placeholder name -> its explanation line ("`<x>` is ...")."""
    out: dict[str, dict[str, str]] = {}
    for doc in skill.docs.values():
        for line in doc.lines:
            m = PLACEHOLDER_DESC.match(line)
            if m:
                out.setdefault(doc.path, {})[m.group(1)] = _prose(m.group(2))
    return out


class HeuristicExtractor(DocExtractor):
    """Lexical, deterministic extractor. High recall on common phrasings, no semantics."""

    name = "heuristic"

    def extract(self, skill: ParsedSkill) -> list[dict]:
        records: list[dict] = []
        n = [0]

        def rid():
            n[0] += 1
            return f"i{n[0]}"

        descs = placeholder_descriptions(skill)
        start = 0
        for doc in skill.docs.values():
            start = len(records)
            refs_by_line: dict[int, list] = {}
            for r in doc.refs:
                refs_by_line.setdefault(r.line, []).append(r)
            last_prose = ""
            for seg in doc.segments:
                if seg.kind == "code":
                    if seg.code_lang not in SHELL_LANGS:
                        continue
                    for ln, line in seg.lines():
                        cmd = line.strip().lstrip("$ ").strip()
                        if not cmd or cmd.startswith("#"):
                            continue
                        ev = {"file": doc.path, "lines": [ln, ln], "quote": line.strip()}
                        code_refs = [r for r in refs_by_line.get(ln, []) if skill.artifacts[r.target].kind == "code"]
                        if code_refs:
                            for r in code_refs:
                                records.append(make_record(rid(), "invoke_script", r.target, ev,
                                                           args_from_argv(r.argv, last_prose), 0.9))
                        else:
                            try:
                                toks = shlex.split(cmd)
                            except ValueError:
                                toks = cmd.split()
                            args = [{"slot": p, "position": None, "flag": None, "filled_from": last_prose}
                                    for p in (_is_placeholder(t) for t in toks) if p]
                            records.append(make_record(rid(), "run_shell", cmd, ev, args, 0.8))
                    continue
                for ln, line in seg.lines():
                    for sent, off in _sentences(line):
                        self._sentence(skill, doc.path, ln, sent, off, refs_by_line.get(ln, []), records, rid)
                        last_prose = _prose(sent)
            # an explicit "`<x>` is ..." line beats the surrounding sentence as the origin of slot x
            here = descs.get(doc.path, {})
            anywhere = {k: v for d in descs.values() for k, v in d.items()}
            for rec in records[start:]:
                for arg in rec["args"]:
                    desc = here.get(arg["slot"]) or anywhere.get(arg["slot"])
                    if desc:
                        arg["filled_from"] = desc
        return records

    def _sentence(self, skill, path, ln, sent, off, refs, records, rid):
        ev = {"file": path, "lines": [ln, ln], "quote": sent.strip()}
        prose = _prose(sent)
        local: list[dict] = []
        # 1. script invocations / doc references mentioned in this sentence
        for r in refs:
            if r.raw not in sent:
                continue
            a = skill.artifacts[r.target]
            if a.kind == "code":
                local.append(make_record(rid(), "invoke_script", r.target, ev, args_from_argv(r.argv, prose), 0.9))
        # 2. fetch
        fm = FETCH_RE.search(prose)
        if fm and _negated(prose, fm.start()):
            fm = None
        if fm and (WEBISH.search(fm.group(0)) or fm.group(1).lower() in ("download", "curl", "wget", "fetch")):
            src = CUT_OBJ.split(fm.group("src"))[0].strip()
            target = f"{fm.group('obj').strip()} from {src}".strip()
            local.append(make_record(rid(), "fetch", target, ev, [], 0.7))
        # 3. read (environment data only; reading the skill's own docs or stdout is not a source)
        rm = READ_RE.search(prose)
        if rm and not _negated(prose, rm.start()):
            obj = CUT_OBJ.split(rm.group("obj"))[0].strip()
            local_doc = any(r.raw in obj for r in refs)
            if obj and ENV_DATA.search(obj) and not CONTEXT_READ.search(obj) and not local_doc:
                local.append(make_record(rid(), "read_file", obj, ev, [], 0.6))
        # 4. write
        for wm in WRITE_RE.finditer(prose):
            if _negated(prose, wm.start()):
                continue
            prev = [x for x in local if x["action"] in ("fetch", "read_file", "invoke_script")]
            chained = prev[-1]["id"] if prev and CHAIN_OBJ.match(wm.group("obj") or "") else None
            local.append(make_record(rid(), "write_file", wm.group("path").strip("`'\""), ev, [], 0.8, input_from=chained))
        # 5. follow content
        flw = FOLLOW_RE.search(prose)
        if flw and not _negated(prose, flw.start()):
            local.append(make_record(rid(), "follow_content", "content in agent context", ev, [], 0.7))
        # 6. inbound messages from other parties (untrusted)
        rcv = RECEIVE_RE.search(prose)
        if rcv and not _negated(prose, rcv.start()):
            local.append(make_record(rid(), "receive_messages", "messages from other parties", ev, [], 0.6))
        # 7. state-changing API calls (method + path survive code-span removal only in the raw sentence)
        for am in API_RE.finditer(sent):
            if not _negated(_prose(sent[: am.start()]), len(_prose(sent[: am.start()]))):
                local.append(make_record(rid(), "call_api", f"{am.group(1)} {am.group('path')}", ev, [], 0.7))
        # 8. report
        if REPORT_RE.search(prose):
            local.append(make_record(rid(), "report_to_user", "user", ev, [], 0.5))
        records.extend(local)


# --------------------------------------------------------------------------- LLM

LLM_SYSTEM = """You extract security-relevant instructions from an LLM agent skill.
Return JSON matching the schema. One record per instruction that makes the agent:
invoke one of the skill's scripts (invoke_script; target = the script path exactly as in the directory structure),
run a shell command (run_shell), fetch remote content (fetch), write a file (write_file; target = file path),
act on/follow content it read (follow_content), read environment data such as repo files, issues, web pages (read_file),
report to the user (report_to_user),
receive messages written by other parties (receive_messages; DMs, chat, email, inbox, webhooks, requests from other
agents or users other than the operator; target = who sends them),
or make a state-changing call to an API or service (call_api; target = method and endpoint, e.g.
"POST /agents/NAME/wallet/send"; covers sending money or tokens, trading, posting, deleting, changing permissions).
For every placeholder argument (<x>, {x}, $X) give slot (placeholder name without brackets), position (1-based argv
position after the script path, null for flags), flag (e.g. "--url" or null), and filled_from: a short phrase quoted
from the document describing where the value comes from.
evidence.quote MUST be copied verbatim from the file (a single line or part of one); evidence.lines are 1-based.
input_from_index: index (0-based, in your records array) of an earlier record whose result this one consumes, else null.
Do not invent scripts, files, or placeholders.
Rules:
- Targets of skill files are paths relative to the skill root as shown after "=" in the directory structure, even when
  the instruction is in a nested document (e.g. "run collect.py" inside references/workflow.md -> scripts/collect.py).
  Files marked "other" are listed but their content is not given.
- If a command runs a file listed in the directory structure (e.g. `python scripts/x.py <a>`, `bash scripts/y.sh`), it is
  invoke_script with target = that path, NOT run_shell. Use run_shell only for commands that run no skill script.
- follow_content is ONLY for instructions that tell the agent to obey/execute/apply what some content says
  (e.g. "follow the steps on the page"). Choosing a value from earlier output to pass to a script is NOT
  follow_content: express it as an invoke_script whose argument has filled_from describing that output and
  input_from_index pointing at the record that produced it.
- Emit one record per instruction; do not duplicate the same instruction under two actions.
- Negated or prohibited actions ("do not run ...", "never download ...") are NOT instructions: emit no record.
- Pointers to the skill's own files (e.g. "follow the workflow in references/workflow.md", "read references/setup.md
  first") are NOT read_file or follow_content: the content of those files is already given to you, so extract the
  instructions inside them instead.
- An instruction to read and respond to / handle / evaluate messages, DMs, requests or proposals from other agents or
  third parties is receive_messages, NOT report_to_user (the agent's reply goes to those parties, not to its user).
- Every documented endpoint or command that changes state (POST/PUT/PATCH/DELETE, "send", "transfer", "trade",
  "swap", "withdraw", "pay", "approve", "delete", "post") is call_api, even when it appears in an API reference section
  and not as an imperative step. Read-only GET requests that pull content in are fetch. If a call_api is run through
  curl or a shell snippet, emit call_api (not run_shell) for it.
- Reading or summarizing output/content for the user is NOT follow_content; follow_content means obeying or executing
  what the content says.
- Implicit arguments: if an instruction passes a value to a skill script without writing a placeholder (e.g. "for
  each Markdown file, run it with scripts/convert.py", where "it" is the file), still emit the arg: slot = a short
  name, position/flag = where the script reads it (see how the script is described or invoked), filled_from = the
  phrase from the document that says what the value is (e.g. "each Markdown file in the repository").
- If a placeholder is explained elsewhere (e.g. "`<since>` is the start time written in the incident ticket"), use
  that explanation as filled_from."""


# --------------------------------------------------------------------------- structured-output models
# Pydantic mirror of RECORD_SCHEMA, used for OpenAI structured outputs (strict JSON schema).

from typing import Literal, Optional  # noqa: E402

from pydantic import BaseModel, ConfigDict, Field  # noqa: E402


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ArgModel(_Strict):
    slot: str = Field(description="placeholder name without brackets, e.g. 'filename'; for an implicit argument "
                      "with no placeholder, a short descriptive name")
    position: Optional[int] = Field(description="1-based positional index after the script path; null for flags")
    flag: Optional[str] = Field(description="flag such as '--url', else null")
    filled_from: str = Field(description="short phrase from the document saying where the value comes from")


class EvidenceModel(_Strict):
    file: str
    lines: list[int] = Field(description="[start, end], 1-based")
    quote: str = Field(description="verbatim text copied from the file")


class RecordModel(_Strict):
    action: Literal["invoke_script", "run_shell", "fetch", "write_file", "follow_content", "read_file", "report_to_user",
                    "receive_messages", "call_api"]
    target: str
    args: list[ArgModel]
    input_from_index: Optional[int]
    evidence: EvidenceModel
    confidence: float


class RecordsModel(_Strict):
    records: list[RecordModel]


# --------------------------------------------------------------------------- LLM backend
ENV_ENDPOINT = "QLAY_AI_FOUNDERY"
ENV_API_KEY = "QLAY_AI_FOUNDERY_API_KEY"
ENV_DEPLOYMENT = "QLAY_AI_DEPLOYMENT"
FALLBACK_DEPLOYMENT = "gpt-5.2"


def default_model() -> str:
    return os.environ.get(ENV_DEPLOYMENT) or FALLBACK_DEPLOYMENT


class LLMExtractor(DocExtractor):
    """Azure AI Foundry (OpenAI SDK) extractor with structured outputs. Opt-in only (``--llm``).

    Reads the endpoint, key and deployment from ``QLAY_AI_FOUNDERY``, ``QLAY_AI_FOUNDERY_API_KEY``
    and ``QLAY_AI_DEPLOYMENT`` (the CLI loads them from ``.env``). Never used in tests.
    """

    name = "llm"

    def __init__(self, model: str | None = None, client=None, max_tokens: int = 16000):
        self.model = model or default_model()
        self.client = client
        self.max_tokens = max_tokens

    @staticmethod
    def available() -> bool:
        if not (os.environ.get(ENV_ENDPOINT) and os.environ.get(ENV_API_KEY)):
            return False
        try:
            import openai  # noqa: F401
        except ImportError:
            return False
        return True

    def _client(self):
        if self.client is None:
            from openai import OpenAI

            endpoint = os.environ[ENV_ENDPOINT].rstrip("/")
            # Azure OpenAI v1 API: the plain OpenAI client works against <endpoint>/openai/v1/.
            self.client = OpenAI(base_url=f"{endpoint}/openai/v1/", api_key=os.environ[ENV_API_KEY])
        return self.client

    def build_prompt(self, skill: ParsedSkill) -> str:
        parts = [
            "Skill directory structure. Paths after \"=\" are relative to the skill root; use them exactly, without any folder prefix, for evidence.file and for targets:",
            directory_tree(skill),
        ]
        for doc in skill.docs.values():
            numbered = "\n".join(f"{i + 1:4d}| {t}" for i, t in enumerate(doc.lines))
            parts.append(f"\n=== {doc.path} ===\n{numbered}")
        return "\n".join(parts)

    def extract(self, skill: ParsedSkill) -> list[dict]:
        resp = self._client().chat.completions.parse(
            model=self.model,
            messages=[
                {"role": "system", "content": LLM_SYSTEM},
                {"role": "user", "content": self.build_prompt(skill)},
            ],
            response_format=RecordsModel,
            max_completion_tokens=self.max_tokens,
        )
        msg = resp.choices[0].message
        if getattr(msg, "refusal", None):
            raise RuntimeError(f"LLM extractor: model refused ({msg.refusal})")
        if msg.parsed is None:
            raise RuntimeError(f"LLM extractor: no parsed output (finish_reason={resp.choices[0].finish_reason})")
        return self.records_from_json(msg.parsed.model_dump())

    @staticmethod
    def records_from_json(data: dict) -> list[dict]:
        out = []
        raw = data.get("records", [])
        for idx, r in enumerate(raw):
            inp = r.get("input_from_index")
            out.append(
                make_record(
                    f"i{idx + 1}",
                    r.get("action"),
                    r.get("target", ""),
                    r.get("evidence", {}),
                    [{**a, "filled_from": normalize_phrase(a.get("filled_from"))} for a in r.get("args", [])],
                    float(r.get("confidence", 0.5)),
                    input_from=f"i{inp + 1}" if isinstance(inp, int) and 0 <= inp < idx else None,
                    extractor="llm",
                )
            )
        return out


def get_extractor(use_llm: bool = False, model: str | None = None) -> tuple[DocExtractor, list[str]]:
    """Return (extractor, warnings). The LLM backend is used only when requested *and* configured."""
    if not use_llm:
        return HeuristicExtractor(), []
    if not LLMExtractor.available():
        return HeuristicExtractor(), [
            f"--llm requested but {ENV_ENDPOINT}/{ENV_API_KEY} are not set (check .env); "
            "using the heuristic extractor"
        ]
    return LLMExtractor(model=model), []
