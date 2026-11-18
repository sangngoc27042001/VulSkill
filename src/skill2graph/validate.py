"""Validate instruction records against the skill on disk.

Hard failures (record dropped): unknown action, quote not verbatim in the file,
missing evidence file, ``invoke_script`` target that is not a code artifact,
skill-local ``read_file`` target that does not exist.

Soft failures (record kept, flagged in ``record["flags"]``): stated lines do not
contain the quote (lines are corrected), an arg slot that is not a parsed placeholder
(arg dropped), an arg position/flag that matches no script input (arg marked
``unbound``; ``build.py`` records a binding error instead of guessing).
"""

from __future__ import annotations

import re

from .code_analysis import ScriptSummary
from .doc_extraction import ACTIONS, CONTEXT_READ, _negated, _prose
from .parse_skill import ParsedSkill

LOCAL_PREFIXES = ("scripts/", "references/", "assets/", "templates/", "./")


def _find_lines(lines: list[str], quote: str) -> list[int] | None:
    for i, line in enumerate(lines):
        if quote in line:
            return [i + 1, i + 1]
    text = "\n".join(lines)
    pos = text.find(quote)
    if pos < 0:
        return None
    start = text.count("\n", 0, pos) + 1
    return [start, start + quote.count("\n")]


# follow_content must actually tell the agent to act on content, not just read or summarize it
OBEY = re.compile(r"\b(follow|execute|carry out|apply|perform|run|obey|act on|do what|complete|install|use)\b", re.I)


def _semantic_guards(action: str | None, target: str, quote: str, skill: ParsedSkill) -> list[str]:
    """Extractor-independent checks for record kinds that are easy to over-extract."""
    reasons = []
    own_doc_in_quote = any(p in quote for p, a in skill.artifacts.items() if a.kind == "doc" and p != "SKILL.md")
    if action == "read_file" and target.removeprefix("./") in skill.artifacts:
        reasons.append(f"read_file target {target!r} is the skill's own file, not environment data")
    if action == "read_file" and CONTEXT_READ.search(target):
        reasons.append(f"read_file target {target!r} is output already in the agent context, not environment data")
    if action == "follow_content":
        if own_doc_in_quote:
            reasons.append("follow_content points at the skill's own document (its instructions are already modeled)")
        prose = _prose(quote)
        m = OBEY.search(prose)
        if not m:
            reasons.append("follow_content quote has no instruction to act on the content")
        elif _negated(prose, m.start()):
            reasons.append("follow_content instruction is negated")
    if action in ("run_shell", "call_api") and _negated(_prose(quote), len(_prose(quote))):
        reasons.append(f"{action} instruction is negated")
    return reasons


_WORD = re.compile(r"[a-z0-9]+")
_STOP = {"a", "an", "the", "of", "in", "on", "for", "each", "every", "all", "to", "from", "with", "and", "or", "it",
         "its", "that", "this", "is", "are", "be", "by", "as", "at", "any"}


def _implicit_arg_problem(arg: dict, action: str | None, doc) -> str | None:
    """An argument with no placeholder ("run it with convert.py", it = each Markdown file) is kept only if it is
    bound to a concrete script position/flag and its ``filled_from`` phrase is grounded in the document."""
    if action != "invoke_script":
        return "implicit arguments are only accepted for invoke_script"
    if not arg.get("flag") and not isinstance(arg.get("position"), int):
        return "no position or flag"
    phrase = (arg.get("filled_from") or "").strip().strip("`'\"")
    target = (arg.get("_target") or "").rsplit("/", 1)[-1]
    spans = re.findall(r"`([^`]*)`", doc.text) if doc is not None else []
    if phrase.startswith("-") or (target and target in phrase) or any(phrase and phrase in s for s in spans):
        return f"filled_from {phrase!r} is a literal in the command, not an input"
    words = [w for w in _WORD.findall(phrase.lower()) if w not in _STOP]
    if not words:
        return "empty filled_from"
    text = set(_WORD.findall(doc.text.lower())) if doc is not None else set()
    grounded = sum(w in text for w in words) / len(words)
    if grounded < 0.75:
        return f"filled_from {arg.get('filled_from')!r} is not grounded in the document"
    return None


def _local_path(path: str | None, skill: ParsedSkill) -> str | None:
    """Undo prefixes extractors add to skill-relative paths ("./x", "<skill-folder>/x")."""
    if not path:
        return path
    p = path.removeprefix("./")
    for prefix in (f"{skill.root.name}/", f"{skill.name}/"):
        if p.startswith(prefix) and p not in skill.artifacts and p.removeprefix(prefix) in skill.artifacts:
            return p.removeprefix(prefix)
    return p if p in skill.artifacts else path


def validate_records(
    records: list[dict], skill: ParsedSkill, summaries: dict[str, ScriptSummary] | None = None
) -> tuple[list[dict], list[dict]]:
    """Return (kept records, rejected [{record, reasons}])."""
    summaries = summaries or {}
    kept, rejected = [], []
    for rec in records:
        reasons: list[str] = []
        flags: list[str] = []
        if rec.get("action") not in ACTIONS:
            reasons.append(f"unknown action {rec.get('action')!r}")
        ev = rec.get("evidence") or {}
        if ev.get("file") and _local_path(ev["file"], skill) != ev["file"]:
            flags.append(f"evidence file {ev['file']!r} normalized")
            ev["file"] = _local_path(ev["file"], skill)
        if rec.get("target") and rec.get("action") in ("invoke_script", "read_file", "write_file"):
            rec["target"] = _local_path(rec["target"], skill)
        file, quote = ev.get("file"), (ev.get("quote") or "").strip()
        doc = skill.docs.get(file) if file else None
        if doc is None:
            reasons.append(f"evidence file {file!r} is not a document of this skill")
        elif not quote:
            reasons.append("empty evidence quote")
        elif quote not in doc.text:
            reasons.append("evidence quote does not appear verbatim in the file")
        else:
            lines = ev.get("lines") or []
            if len(lines) >= 1:
                lo, hi = lines[0], lines[-1]
                window = "\n".join(doc.lines[max(lo - 1, 0) : max(hi, lo)])
            else:
                window = ""
            if quote not in window:
                fixed = _find_lines(doc.lines, quote)
                flags.append(f"evidence lines {lines} corrected to {fixed}")
                ev["lines"] = fixed
        target = rec.get("target") or ""
        action = rec.get("action")
        if action == "invoke_script":
            art = skill.artifacts.get(target.removeprefix("./"))
            if art is None or art.kind != "code":
                reasons.append(f"invoke_script target {target!r} is not a script in the skill")
            else:
                rec["target"] = art.path
        if action == "read_file" and target.startswith(LOCAL_PREFIXES) and target.removeprefix("./") not in skill.artifacts:
            reasons.append(f"read_file target {target!r} looks skill-local but does not exist")
        reasons += _semantic_guards(action, target, quote, skill)
        if reasons:
            rejected.append({"record": rec, "reasons": reasons})
            continue
        placeholders = skill.placeholder_names(file)
        good_args = []
        for arg in rec.get("args") or []:
            slot = arg.get("slot")
            if slot not in placeholders:
                why = _implicit_arg_problem(dict(arg, _target=rec.get("target")), action, doc)
                if why:
                    flags.append(f"arg slot {slot!r} is not a placeholder parsed in {file} ({why}); arg dropped")
                    continue
                arg["implicit"] = True
                flags.append(f"arg {slot!r} kept as implicit argument (described in prose, no placeholder)")
            if action == "invoke_script":
                summ = summaries.get(rec["target"])
                if summ is not None and summ.analyzer != "none":
                    inp = None
                    if arg.get("flag"):
                        inp = summ.input_by_flag(arg["flag"])
                    elif isinstance(arg.get("position"), int):
                        inp = summ.input_by_position(arg["position"])
                    if inp is None:
                        arg["unbound"] = True
                        flags.append(
                            f"arg {slot!r} (position={arg.get('position')}, flag={arg.get('flag')}) "
                            f"matches no input of {rec['target']}"
                        )
                    else:
                        arg["input_id"] = inp.id
            good_args.append(arg)
        rec["args"] = good_args
        if flags:
            rec["flags"] = flags
        kept.append(rec)
    return kept, rejected
