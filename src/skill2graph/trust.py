"""Map a natural-language ``filled_from`` phrase to a source category and trust level.

The rule table is ordered: the first matching rule wins. Categories whose value is
chosen by the agent from what it already holds (``previous_output``, ``agent_choice``)
are *bound from AgentContext* by ``build.py`` (a probabilistic ``llm_binding`` flow)
rather than becoming a new Source node.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Categories that the builder binds from AgentContext instead of creating a Source.
FROM_CONTEXT = {"previous_output", "agent_choice"}


@dataclass(frozen=True)
class TrustDecision:
    category: str
    trust: str  # trusted | untrusted | secret
    decided_by: str  # rule | llm | default
    rule: str | None = None

    @property
    def from_context(self) -> bool:
        return self.category in FROM_CONTEXT


# (rule name, regex, category, trust)
RULES: list[tuple[str, str, str, str]] = [
    ("secret", r"(?<![a-z])(token|api[ _-]?key|secret|password|passwd|credential|private[ _-]key)s?(?![a-z])", "env_secret", "secret"),
    ("agent-pick-from-output",
     r"\b(pick|choose|select)\b|\bfrom (the|its) (output|list|results?)\b|\bprevious (step|output|command)\b|\b(returned|printed|listed) by\b|\bprinted\b",
     "previous_output", "untrusted"),
    # a literal value such as `notes.md` or "config/out.json" (file-like token), or an explicit "literal ..."
    ("constant", r"^\s*(literal|constant)\b|^\s*['\"`]?[\w\-]*[./][\w./\-]+['\"`]?\s*$", "constant", "trusted"),
    ("issue-like", r"\b(issues?|pull requests?|PRs?|emails?|comments?|tickets?|messages?|chat|slack|discussions?)\b",
     "external_text", "untrusted"),
    ("file-names", r"\b(file ?names?|each\b[^.]*\bfiles?\b|every\b[^.]*\bfiles?\b|all\b[^.]*\bfiles\b|files? in the (repo|repository|workspace|project|directory|folder))",
     "workspace_file_name", "untrusted"),
    ("file-content",
     r"\b(contents? of|config(uration)? files?|README|repository'?s|repo'?s|workspace|project files?|in the (repo|repository|project))\b|\.(json|ya?ml|toml|ini|env|txt|md)\b",
     "workspace_file_content", "untrusted"),
    ("user", r"\bthe user('s)?\b|\buser[- ](provided|supplied|given|specified)\b|\b(user|you are) (gives?|provides?|names?|asks?|specif(y|ies)|types?|says?|requests?)\b",
     "user_prompt", "trusted"),
    ("web", r"\b(url|urls|web ?page|web|page|site|website|link|http|https|online|internet|download(ed)?)\b",
     "web_content", "untrusted"),
]
_COMPILED = [(n, re.compile(rx, re.I), c, t) for n, rx, c, t in RULES]


def normalize_phrase(text: str | None) -> str:
    """Strip whitespace and wrapping quotes the extractor may add around a quoted phrase."""
    text = (text or "").strip()
    while len(text) >= 2 and text[0] in "\"'`" and text[-1] == text[0]:
        text = text[1:-1].strip()
    if text[:1] in "\"'`" and text.count(text[0]) == 2:  # '"For each title" (i.e. ...)' -> keep both parts
        text = text.replace(text[0], "", 2).strip()
    return text


def classify(filled_from: str | None, llm_hint: dict | None = None) -> TrustDecision:
    """Classify a ``filled_from`` phrase.

    ``llm_hint`` (``{"category":..., "trust":...}``) is only used when no rule matches.
    Without a match the default is ``agent_choice`` / untrusted: the agent fills the
    slot from whatever is in its context.
    """
    raw = (filled_from or "").strip()
    if re.fullmatch(r"(['\"`])[^\s'\"`]+\1", raw):  # a quoted single token such as 'production' is a literal
        return TrustDecision("constant", "trusted", "rule", "constant")
    text = normalize_phrase(raw)
    for name, rx, cat, trust in _COMPILED:
        if text and rx.search(text):
            return TrustDecision(cat, trust, "rule", name)
    if llm_hint and llm_hint.get("category") and llm_hint.get("trust") in ("trusted", "untrusted", "secret"):
        return TrustDecision(llm_hint["category"], llm_hint["trust"], "llm")
    return TrustDecision("agent_choice", "untrusted", "default")


def classify_read_target(target: str) -> TrustDecision:
    """Classify what a doc-level read/fetch instruction pulls into context."""
    d = classify(target)
    if d.category in ("user_prompt", "constant", "agent_choice", "previous_output"):
        return TrustDecision("workspace_file_content", "untrusted", "default")
    return d
