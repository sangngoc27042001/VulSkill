"""Assemble the Skill Flow Graph (networkx MultiDiGraph).

Node ``type``: Artifact | Source | Operator | AgentContext.
Edge ``etype``: refers | defines | flow.
Node ids are stable, assigned in deterministic build order: n1, n2, ...
"""

from __future__ import annotations

import re
from pathlib import Path

import networkx as nx

from .code_analysis import ScriptSummary, analyze_script, is_agent_config_path
from .doc_extraction import DocExtractor, get_extractor
from .parse_skill import ParsedSkill, parse_skill
from .trust import TrustDecision, classify, classify_read_target
from .validate import validate_records

TRIGGER_BREADTH_THRESHOLD = 0.5
DEFAULT_ENV_LABEL = "environment content [untrusted]"
DEFAULT_EGRESS_LABEL = "agent generic tool use (network) [default]"
# call_api targets/quotes that move money or assets get the stronger sink category
VALUE_TRANSFER_RE = re.compile(
    r"\b(send|transfer|withdraw(al)?|pay(ment)?|payout|swap|trade|buy|sell|deposit|fund(ing)?|wallet|tip|bridge|"
    r"stake|mint)\b",
    re.I,
)
SECRET_ENV_RE = re.compile(r"(TOKEN|KEY|SECRET|PASSWORD|PASSWD|AUTH|CREDENTIAL|COOKIE|SESSION|PRIVATE)", re.I)


def declared_requires(fm: dict, kind: str) -> list[str]:
    """Names a skill declares under ``requires.<kind>`` at any depth of the frontmatter
    (e.g. ``metadata.openclaw.requires.env``), plus a top-level ``<kind>`` list."""
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "requires" and isinstance(v, dict) and isinstance(v.get(kind), list):
                    out.extend(str(x) for x in v[kind])
                walk(v)
        elif isinstance(node, list):
            for x in node:
                walk(x)

    walk(fm)
    if isinstance(fm.get(kind), list):
        out.extend(str(x) for x in fm[kind])
    return list(dict.fromkeys(out))


def description_breadth(desc: str) -> float:
    """Heuristic 0..1 score of how broadly a description triggers the skill."""
    d = desc.lower()
    score = 0.3
    if re.search(r"\b(whenever|any ?time|always|any|every|all|anything)\b", d):
        score += 0.3
    if re.search(r"\b(mention(ed|s)?|related to|involving|about|touch(es)?|refers? to)\b", d):
        score += 0.2
    if re.search(r"\b(when|if) the user (explicitly )?(asks|requests|says|wants|invokes)\b|\bonly when\b", d):
        score -= 0.2
    if len(d) < 60:
        score += 0.1
    return round(max(0.0, min(1.0, score)), 2)


def _short(text: str, n: int = 48) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


class GraphBuilder:
    def __init__(self, skill: ParsedSkill):
        self.skill = skill
        self.G = nx.MultiDiGraph()
        self.keys: dict[str, str] = {}
        self.n = 0

    # ------------------------------------------------------------ primitives
    def node(self, key: str, ntype: str, label: str, **attrs) -> str:
        if key in self.keys:
            return self.keys[key]
        self.n += 1
        nid = f"n{self.n}"
        self.keys[key] = nid
        self.G.add_node(nid, type=ntype, label=label, key=key, **{k: v for k, v in attrs.items() if v is not None})
        return nid

    def edge(self, u: str, v: str, etype: str, **attrs):
        for k, d in (self.G.get_edge_data(u, v) or {}).items():
            if d.get("etype") == etype and d.get("certainty") == attrs.get("certainty") and d.get("via") == attrs.get("via"):
                if attrs.get("binds") and attrs["binds"] not in (d.get("binds") or ""):
                    d["binds"] = ", ".join(x for x in (d.get("binds"), attrs["binds"]) if x)
                return
        self.G.add_edge(u, v, etype=etype, **{k: v for k, v in attrs.items() if v is not None})

    def flow(self, u, v, certainty, via=None, **attrs):
        self.edge(u, v, "flow", certainty=certainty, via=via, **attrs)

    def artifact(self, path: str) -> str:
        return self.keys[f"artifact:{path}"]


def build_graph(
    skill_dir: str | Path,
    extractor: DocExtractor | None = None,
    use_llm: bool = False,
    model: str | None = None,
) -> nx.MultiDiGraph:
    skill = parse_skill(skill_dir)
    warnings = list(skill.warnings)
    if extractor is None:
        extractor, w = get_extractor(use_llm, model)
        warnings += w
    b = GraphBuilder(skill)
    G = b.G

    # ---------------------------------------------------------------- artifacts
    for a in skill.artifacts.values():
        if a.kind in ("code", "doc"):
            b.node(f"artifact:{a.path}", "Artifact", a.path, kind=a.kind, path=a.path, lang=a.lang, modality=a.kind)
    ctx = b.node("ctx", "AgentContext", "Agent context", future_sessions=False)

    # ---------------------------------------------------------------- code
    summaries: dict[str, ScriptSummary] = {}
    port_nodes: dict[tuple[str, str], str] = {}
    for a in skill.code_artifacts():
        s = analyze_script(skill.root, a.path, a.lang)
        summaries[a.path] = s
        warnings += s.warnings
        art = b.artifact(a.path)
        local: dict[str, str] = {}
        base = a.path.rsplit("/", 1)[-1]
        for i in s.inputs:
            nid = b.node(f"code:{a.path}:{i.id}", "Operator", f"{base} {i.name}", role="neutral", port=i.name,
                         position=i.position, flag=i.flag, script=a.path, modality="code",
                         evidence=i.evidence.to_dict(), **{"in": "code"})
            G.nodes[nid]["operator_kind"] = "script_input"
            local[i.id] = nid
            port_nodes[(a.path, i.id)] = nid
            b.edge(art, nid, "defines")
        for src in s.sources:
            nid = b.node(f"code:{a.path}:{src.id}", "Source", f"{src.label} [{src.trust}]", trust=src.trust,
                         found_in=src.found_in, category=src.category, modality="code", evidence=src.evidence.to_dict())
            local[src.id] = nid
            b.edge(art, nid, "defines")
        for op in s.operators:
            nid = b.node(f"code:{a.path}:{op.id}", "Operator", f"{base}: {op.label}", role=op.role,
                         sink_category=op.sink_category, modality="code", evidence=op.evidence.to_dict(),
                         **{"in": "code"})
            local[op.id] = nid
            b.edge(art, nid, "defines")
            if op.sink_category == "context_output":
                b.flow(nid, ctx, "deterministic", via="stdout")
            if op.sink_category == "agent_config_write":
                b.flow(nid, ctx, "deterministic", via="persists", future_sessions=True)
                G.nodes[ctx]["future_sessions"] = True
        for u, v in sorted(s.flows):
            if u in local and v in local:
                b.flow(local[u], local[v], "deterministic", via="code")
        for ref, _line in s.refers:
            tokens = set(re.split(r"[./\\]", ref))
            for other in skill.code_artifacts():
                stem = other.path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                if other.path != a.path and stem in tokens:
                    b.edge(art, b.artifact(other.path), "refers")

    # ---------------------------------------------------------------- doc refs
    for doc in skill.docs.values():
        for r in doc.refs:
            b.edge(b.artifact(doc.path), b.artifact(r.target), "refers")

    # ---------------------------------------------------------------- doc instructions
    raw = extractor.extract(skill)
    records, rejected = validate_records(raw, skill, summaries)
    binding_errors: list[dict] = []
    op_of: dict[str, str] = {}
    env_reads = False

    def doc_source(rec, label_text, decision, slot=None):
        ev = rec["evidence"]
        key = f"docsrc:{ev['file']}:{ev['lines'][0]}:{decision.category}:{slot or label_text}"
        nid = b.node(key, "Source", f"{decision.category}: {_short(label_text, 40)} [{decision.trust}]",
                     trust=decision.trust, found_in="doc", category=decision.category, decided_by=decision.decided_by,
                     rule=decision.rule, filled_from=label_text, modality="doc", evidence=ev)
        b.edge(b.artifact(ev["file"]), nid, "defines")
        return nid

    def doc_op(rec, label, role, sink=None, **extra):
        ev = rec["evidence"]
        nid = b.node(f"docop:{rec['id']}", "Operator", label, role=role, sink_category=sink, modality="doc",
                     action=rec["action"], record_id=rec["id"], confidence=rec.get("confidence"),
                     extractor=rec.get("extractor"), evidence=ev, **{"in": "doc"}, **extra)
        b.edge(b.artifact(ev["file"]), nid, "defines")
        op_of[rec["id"]] = nid
        return nid

    def bind_arg(rec, arg, dst, binds):
        d = classify(arg.get("filled_from"))
        extra = dict(binds=binds, filled_from=_short(arg.get("filled_from") or "", 120), decided_by=d.decided_by)
        if d.from_context:
            b.flow(ctx, dst, "probabilistic", via="llm_binding", **extra)
        else:
            src = doc_source(rec, arg.get("filled_from") or arg["slot"], d, slot=arg["slot"])
            b.flow(src, dst, "extracted", via="doc_instruction", **extra)

    for rec in records:
        act, ev = rec["action"], rec["evidence"]
        if act == "invoke_script":
            script = rec["target"]
            binds_all = []
            for arg in rec["args"]:
                port_label = arg.get("flag") or f"argv[{arg.get('position')}]"
                if arg.get("unbound") or "input_id" not in arg:
                    binding_errors.append({"record": rec["id"], "script": script, "slot": arg["slot"],
                                           "position": arg.get("position"), "flag": arg.get("flag"),
                                           "reason": "no matching script input", "evidence": ev})
                    continue
                port = port_nodes[(script, arg["input_id"])]
                binds = f"<{arg['slot']}> -> {port_label}"
                binds_all.append(binds)
                bind_arg(rec, arg, port, binds)
            b.edge(b.artifact(ev["file"]), b.artifact(script), "refers", binds=", ".join(binds_all) or None)
            # chaining target: the script's stdout operators
            outs = [n for n in G.successors(b.artifact(script)) if G.nodes[n].get("sink_category") == "context_output"]
            if outs:
                op_of[rec["id"]] = outs[0]
        elif act == "run_shell":
            op = doc_op(rec, f"shell: {_short(rec['target'])}", "sink", "shell_exec")
            for arg in rec["args"]:
                bind_arg(rec, arg, op, f"<{arg['slot']}>")
        elif act in ("fetch", "read_file"):
            env_reads = True
            d = classify_read_target(rec["target"])
            if act == "fetch":
                d = TrustDecision("web_content", "untrusted", "rule", "fetch")
            op = doc_op(rec, f"{act.replace('_file', '')}: {_short(rec['target'])}", "neutral")
            src = doc_source(rec, rec["target"], d)
            b.flow(src, op, "extracted", via="doc_instruction")
            b.flow(op, ctx, "extracted", via="doc_instruction")
        elif act == "write_file":
            # Only writes to agent config files are sinks at doc level: untrusted *content* in an ordinary
            # file is not a finding (same rule as code-level writes, see code_analysis._content_flow).
            cat = "agent_config_write" if is_agent_config_path(rec["target"]) else None
            op = doc_op(rec, f"write: {rec['target']}", "sink" if cat else "neutral", cat, target=rec["target"])
            prev = op_of.get(rec.get("input_from") or "")
            if prev:
                b.flow(prev, op, "extracted", via="doc_instruction")
            else:
                b.flow(ctx, op, "probabilistic", via="doc_instruction")
            if cat == "agent_config_write":
                b.flow(op, ctx, "deterministic", via="persists", future_sessions=True)
                G.nodes[ctx]["future_sessions"] = True
        elif act == "follow_content":
            op = doc_op(rec, f"follow content: {_short(ev['quote'], 40)}", "sink", "shell_exec")
            b.flow(ctx, op, "probabilistic", via="doc_instruction")
        elif act == "report_to_user":
            op = doc_op(rec, "report to user", "neutral")
            b.flow(ctx, op, "probabilistic", via="doc_instruction")
        elif act == "receive_messages":
            # text written by other parties (agents, users, mail senders) lands in the context
            d = TrustDecision("external_text", "untrusted", "rule", "receive_messages")
            op = doc_op(rec, f"receive: {_short(rec['target'])}", "neutral")
            src = doc_source(rec, rec["target"] or "inbound messages", d)
            b.flow(src, op, "extracted", via="doc_instruction")
            b.flow(op, ctx, "extracted", via="doc_instruction")
        elif act == "call_api":
            moves_value = bool(VALUE_TRANSFER_RE.search(rec["target"]))
            cat = "value_transfer" if moves_value else "privileged_api"
            op = doc_op(rec, f"api: {_short(rec['target'])}", "sink", cat, target=rec["target"])
            prev = op_of.get(rec.get("input_from") or "")
            b.flow(prev or ctx, op, "extracted" if prev else "probabilistic", via="doc_instruction")
            for arg in rec["args"]:
                bind_arg(rec, arg, op, f"<{arg['slot']}>")

    # ---------------------------------------------------------------- defaults
    if env_reads:
        env = b.node("env_default", "Source", DEFAULT_ENV_LABEL, trust="untrusted", found_in="environment",
                     category="environment_content", default=True,
                     note="Added because the skill instructs the agent to read environment data (files/pages/issues).")
        b.flow(env, ctx, "probabilistic", via="doc_instruction", default=True)

    # secrets the skill declares it needs (frontmatter requires.env). They live in the environment of the agent's
    # commands, NOT in its context: no flow edge to the context (only printed values label the context). They are
    # recorded so the T8 query can report "untrusted context + shell/network + reachable secret".
    for var in declared_requires(skill.frontmatter, "env"):
        if not SECRET_ENV_RE.search(var):
            continue
        line = next((i + 1 for i, t in enumerate(skill.skill_md.lines) if var in t), 1)
        ev = {"file": "SKILL.md", "lines": [line, line], "quote": var}
        src = b.node(f"envsecret:{var}", "Source", f"env {var} [secret]", trust="secret", found_in="environment",
                     category="env_secret", decided_by="rule", rule="declared_env", env_var=var, modality="doc",
                     evidence=ev)
        b.edge(b.artifact("SKILL.md"), src, "defines")
    G.graph["declared_bins"] = declared_requires(skill.frontmatter, "bins")

    breadth = description_breadth(skill.description)
    desc_line = next((i + 1 for i, t in enumerate(skill.skill_md.lines) if t.strip().startswith("description:")), 1)
    trig = b.node("trigger", "Operator", f"trigger: {skill.name} (breadth {breadth})", role="sink",
                  sink_category="skill_trigger", breadth=breadth, modality="doc",
                  evidence={"file": "SKILL.md", "lines": [desc_line, desc_line], "quote": skill.description},
                  **{"in": "doc"})
    b.edge(b.artifact("SKILL.md"), trig, "defines")
    if breadth >= TRIGGER_BREADTH_THRESHOLD:
        b.flow(ctx, trig, "probabilistic", via="trigger", breadth=breadth)

    compute_context_labels(G)
    if G.nodes[ctx]["holds_secret"]:
        eg = b.node("egress_default", "Operator", DEFAULT_EGRESS_LABEL, role="sink", sink_category="network_egress",
                    default=True, note="Added because the context holds a secret: any generic network-capable tool "
                    "use by the agent is a possible outflow.", **{"in": "doc"})
        b.flow(ctx, eg, "probabilistic", via="default_outflow", default=True)
        compute_context_labels(G)

    G.graph.update(
        skill=skill.name,
        skill_dir=str(skill.root),
        description=skill.description,
        extractor=extractor.name,
        trigger_breadth=breadth,
        warnings=warnings,
        records=records,
        rejected_records=rejected,
        declared_bins=G.graph.get("declared_bins", []),
        binding_errors=binding_errors,
    )
    return G


def compute_context_labels(G: nx.MultiDiGraph) -> None:
    """Propagate Source reachability over flow edges (sanitizers block) and label AgentContext."""
    reach: dict[str, set[str]] = {n: set() for n in G}
    for n, d in G.nodes(data=True):
        if d["type"] == "Source":
            reach[n].add(n)
    changed = True
    while changed:
        changed = False
        for u, v, d in G.edges(data=True):
            if d.get("etype") != "flow" or G.nodes[u].get("role") == "sanitizer":
                continue
            new = reach[u] - reach[v]
            if new:
                reach[v] |= new
                changed = True
    for n, d in G.nodes(data=True):
        if d["type"] == "AgentContext":
            srcs = sorted(reach[n] - {n})
            d["holds_untrusted"] = any(G.nodes[s].get("trust") == "untrusted" for s in srcs)
            d["holds_secret"] = any(G.nodes[s].get("trust") == "secret" for s in srcs)
            d["label_sources"] = srcs
