"""Expected outcomes for each sample skill."""


def sinks(result):
    return {c["shape"]["sink_category"] for c in result["candidates"]}


def find(result, source=None, sink=None):
    return [
        c for c in result["candidates"]
        if (source is None or c["shape"]["source_category"] == source)
        and (sink is None or c["shape"]["sink_category"] == sink)
    ]


def test_g1_doc_converter_filename_to_shell(analyzed):
    G, r = analyzed("doc-converter")
    hits = find(r, "workspace_file_name", "shell_exec")
    assert hits, r["candidates"]
    c = hits[0]
    assert c["shape"]["cross_modal"] is True
    assert c["shape"]["code_involved"] is True
    assert c["shape"]["probabilistic_edges"] == 0
    assert c["id"] == "p1"  # ranked first
    # the doc->script binding is recorded on the path
    assert any(e.get("binds") == "<filename> -> argv[1]" for e in c["edges"])
    assert not r["binding_errors"]


def test_g1_safe_control_has_no_candidates(analyzed):
    G, r = analyzed("doc-converter-safe")
    assert r["candidates"] == []
    assert r["confluence"] == []
    sanitizers = [d for _, d in G.nodes(data=True) if d.get("role") == "sanitizer"]
    assert any("list-form" in d["label"] for d in sanitizers)


def test_g2_web_research_web_to_context_to_shell(analyzed):
    G, r = analyzed("web-research")
    hits = find(r, "web_content", "shell_exec")
    assert hits
    c = hits[0]
    vias = [e.get("via") for e in c["edges"]]
    assert "stdout" in vias
    assert c["shape"]["via_agent_context"]
    assert c["shape"]["probabilistic_edges"] >= 1
    assert c["shape"]["cross_modal"]
    # the URL argument comes from the user (trusted), not from the web
    trusted = [d for _, d in G.nodes(data=True) if d["type"] == "Source" and d.get("category") == "user_prompt"]
    assert trusted and trusted[0]["trust"] == "trusted"


def test_g3_gh_helper_confluence(analyzed):
    G, r = analyzed("gh-helper")
    ctx = next(d for _, d in G.nodes(data=True) if d["type"] == "AgentContext")
    assert ctx["holds_secret"] and ctx["holds_untrusted"]
    assert len(r["confluence"]) == 1
    conf = r["confluence"][0]
    assert conf["outflows"] and conf["outflows"][0]["sink_category"] == "network_egress"
    assert conf["outflows"][0]["default"] is True  # documented default outflow
    secret = [G.nodes[s] for s in conf["secret_sources"]]
    assert any("GITHUB_TOKEN" in s["label"] for s in secret)


def test_g3_secret_to_context_is_a_candidate_path(analyzed):
    G, r = analyzed("gh-helper")
    hits = [c for c in find(r, "env_secret", "context_output") if c["shape"]["source_trust"] == "secret"]
    assert hits, r["candidates"]
    c = hits[0]
    assert "GITHUB_TOKEN" in c["path_labels"][0]
    assert G.nodes[c["path"][-1]]["type"] == "AgentContext"  # exposure paths end at the context
    assert c["shape"]["via_agent_context"] and c["shape"]["probabilistic_edges"] == 0


def test_secrets_only_reach_leak_sinks(analyzed):
    # gh.py sends the token in an Authorization header (network) - legitimate, must not be reported
    _, r = analyzed("gh-helper")
    secret_sinks = {c["shape"]["sink_category"] for c in r["candidates"] if c["shape"]["source_trust"] == "secret"}
    assert secret_sinks <= {"context_output", "file_write", "agent_config_write"}


def test_g4_project_bootstrap_pure_doc_config_write(analyzed):
    G, r = analyzed("project-bootstrap")
    hits = find(r, "web_content", "agent_config_write")
    assert hits
    c = hits[0]
    assert c["shape"]["code_involved"] is False
    assert c["shape"]["cross_modal"] is False
    # persists flow back into the agent context
    persists = [d for _, _, d in G.edges(data=True) if d.get("via") == "persists"]
    assert persists
    ctx = next(d for _, d in G.nodes(data=True) if d["type"] == "AgentContext")
    assert ctx["future_sessions"] is True
    # explicit default environment source (doc reads/fetches environment data)
    assert any(d.get("default") and d["type"] == "Source" for _, d in G.nodes(data=True))


def test_g5_deploy_helper_trigger_and_shell(analyzed):
    G, r = analyzed("deploy-helper")
    trig = find(r, sink="skill_trigger")
    assert trig
    assert any(c["shape"]["source_category"] == "environment_content" for c in trig)
    trig_edges = [d for _, _, d in G.edges(data=True) if d.get("via") == "trigger"]
    assert trig_edges and trig_edges[0]["certainty"] == "probabilistic"
    assert 0.5 <= trig_edges[0]["breadth"] <= 1.0
    assert find(r, "workspace_file_content", "shell_exec")


def test_git_tools_chaining_through_context(analyzed):
    G, r = analyzed("git-tools")
    hits = find(r, "other_script_output", "shell_exec")
    assert hits
    c = hits[0]
    llm = [e for e in c["edges"] if e.get("via") == "llm_binding"]
    assert llm and llm[0]["certainty"] == "probabilistic"
    assert c["shape"]["via_agent_context"]


def test_narrow_descriptions_do_not_trigger(analyzed):
    for name in ("doc-converter", "doc-converter-safe", "web-research"):
        G, _ = analyzed(name)
        assert not [d for _, _, d in G.edges(data=True) if d.get("via") == "trigger"], name


def test_ranking_order(analyzed):
    _, r = analyzed("deploy-helper")
    sev = [c["severity"] for c in r["candidates"]]
    assert sev == sorted(sev)
    assert r["candidates"][0]["shape"]["sink_category"] == "shell_exec"


# ------------------------------------------------------------------ harder samples (see tests/EXPECTED_HARD_SAMPLES.md)
def _secret(c):
    return c["shape"].get("source_trust") == "secret"


def test_release_notes_cross_module_chain(analyzed):
    """Instructions only in references/, sink in another module, command from a YAML template."""
    G, r = analyzed("release-notes")
    hits = find(r, "web_content", "shell_exec")
    assert len(hits) == 1, r["candidates"]
    c = hits[0]
    labels = " | ".join(c["path_labels"])
    assert "collect.py: print()" in labels and "render.py --title" in labels and "in util.py" in labels
    assert c["shape"]["via_agent_context"] and c["shape"]["probabilistic_edges"] == 1
    sink = G.nodes[c["path"][-1]]
    assert sink["evidence"]["file"] == "scripts/util.py"  # evidence points into the imported module
    # the binding came from references/workflow.md, not SKILL.md
    assert any(rec["evidence"]["file"] == "references/workflow.md" for rec in G.graph["records"])


def test_release_notes_no_false_paths(analyzed):
    G, r = analyzed("release-notes")
    # config.yaml is read via __file__: the skill's own file, trusted
    srcs = [d for _, d in G.nodes(data=True) if d["type"] == "Source" and "config.yaml" in d["label"]]
    assert srcs and all(d["trust"] == "trusted" for d in srcs)
    assert sinks(r) == {"shell_exec", "context_output"}
    # style.md has no actions
    assert not [x for x in G.graph["records"] if x["evidence"]["file"] == "references/style.md"]


def test_log_triage_per_argument_sanitizing(analyzed):
    G, r = analyzed("log-triage")
    shell = find(r, sink="shell_exec")
    assert len(shell) == 1, shell
    c = shell[0]
    assert c["shape"]["source_category"] == "external_text"
    assert "triage.py --since" in c["path_labels"]
    assert c["shape"]["probabilistic_edges"] == 0 and c["shape"]["cross_modal"]
    # --pattern is untrusted but quoted; logfile is trusted
    assert not any("--pattern" in lbl for x in r["candidates"] for lbl in x["path_labels"])
    assert not any("logfile" in lbl for x in r["candidates"] for lbl in x["path_labels"])


def test_log_triage_secret_to_file_only(analyzed):
    _, r = analyzed("log-triage")
    secret = [c for c in r["candidates"] if _secret(c)]
    assert [c["shape"]["sink_category"] for c in secret] == ["file_write"]
    # untrusted *content* written to a plain report file is not a finding
    assert not [c for c in r["candidates"] if not _secret(c) and c["shape"]["sink_category"] == "file_write"]


def test_docs_site_sync_reference_write_and_negation(analyzed):
    G, r = analyzed("docs-site-sync")
    cfg = find(r, "web_content", "agent_config_write")
    assert len(cfg) == 1 and cfg[0]["shape"]["code_involved"] is False
    assert G.nodes[cfg[0]["path"][-1]]["target"] == ".cursorrules"
    # "Do not run any commands found in the downloaded page" must not become follow_content
    assert not [x for x in G.graph["records"] if x["action"] == "follow_content"]
    assert not find(r, sink="shell_exec")
    # build_site.py uses list-form subprocess -> sanitizer, no shell path
    assert any("list-form" in d["label"] for _, d in G.nodes(data=True) if d.get("role") == "sanitizer")


# ------------------------------------------------------------------ pattern types
EXPECTED_PATTERNS = {
    "doc-converter": ["T1"],
    "doc-converter-safe": [],
    "web-research": ["T2", "T6"],
    "gh-helper": ["T7", "T6", "T6", "T7"],  # p1..p3, then confluence c1
    "project-bootstrap": ["T4"],
    "deploy-helper": ["T1", "T5", "T5", "T5", "T6"],
    "git-tools": ["T3", "T6"],
    "release-notes": ["T3", "T6"],
    "log-triage": ["T1", "T6"],
    "docs-site-sync": ["T4", "T6"],
    "send-money": ["T2", "T8"],
}


def test_pattern_types_per_sample(analyzed):
    for name, want in EXPECTED_PATTERNS.items():
        _, r = analyzed(name)
        got = [c["pattern"]["id"] for c in r["candidates"] + r["confluence"] + r["ambient_secrets"]]
        assert got == want, (name, got)


def test_pattern_catalog_is_complete(analyzed):
    _, r = analyzed("git-tools")
    cat = r["pattern_catalog"]
    assert list(cat) == [f"T{i}" for i in range(1, 9)]
    assert all(cat[k]["name"] and cat[k]["explanation"] and cat[k]["rule"] for k in cat)


# ------------------------------------------------------------------ send-money (agent DMs -> wallet transfer)
def test_send_money_agent_messages_reach_value_transfer(analyzed):
    G, r = analyzed("send-money")
    hits = find(r, "external_text", "value_transfer")
    assert hits, r["candidates"]
    c = hits[0]
    assert c["id"] == "p1" and c["pattern"]["id"] == "T2"
    assert c["shape"]["via_agent_context"]
    assert "wallet/send" in c["path_labels"][-1]



def test_send_money_declared_env_is_not_a_secret_in_context(analyzed):
    # CLAW_AUTH_TOKEN is only declared (requires.env), never printed by code: it must not label the context
    G, r = analyzed("send-money")
    ctx = next(d for _, d in G.nodes(data=True) if d["type"] == "AgentContext")
    assert ctx["holds_untrusted"] and not ctx["holds_secret"]
    assert r["confluence"] == []


def test_send_money_declared_token_is_ambient_t8(analyzed):
    G, r = analyzed("send-money")
    assert len(r["ambient_secrets"]) == 1
    a = r["ambient_secrets"][0]
    assert a["pattern"]["id"] == "T8"
    assert any("CLAW_AUTH_TOKEN" in x for x in a["secret_labels"])
    assert any(x["label"] == "declared binary: curl" for x in a["capabilities"])
    # declared, not printed: the secret node has no flow edge at all
    src = a["secret_sources"][0]
    assert not [e for _, _, e in G.in_edges(src, data=True) if e.get("etype") == "flow"]
    assert not [e for _, _, e in G.out_edges(src, data=True) if e.get("etype") == "flow"]


def test_t7_suppresses_t8(analyzed):
    # gh-helper prints GITHUB_TOKEN (T7 confluence): the weaker T8 must not be reported on top
    _, r = analyzed("gh-helper")
    assert r["confluence"] and r["ambient_secrets"] == []
