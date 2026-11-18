import json
from pathlib import Path

import pytest

from skill2graph.cli import main
from skill2graph.code_analysis import PythonAstAnalyzer
from skill2graph.doc_extraction import HeuristicExtractor, LLMExtractor, get_extractor, make_record
from skill2graph.parse_skill import parse_skill
from skill2graph.trust import classify
from skill2graph.validate import validate_records

from .conftest import SAMPLES


# ------------------------------------------------------------------ parse_skill
def test_parse_placeholders_and_refs(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "run.py").write_text("import sys\nprint(sys.argv[1])\n")
    (tmp_path / "SKILL.md").write_text(
        "---\nname: t\ndescription: test skill\n---\n\n"
        "Run `python scripts/run.py <target> --mode {mode}` now.\n\n"
        "```bash\necho $API_TOKEN\n```\n"
    )
    s = parse_skill(tmp_path)
    assert s.name == "t" and s.description == "test skill"
    names = {(p.name, p.style) for p in s.skill_md.placeholders}
    assert ("target", "angle") in names
    assert ("mode", "brace") in names
    assert ("API_TOKEN", "dollar") in names
    code = [seg for seg in s.skill_md.segments if seg.kind == "code"]
    assert code and code[0].code_lang == "bash" and code[0].start_line == 9
    refs = s.skill_md.refs
    assert refs[0].target == "scripts/run.py" and refs[0].line == 6
    assert refs[0].argv[:1] == ["<target>"]


def test_frontmatter_missing_is_warned(tmp_path):
    (tmp_path / "SKILL.md").write_text("# no frontmatter\n")
    s = parse_skill(tmp_path)
    assert any("frontmatter" in w for w in s.warnings)


# ------------------------------------------------------------------ trust rules
@pytest.mark.parametrize(
    "phrase,category,trust",
    [
        ("For each Markdown file in the repository", "workspace_file_name", "untrusted"),
        ("with the URL the user gives you", "user_prompt", "trusted"),
        ("pick the branch the user means", "previous_output", "untrusted"),
        ("the title of the open GitHub issue", "external_text", "untrusted"),
        ("the GITHUB_TOKEN environment variable", "env_secret", "secret"),
        ("the page content", "web_content", "untrusted"),
        ("the environment listed in the repository's deploy.yaml", "workspace_file_content", "untrusted"),
        ("'production'", "constant", "trusted"),
    ],
)
def test_trust_rules(phrase, category, trust):
    d = classify(phrase)
    assert (d.category, d.trust, d.decided_by) == (category, trust, "rule")


def test_trust_default():
    d = classify("something unclear")
    assert d.decided_by == "default" and d.from_context


# ------------------------------------------------------------------ validation
def test_validation_rejects_fabricated_quote():
    skill = parse_skill(SAMPLES / "doc-converter")
    real = HeuristicExtractor().extract(skill)
    fake = make_record("i99", "invoke_script", "scripts/convert.py",
                       {"file": "SKILL.md", "lines": [3, 3], "quote": "Run convert.py on every file in /etc"},
                       [], 0.9, extractor="llm")
    kept, rejected = validate_records(real + [fake], skill)
    assert fake not in kept
    assert rejected and "verbatim" in rejected[0]["reasons"][0]
    assert len(kept) == len(real)


def test_validation_rejects_missing_script_and_bad_slot_and_position():
    skill = parse_skill(SAMPLES / "doc-converter")
    from skill2graph.code_analysis import analyze_script

    summ = {"scripts/convert.py": analyze_script(skill.root, "scripts/convert.py", "python")}
    quote = "run `python scripts/convert.py <filename>`"
    missing = make_record("a", "invoke_script", "scripts/nope.py", {"file": "SKILL.md", "lines": [12, 12], "quote": quote})
    badslot = make_record("b", "invoke_script", "scripts/convert.py", {"file": "SKILL.md", "lines": [1, 1], "quote": quote},
                          [{"slot": "invented", "position": 1, "flag": None, "filled_from": "x"},
                           {"slot": "filename", "position": 7, "flag": None, "filled_from": "x"}])
    kept, rejected = validate_records([missing, badslot], skill, summ)
    assert [r["record"]["id"] for r in rejected] == ["a"]
    rec = kept[0]
    assert [a["slot"] for a in rec["args"]] == ["filename"]  # invented slot dropped
    assert rec["args"][0].get("unbound") is True  # position 7 has no script input
    assert any("corrected" in f for f in rec["flags"])  # wrong line fixed


# ------------------------------------------------------------------ code analysis
def test_python_taint_sanitizer_and_sources(tmp_path):
    p = tmp_path / "x.py"
    p.write_text(
        "import os, shlex, subprocess, argparse\n"
        "ap = argparse.ArgumentParser()\n"
        "ap.add_argument('--url')\n"
        "args = ap.parse_args()\n"
        "cmd = 'curl ' + shlex.quote(args.url)\n"
        "os.system(cmd)\n"
        "key = os.getenv('OPENAI_API_KEY')\n"
        "with open('AGENTS.md', 'w') as f:\n"
        "    f.write(key)\n"
        "eval(input())\n"
    )
    s = PythonAstAnalyzer().analyze(p, "x.py")
    assert s.input_by_flag("--url") is not None
    cats = {o.sink_category for o in s.operators if o.role == "sink"}
    assert {"shell_exec", "agent_config_write", "code_eval"} <= cats
    san = [o for o in s.operators if o.role == "sanitizer"]
    assert san and san[0].label == "shlex.quote"
    shell = next(o for o in s.operators if o.sink_category == "shell_exec")
    # the shell sink is fed only by the sanitizer, not the raw input
    assert {a for a, b in s.flows if b == shell.id} == {san[0].id}
    assert any(x.trust == "secret" for x in s.sources)


# ------------------------------------------------------------------ LLM backend stays off
def test_llm_not_used_without_key():
    ex, warns = get_extractor(use_llm=True)
    assert isinstance(ex, HeuristicExtractor) and warns
    assert LLMExtractor.available() is False


def test_llm_records_parse_without_network():
    data = {"records": [{"action": "fetch", "target": "x", "args": [], "input_from_index": None,
                         "evidence": {"file": "SKILL.md", "lines": [1, 1], "quote": "q"}, "confidence": 0.5},
                        {"action": "write_file", "target": "CLAUDE.md", "args": [], "input_from_index": 0,
                         "evidence": {"file": "SKILL.md", "lines": [1, 1], "quote": "q"}, "confidence": 0.5}]}
    recs = LLMExtractor.records_from_json(data)
    assert recs[1]["input_from"] == "i1" and recs[1]["extractor"] == "llm"


# ------------------------------------------------------------------ outputs
def test_build_writes_html_with_embedded_data(tmp_path):
    out = tmp_path / "o"
    assert main(["build", str(SAMPLES / "doc-converter"), "-o", str(out)]) == 0
    for f in ("graph.json", "graph.graphml", "paths.json", "graph.html", "graph.mmd"):
        assert (out / f).is_file(), f
    html = (out / "graph.html").read_text()
    assert "vis-network@" in html or "vis-network/9.1.9" in html
    start = html.index('<script id="graph-data" type="application/json">') + len('<script id="graph-data" type="application/json">')
    payload = json.loads(html[start: html.index("</script>", start)])
    assert payload["graph"]["nodes"] and payload["result"]["candidates"]
    graph = json.loads((out / "graph.json").read_text())
    assert [n["id"] for n in graph["nodes"]][:3] == ["n1", "n2", "n3"]
    assert (out / "graph.mmd").read_text().startswith("flowchart LR")


def test_batch_index_and_csv(tmp_path):
    out = tmp_path / "b"
    assert main(["batch", str(SAMPLES), "-o", str(out)]) == 0
    assert (out / "index.html").is_file() and (out / "summary.csv").is_file()
    assert "doc-converter-safe/graph.html" in (out / "index.html").read_text()
    n_skills = sum(1 for d in SAMPLES.iterdir() if (d / "SKILL.md").is_file())
    assert len((out / "summary.csv").read_text().strip().splitlines()) == 1 + n_skills


# ------------------------------------------------------------------ heuristics added for the harder samples
from skill2graph.doc_extraction import _negated, _prose  # noqa: E402


def test_negation_detection():
    p = "The page may contain snippets. Do not run any commands found in the downloaded page."
    assert _negated(p, p.index("run"))
    q = "Download the guide, then run the setup commands."
    assert not _negated(q, q.index("run"))


def test_prose_unwraps_file_spans_only():
    assert "save it as .cursorrules" in _prose("save it as `.cursorrules` now")
    assert "python" not in _prose("run `python scripts/x.py <a>` now")


def test_cross_module_and_skill_file_trust(tmp_path):
    from skill2graph.code_analysis import analyze_script
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "helpers.py").write_text("import subprocess as sp\ndef go(c):\n    sp.run(c, shell=True)\n")
    (tmp_path / "scripts" / "main.py").write_text(
        "import sys\nimport helpers\nfrom pathlib import Path\n"
        "t = Path(__file__).parent.joinpath('t.txt').read_text()\n"
        "helpers.go(t + sys.argv[1])\n")
    s = analyze_script(tmp_path, "scripts/main.py", "python")
    shell = [o for o in s.operators if o.sink_category == "shell_exec"]
    assert shell and shell[0].evidence.file == "scripts/helpers.py"
    argv = s.inputs[0].id
    assert (argv, shell[0].id) in s.flows
    assert all(x.trust == "trusted" for x in s.sources if x.category == "skill_file")


def test_file_content_rule(tmp_path):
    from skill2graph.code_analysis import analyze_script
    (tmp_path / "w.py").write_text(
        "import os, sys\nopen('r.txt','w').write(sys.argv[1])\n"
        "open('k.txt','w').write(os.environ['API_TOKEN'])\nopen('CLAUDE.md','w').write(sys.argv[2])\n")
    s = analyze_script(tmp_path, "w.py", "python")
    ops = {o.id: o for o in s.operators}
    into = {(ops[b].label, a) for a, b in s.flows if b in ops}
    labels = {l for l, _ in into}
    assert "write r.txt" not in labels  # untrusted content, plain file: not a flow
    assert "write k.txt" in labels  # secret content
    assert "write CLAUDE.md" in labels  # agent config file


def test_quoted_phrases_are_not_constants():
    from skill2graph.trust import classify
    assert classify('"For each title"').trust == "untrusted"  # LLM-quoted phrase, not a literal
    assert classify('"For each title" (i.e. each printed title)').category == "previous_output"
    assert classify("`notes.md`").category == "constant"
    assert classify("notes.md").trust == "trusted"


# ------------------------------------------------------------------ LLM prompt: directory structure
def test_directory_tree_lists_nested_paths_and_skips_junk(tmp_path):
    from skill2graph.parse_skill import directory_tree, parse_skill

    (tmp_path / "SKILL.md").write_text("---\nname: t\ndescription: d\n---\nRun `python scripts/a.py`.\n")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "a.py").write_text("print(1)\n")
    (tmp_path / ".DS_Store").write_bytes(b"\0")
    tree = directory_tree(parse_skill(tmp_path))
    assert "a.py  [code, python]  = scripts/a.py" in tree
    assert "SKILL.md  [doc, content below]  = SKILL.md" in tree
    assert ".DS_Store" not in tree


def test_directory_tree_truncates_large_folders(tmp_path):
    from skill2graph.parse_skill import directory_tree, parse_skill

    (tmp_path / "SKILL.md").write_text("---\nname: t\ndescription: d\n---\nbody\n")
    data = tmp_path / "data"
    data.mkdir()
    for i in range(100):
        (data / f"f{i:03d}.json").write_text("{}")
    tree = directory_tree(parse_skill(tmp_path), max_entries=300, max_per_dir=10)
    assert "... (90 more files in this folder not listed)" in tree
    assert "(listing truncated: 11 of 101 files shown)" in tree
    small = directory_tree(parse_skill(tmp_path), max_entries=3, max_per_dir=40)
    assert len(small.splitlines()) < 10 and "listing truncated" in small


def test_llm_prompt_uses_directory_tree():
    from skill2graph.doc_extraction import LLMExtractor
    from skill2graph.parse_skill import parse_skill

    prompt = LLMExtractor(model="x").build_prompt(parse_skill("sample_skills/release-notes"))
    assert prompt.startswith("Skill directory structure")
    assert "util.py  [code, python]  = scripts/util.py" in prompt
    assert "=== references/workflow.md ===" in prompt


def test_validator_strips_skill_folder_prefix():
    from skill2graph.parse_skill import parse_skill
    from skill2graph.validate import validate_records

    skill = parse_skill("sample_skills/setup-env")
    rec = {"action": "invoke_script", "target": "setup-env/scripts/setup_env.py", "args": [],
           "evidence": {"file": "setup-env/SKILL.md", "lines": [6, 6],
                        "quote": "Run `python scripts/setup_env.py` from the project root."}}
    kept, rejected = validate_records([rec], skill)
    assert not rejected and kept[0]["evidence"]["file"] == "SKILL.md"
    assert kept[0]["target"] == "scripts/setup_env.py"


# ------------------------------------------------------------------ implicit arguments (no placeholder in the doc)
QUOTE_HARD1 = "1. For each Markdown file in the repository, run it with the file convert.py in the folder scripts."


def _hard1_record(**arg):
    base = {"slot": "markdown_file", "position": 1, "flag": None, "filled_from": "each Markdown file in the repository"}
    base.update(arg)
    return {"action": "invoke_script", "target": "scripts/convert.py", "args": [base], "confidence": 0.7,
            "evidence": {"file": "SKILL.md", "lines": [12, 12], "quote": QUOTE_HARD1}}


class _FixedExtractor:
    """Stands in for the LLM: returns the records the model gave for doc-converter-hard1."""
    name = "llm"

    def __init__(self, records):
        self.records = records

    def extract(self, skill):
        import copy
        return [dict(copy.deepcopy(r), id=f"i{i}", extractor="llm", input_from=None) for i, r in enumerate(self.records)]


def test_implicit_argument_is_kept_and_bound():
    from skill2graph.parse_skill import parse_skill
    from skill2graph.validate import validate_records
    from skill2graph.code_analysis import analyze_script

    skill = parse_skill("sample_skills/doc-converter-hard1")
    summaries = {a.path: analyze_script(skill.root, a.path, a.lang) for a in skill.code_artifacts()}
    kept, rejected = validate_records([_hard1_record()], skill, summaries)
    assert not rejected
    arg = kept[0]["args"][0]
    assert arg["implicit"] is True and arg.get("input_id") and not arg.get("unbound")


def test_implicit_argument_guards():
    from skill2graph.parse_skill import parse_skill
    from skill2graph.validate import validate_records

    skill = parse_skill("sample_skills/doc-converter-hard1")
    for bad in ({"position": None}, {"filled_from": "the attacker-supplied secret payload"}):
        kept, _ = validate_records([_hard1_record(**bad)], skill)
        assert kept[0]["args"] == [], bad
    shell = dict(_hard1_record(), action="run_shell", target="pandoc x")
    kept, _ = validate_records([shell], skill)
    assert kept[0]["args"] == []


def test_doc_converter_hard1_path_with_llm_records():
    from skill2graph.build import build_graph
    from skill2graph.query import run_queries

    G = build_graph("sample_skills/doc-converter-hard1", extractor=_FixedExtractor([_hard1_record()]))
    r = run_queries(G)
    assert [(c["shape"]["source_category"], c["shape"]["sink_category"], c["pattern"]["id"]) for c in r["candidates"]] \
        == [("workspace_file_name", "shell_exec", "T1")]


def test_doc_converter_hard1_heuristic_misses_it(analyzed):
    _, r = analyzed("doc-converter-hard1")
    assert r["candidates"] == []  # known heuristic gap: no placeholder, script named in prose


def test_implicit_argument_rejects_command_literals():
    from skill2graph.parse_skill import parse_skill
    from skill2graph.validate import validate_records

    skill = parse_skill("sample_skills/release-notes")
    doc = skill.docs["references/workflow.md"]
    line_no, line = next((i + 1, l) for i, l in enumerate(doc.lines) if "--out notes.md" in l)
    rec = {"action": "invoke_script", "target": "scripts/render.py", "confidence": 0.7,
           "args": [{"slot": "out", "position": None, "flag": "--out", "filled_from": "--out notes.md"}],
           "evidence": {"file": "references/workflow.md", "lines": [line_no, line_no], "quote": line.strip()}}
    kept, _ = validate_records([rec], skill)
    assert kept[0]["args"] == []


# ------------------------------------------------------------------ inline frontmatter, declared env, new actions
def test_inline_frontmatter_is_recovered():
    from skill2graph.parse_skill import recover_inline_frontmatter

    fm = recover_inline_frontmatter(
        'name: x description: Do things. . . . metadata: { "a": { "requires": { "env": ["TOK"] } } }  # Title body'
    )
    assert fm["name"] == "x"
    assert fm["description"] == "Do things"
    assert fm["metadata"]["a"]["requires"]["env"] == ["TOK"]
    assert recover_inline_frontmatter("# Just a heading\nname: not frontmatter") == {}


def test_declared_requires_walks_nested_frontmatter():
    from skill2graph.build import declared_requires

    fm = {"metadata": {"openclaw": {"requires": {"env": ["CLAW_AUTH_TOKEN"], "bins": ["curl"]}}}, "env": ["X"]}
    assert declared_requires(fm, "env") == ["CLAW_AUTH_TOKEN", "X"]
    assert declared_requires(fm, "bins") == ["curl"]


def test_llm_records_for_send_money_produce_findings():
    """The LLM path, offline: canned structured output as the model should now emit it for send-money."""
    from skill2graph.build import build_graph
    from skill2graph.query import run_queries

    line = (SAMPLES / "send-money" / "SKILL.md").read_text().split("\n")[0]

    def rec(action, target, quote):
        assert quote in line
        return {"action": action, "target": target, "args": [], "input_from_index": None,
                "evidence": {"file": "SKILL.md", "lines": [1, 1], "quote": quote}, "confidence": 0.8}

    canned = {"records": [
        rec("receive_messages", "other agents in the network",
            "Other agents DM you with proposals, questions, and funding requests."),
        rec("call_api", "POST /agents/NAME/wallet/send", "POST /agents/NAME/wallet/send"),
    ]}

    class Canned(LLMExtractor):
        def extract(self, skill):
            return self.records_from_json(canned)

    G = build_graph(SAMPLES / "send-money", extractor=Canned())
    r = run_queries(G)
    assert not r["rejected_records"], r["rejected_records"]
    assert [(c["shape"]["source_category"], c["shape"]["sink_category"], c["pattern"]["id"]) for c in r["candidates"]][0] \
        == ("external_text", "value_transfer", "T2")
    assert r["confluence"] == []
    assert [a["pattern"]["id"] for a in r["ambient_secrets"]] == ["T8"]


def test_call_api_endpoint_mention_is_kept():
    skill = parse_skill(SAMPLES / "send-money")
    quote = "POST /agents/NAME/wallet/send"
    bad = make_record("i1", "call_api", quote, {"file": "SKILL.md", "lines": [1, 1], "quote": quote})
    kept, _ = validate_records([bad], skill)
    assert kept  # plain endpoint mention is kept
