"""Run the --llm extractor N times on every sample skill and compare each outcome with the heuristic one.

Usage: uv run python tools/llm_stability.py [N]   (default 5; needs the .env settings, makes N x skills LLM calls)
"""
import collections, sys
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(".env")
from skill2graph.build import build_graph
from skill2graph.query import run_queries

N = int(sys.argv[1]) if len(sys.argv) > 1 else 5
def sig(r):
    return tuple(sorted({(c["shape"]["source_trust"] or "?", c["shape"]["sink_category"]) for c in r["candidates"]})), bool(r["confluence"])
for d in sorted(p for p in Path("sample_skills").iterdir() if (p / "SKILL.md").exists()):
    h = sig(run_queries(build_graph(d)))
    runs = collections.Counter(sig(run_queries(build_graph(d, use_llm=True))) for _ in range(N))
    agree = runs.get(h, 0)
    print(f"{d.name:20s} LLM matches heuristic {agree}/{N}" + ("" if agree == N else f"   other outcomes: {[(k, v) for k, v in runs.items() if k != h]}"))
