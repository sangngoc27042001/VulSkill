"""Run every sample skill with the heuristic and the LLM extractor, time each, and compare the findings.

    uv run python tools/compare_extractors.py [skills_root] [--heuristic-out out] [--llm-out out_llm] [--model M]

Writes, in each output folder:
    <skill>/...        graph files (same as `skill2graph batch`)
    index.html         every graph in the folder, with extractor and build time
    summary.csv        one row per skill (includes extractor, model, seconds)
    timing.csv         skill, extractor, model, seconds for this run
and prints a side-by-side table: time per skill for each extractor, and whether the findings agree.
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

from skill2graph.cli import build_one, refresh_index


def run(skills: list[Path], root: Path, out: Path, use_llm: bool, model: str | None) -> dict[str, dict]:
    label = "llm" if use_llm else "heuristic"
    out.mkdir(parents=True, exist_ok=True)
    rows: dict[str, dict] = {}
    t0 = time.perf_counter()
    for sd in skills:
        rel = sd.relative_to(root).as_posix()
        try:
            r = build_one(sd, out / rel, use_llm, model)
        except Exception as e:  # keep going
            print(f"  [error] {label} {rel}: {e}", file=sys.stderr)
            continue
        rows[rel] = r
        print(f"  {label:<9} {rel:<24} {r['seconds']:7.3f} s  candidates={r['candidates']}")
    wall = time.perf_counter() - t0
    with open(out / "timing.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["skill", "extractor", "model", "seconds"])
        for rel, r in rows.items():
            w.writerow([rel, r["extractor"], r["model"] or "", f"{r['seconds']:.3f}"])
        w.writerow(["TOTAL", label, "", f"{wall:.3f}"])
    refresh_index(out)
    rows["__wall__"] = {"seconds": wall}
    return rows


def finding(r: dict) -> tuple:
    return (r["candidates"], tuple(r["sinks"]), tuple(r["patterns"]), r["confluence"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("skills_root", nargs="?", default="sample_skills", type=Path)
    ap.add_argument("--heuristic-out", default="out", type=Path)
    ap.add_argument("--llm-out", default="out_llm", type=Path)
    ap.add_argument("--model", default=None, help="Azure deployment (default: QLAY_AI_DEPLOYMENT)")
    a = ap.parse_args()
    load_dotenv(find_dotenv(usecwd=True), override=False)

    from skill2graph.doc_extraction import LLMExtractor

    if not LLMExtractor.available():
        print("LLM settings missing (QLAY_AI_FOUNDERY / QLAY_AI_FOUNDERY_API_KEY in .env)", file=sys.stderr)
        return 2
    root = a.skills_root
    skills = sorted({p.parent for p in root.rglob("SKILL.md")})
    print(f"{len(skills)} skill(s) under {root}\n")
    print("heuristic ->", a.heuristic_out)
    h = run(skills, root, a.heuristic_out, False, None)
    print("\nllm ->", a.llm_out)
    l = run(skills, root, a.llm_out, True, a.model)

    names = [k for k in h if k != "__wall__" and k in l]
    w = max([len(n) for n in names] + [5])
    print(f"\n{'skill':<{w}}  {'heur s':>7}  {'llm s':>7}  {'heur':<14} {'llm':<14} agree")
    print(f"{'-' * w}  {'-' * 7}  {'-' * 7}  {'-' * 14} {'-' * 14} -----")
    differ = []
    for n in names:
        hr, lr = h[n], l[n]
        same = finding(hr) == finding(lr)
        if not same:
            differ.append(n)
        fmt = lambda r: f"{r['candidates']} {' '.join(r['patterns']) or '-'}"  # noqa: E731
        print(f"{n:<{w}}  {hr['seconds']:7.3f}  {lr['seconds']:7.3f}  {fmt(hr):<14} {fmt(lr):<14} "
              f"{'yes' if same else 'NO'}")
    hs = sum(h[n]["seconds"] for n in names)
    ls = sum(l[n]["seconds"] for n in names)
    print(f"{'TOTAL':<{w}}  {hs:7.3f}  {ls:7.3f}")
    print(f"{'mean':<{w}}  {hs / max(len(names), 1):7.3f}  {ls / max(len(names), 1):7.3f}")
    print(f"\nwall time: heuristic {h['__wall__']['seconds']:.1f} s, llm {l['__wall__']['seconds']:.1f} s")
    print(f"findings differ for {len(differ)} skill(s){': ' + ', '.join(differ) if differ else ''}")
    print(f"timing written to {a.heuristic_out / 'timing.csv'} and {a.llm_out / 'timing.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
