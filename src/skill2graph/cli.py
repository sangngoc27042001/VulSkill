"""Command line interface: ``skill2graph build|paths|batch``."""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from .build import build_graph
from .export import write_graphml, write_json, write_paths
from .query import run_queries
from .visualize import write_html, write_mermaid

DEFAULT_MODEL = None  # None -> QLAY_AI_DEPLOYMENT from .env, else gpt-5.2


def build_one(skill_dir: Path, out_dir: Path, use_llm: bool = False, model: str = DEFAULT_MODEL) -> dict:
    t0 = time.perf_counter()
    G = build_graph(skill_dir, use_llm=use_llm, model=model)
    result = run_queries(G)
    seconds = time.perf_counter() - t0
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(G, out_dir / "graph.json")
    write_graphml(G, out_dir / "graph.graphml")
    write_paths(result, out_dir / "paths.json")
    write_html(G, result, out_dir / "graph.html")
    write_mermaid(G, out_dir / "graph.mmd")
    extractor = G.graph.get("extractor", "")
    if extractor == "llm":
        from .doc_extraction import default_model

        model = model or default_model()
    meta = {"skill": G.graph["skill"], "skill_dir": str(skill_dir), "extractor": extractor,
            "model": model if extractor == "llm" else None, "seconds": round(seconds, 3),
            "built_at": datetime.now().isoformat(timespec="seconds")}
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    ctx = next(d for _, d in G.nodes(data=True) if d["type"] == "AgentContext")
    return {
        "skill": G.graph["skill"],
        "dir": out_dir,
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "candidates": len(result["candidates"]),
        "top_sink": result["candidates"][0]["shape"]["sink_category"] if result["candidates"] else "",
        "sinks": sorted({c["shape"]["sink_category"] for c in result["candidates"]}),
        "patterns": sorted({c["pattern"]["id"] for c in result["candidates"] + result["confluence"]
                            + result.get("ambient_secrets", [])}),
        "confluence": bool(result["confluence"]),
        "ambient_secret": bool(result.get("ambient_secrets")),
        "holds_untrusted": ctx.get("holds_untrusted", False),
        "holds_secret": ctx.get("holds_secret", False),
        "binding_errors": len(result["binding_errors"]),
        "extractor": extractor,
        "model": meta["model"],
        "seconds": meta["seconds"],
        "built_at": meta["built_at"],
        "result": result,
    }


def row_from_disk(skill_out: Path) -> dict:
    """Summary row for one built skill, read back from its output folder (paths/graph/meta JSON)."""
    paths = json.loads((skill_out / "paths.json").read_text(encoding="utf-8"))
    graph = json.loads((skill_out / "graph.json").read_text(encoding="utf-8"))
    meta_f = skill_out / "meta.json"
    meta = json.loads(meta_f.read_text(encoding="utf-8")) if meta_f.is_file() else {}
    ctx = next((n for n in graph["nodes"] if n.get("type") == "AgentContext"), {})
    cands, conf, amb = paths["candidates"], paths["confluence"], paths.get("ambient_secrets", [])
    return {
        "skill": graph["graph"]["skill"],
        "dir": skill_out,
        "nodes": len(graph["nodes"]),
        "edges": len(graph["edges"]),
        "candidates": len(cands),
        "top_sink": cands[0]["shape"]["sink_category"] if cands else "",
        "sinks": sorted({c["shape"]["sink_category"] for c in cands}),
        "patterns": sorted({c["pattern"]["id"] for c in cands + conf + amb}),
        "confluence": bool(conf),
        "ambient_secret": bool(amb),
        "holds_untrusted": ctx.get("holds_untrusted", False),
        "holds_secret": ctx.get("holds_secret", False),
        "binding_errors": len(paths.get("binding_errors", [])),
        "extractor": meta.get("extractor") or graph["graph"].get("extractor", ""),
        "model": meta.get("model"),
        "seconds": meta.get("seconds"),
        "built_at": meta.get("built_at", ""),
    }


def refresh_index(out: Path) -> list[dict]:
    """Rebuild ``index.html`` and ``summary.csv`` from every graph folder under ``out``."""
    rows = []
    for pj in sorted(out.rglob("paths.json")):
        d = pj.parent
        if d == out or not (d / "graph.json").is_file():
            continue
        try:
            rows.append(row_from_disk(d))
        except (KeyError, ValueError, OSError) as e:
            print(f"[index] skipped {d}: {e}", file=sys.stderr)
    write_index(rows, out)
    write_csv(rows, out)
    return rows


def format_table(result: dict) -> str:
    rows = [("id", "type", "source", "sink", "prob", "x-modal", "code", "path")]
    for c in result["candidates"]:
        s = c["shape"]
        rows.append((c["id"], c["pattern"]["id"], s["source_category"], s["sink_category"], str(s["probabilistic_edges"]),
                     "yes" if s["cross_modal"] else "no", "yes" if s["code_involved"] else "no",
                     " -> ".join(c["path_labels"])))
    n = len(rows[0]) - 1
    widths = [max(len(r[i]) for r in rows) for i in range(n)]
    lines = []
    for i, r in enumerate(rows):
        lines.append("  ".join(r[j].ljust(widths[j]) for j in range(n)) + "  " + r[n])
        if i == 0:
            lines.append("  ".join("-" * w for w in widths) + "  ----")
    if not result["candidates"]:
        lines.append("(no candidate paths)")
    for c in result["confluence"]:
        lines.append(f"\n[confluence {c['id']} · {c['pattern']['id']}] context holds secret + untrusted; outflows: "
                     + ", ".join(o["label"] for o in c["outflows"]))
    for a in result.get("ambient_secrets", []):
        lines.append(f"\n[ambient secret {a['id']} · {a['pattern']['id']}] untrusted context; reachable secret(s): "
                     + ", ".join(a["secret_labels"]) + "; via: " + ", ".join(x["label"] for x in a["capabilities"]))
    used = sorted({c["pattern"]["id"] for c in result["candidates"] + result["confluence"]
                   + result.get("ambient_secrets", [])})
    if used:
        lines.append("\nPattern types:")
        for pid in used:
            P = result["pattern_catalog"][pid]
            lines.append(f"  {pid} {P['name']}: {P['summary']}")
    for b in result["binding_errors"]:
        lines.append(f"[binding error] {b['script']} <{b['slot']}>: {b['reason']}")
    for w in result["warnings"]:
        lines.append(f"[warning] {w}")
    return "\n".join(lines)


def _secs(v) -> str:
    return "" if v is None else f"{v:.3f}"


def write_index(rows: list[dict], out: Path) -> None:
    body = []
    for r in rows:
        rel = r["dir"].relative_to(out).as_posix()
        label = html.escape(r["skill"])
        if r["skill"] != rel:  # folder name differs from the frontmatter name
            label += f" <span class='m'>({html.escape(rel)})</span>"
        ext = r.get("extractor") or ""
        if ext == "llm" and r.get("model"):
            ext += f" · {r['model']}"
        body.append(
            "<tr>"
            f"<td><a href='{html.escape(rel)}/graph.html'>{label}</a></td>"
            f"<td>{r['candidates']}</td><td>{html.escape(' '.join(r.get('patterns', [])))}</td>"
            f"<td>{html.escape(', '.join(r['sinks']))}</td>"
            f"<td>{'yes' if r['confluence'] else ''}</td><td>{'yes' if r.get('ambient_secret') else ''}</td>"
            f"<td>{'U' if r['holds_untrusted'] else ''}{' S' if r['holds_secret'] else ''}</td>"
            f"<td>{r['binding_errors']}</td><td>{r['nodes']}/{r['edges']}</td>"
            f"<td>{html.escape(ext)}</td><td class='n'>{_secs(r.get('seconds'))}</td>"
            f"<td class='m'>{html.escape(r.get('built_at') or '')}</td>"
            f"<td><a href='{html.escape(rel)}/paths.json'>paths</a> · <a href='{html.escape(rel)}/graph.json'>graph</a> · "
            f"<a href='{html.escape(rel)}/graph.mmd'>mmd</a></td></tr>"
        )
    total = f"{sum(r.get('seconds') or 0 for r in rows):.1f}"
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Skill flow graphs</title>
<style>
:root {{ --bg:#fff; --fg:#111827; --muted:#6b7280; --border:#e5e7eb; --link:#6d28d9; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1115; --fg:#e5e7eb; --muted:#9ca3af; --border:#2a2f3a; --link:#a78bfa; }} }}
body {{ background:var(--bg); color:var(--fg); font:14px/1.5 system-ui, sans-serif; margin:24px 16px; }}
table {{ border-collapse:collapse; width:100%; max-width:1100px; }}
th, td {{ text-align:left; padding:6px 10px; border-bottom:1px solid var(--border); }}
th {{ color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; }}
a {{ color:var(--link); }} .wrap {{ overflow-x:auto; }} .m {{ color:var(--muted); font-size:12px; }}
td.n {{ text-align:right; font-variant-numeric:tabular-nums; }}
</style></head><body>
<h1>Skill flow graphs</h1>
<p class="m">{len(rows)} skill(s), {total} s build time in all. Context column: U = holds untrusted, S = holds secret.
Candidates are static hypotheses to be confirmed dynamically. This page lists every graph folder found here, so a
skill built later with <code>skill2graph build</code> appears after a reload.</p>
<div class="wrap"><table><thead><tr><th>Skill</th><th>Candidates</th><th>Patterns</th><th>Sinks</th><th>Confluence</th>
<th>Env secret (T8)</th><th>Context</th><th>Binding errors</th><th>Nodes/edges</th><th>Extractor</th><th>Time (s)</th><th>Built</th>
<th>Files</th></tr></thead>
<tbody>{''.join(body)}</tbody></table></div></body></html>"""
    (out / "index.html").write_text(page, encoding="utf-8")


def write_csv(rows: list[dict], out: Path) -> None:
    with open(out / "summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["skill", "candidates", "top_sink", "sinks", "patterns", "confluence", "holds_untrusted", "holds_secret",
                    "binding_errors", "nodes", "edges", "extractor", "model", "seconds", "built_at", "graph_html",
                    "ambient_secret"])
        for r in rows:
            w.writerow([r["skill"], r["candidates"], r["top_sink"], ";".join(r["sinks"]), ";".join(r["patterns"]), r["confluence"],
                        r["holds_untrusted"], r["holds_secret"], r["binding_errors"], r["nodes"], r["edges"],
                        r.get("extractor", ""), r.get("model") or "", _secs(r.get("seconds")), r.get("built_at", ""),
                        (r["dir"] / "graph.html").relative_to(out).as_posix(), r.get("ambient_secret", False)])


def main(argv: list[str] | None = None) -> int:
    if not os.environ.get("SKILL2GRAPH_NO_DOTENV"):
        from dotenv import find_dotenv, load_dotenv

        load_dotenv(find_dotenv(usecwd=True), override=False)
    p = argparse.ArgumentParser(prog="skill2graph", description="Build Skill Flow Graphs from agent skill folders.")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="build graph + paths + visualization for one skill")
    b.add_argument("skill_dir", type=Path)
    b.add_argument("-o", "--out", type=Path, default=None, help="output dir (default: ./out/<skill>)")
    b.add_argument("--llm", action="store_true", help="use the Azure OpenAI LLM extractor (settings from .env)")
    b.add_argument("--model", default=DEFAULT_MODEL, help="Azure deployment name (default: QLAY_AI_DEPLOYMENT)")
    q = sub.add_parser("paths", help="print ranked candidate paths for one skill")
    q.add_argument("skill_dir", type=Path)
    q.add_argument("--llm", action="store_true")
    q.add_argument("--model", default=DEFAULT_MODEL, help="Azure deployment name (default: QLAY_AI_DEPLOYMENT)")
    bt = sub.add_parser("batch", help="process every subfolder containing SKILL.md")
    bt.add_argument("skills_root", type=Path)
    bt.add_argument("-o", "--out", type=Path, required=True)
    bt.add_argument("--llm", action="store_true")
    bt.add_argument("--model", default=DEFAULT_MODEL, help="Azure deployment name (default: QLAY_AI_DEPLOYMENT)")
    ix = sub.add_parser("index", help="rebuild index.html and summary.csv from the graph folders in an output dir")
    ix.add_argument("out", type=Path)
    a = p.parse_args(argv)

    if a.cmd == "build":
        out = a.out or Path("out") / a.skill_dir.resolve().name
        r = build_one(a.skill_dir, out, a.llm, a.model)
        print(f"{r['skill']}: {r['nodes']} nodes, {r['edges']} edges, {r['candidates']} candidate(s)"
              f"{', confluence' if r['confluence'] else ''} -> {out}")
        print(format_table(r["result"]))
        refresh_index(out.parent)
        print(f"updated {out.parent / 'index.html'} ({r['seconds']:.3f} s, {r['extractor']})")
        return 0
    if a.cmd == "index":
        rows = refresh_index(a.out)
        print(f"wrote {a.out / 'index.html'} and {a.out / 'summary.csv'} ({len(rows)} skill(s))")
        return 0
    if a.cmd == "paths":
        G = build_graph(a.skill_dir, use_llm=a.llm, model=a.model)
        print(f"# {G.graph['skill']}")
        print(format_table(run_queries(G)))
        return 0
    if a.cmd == "batch":
        root, out = a.skills_root, a.out
        out.mkdir(parents=True, exist_ok=True)
        skills = sorted({p.parent for p in root.rglob("SKILL.md")})
        rows = []
        for sd in skills:
            rel = sd.relative_to(root).as_posix() if sd != root else sd.name
            try:
                r = build_one(sd, out / rel, a.llm, a.model)
            except Exception as e:  # keep the batch going
                print(f"[error] {sd}: {e}", file=sys.stderr)
                continue
            rows.append(r)
            print(f"{rel:<22} candidates={r['candidates']:<3} sinks={','.join(r['sinks']) or '-':<55}"
                  f" confluence={'yes' if r['confluence'] else 'no':<4} {r['seconds']:6.2f}s")
        all_rows = refresh_index(out)
        print(f"wrote {out / 'index.html'} and {out / 'summary.csv'} ({len(all_rows)} skill(s), "
              f"{sum(r['seconds'] for r in rows):.1f} s for this batch)")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
