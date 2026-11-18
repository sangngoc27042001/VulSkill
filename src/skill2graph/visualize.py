"""Interactive HTML (vis-network) and Mermaid renderings of a Skill Flow Graph."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

import networkx as nx

from .export import to_node_link

VIS_NETWORK_URL = "https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js"


def render_html(G: nx.MultiDiGraph, result: dict) -> str:
    payload = {"graph": to_node_link(G), "result": result}
    data = json.dumps(payload, default=str).replace("</", "<\\/")
    title = html.escape(f"{G.graph.get('skill', 'skill')} flow graph")
    return (
        _TEMPLATE.replace("__TITLE__", title)
        .replace("__VIS_URL__", VIS_NETWORK_URL)
        .replace("__DATA__", data)
    )


def write_html(G: nx.MultiDiGraph, result: dict, path: str | Path) -> None:
    Path(path).write_text(render_html(G, result), encoding="utf-8")


# --------------------------------------------------------------------------- Mermaid


def _mm_label(text: str) -> str:
    text = re.sub(r"\s+", " ", str(text))
    return text.replace('"', "#quot;").replace("<", "#lt;").replace(">", "#gt;")[:70]


def render_mermaid(G: nx.MultiDiGraph) -> str:
    lines = ["flowchart LR"]
    for n, d in G.nodes(data=True):
        lab = _mm_label(d.get("label", n))
        t = d["type"]
        if t == "Artifact":
            lines.append(f'  {n}["{lab}"]:::{"code" if d.get("kind") == "code" else "doc"}')
        elif t == "Source":
            lines.append(f'  {n}[/"{lab}"/]:::{d.get("trust", "trusted")}')
        elif t == "Operator":
            lines.append(f'  {n}{{{{"{lab}"}}}}:::{d.get("role", "neutral")}')
        else:
            lines.append(f'  {n}(("{lab}")):::ctx')
    for u, v, d in G.edges(data=True):
        et = d.get("etype")
        if et == "refers":
            b = d.get("binds")
            lines.append(f'  {u} -.->|"refers{": " + _mm_label(b) if b else ""}"| {v}')
        elif et == "defines":
            lines.append(f"  {u} -.- {v}")
        else:
            lab = d.get("certainty", "")
            if d.get("via"):
                lab += f" / {d['via']}"
            arrow = "==>" if d.get("certainty") == "deterministic" else "-->"
            lines.append(f'  {u} {arrow}|"{_mm_label(lab)}"| {v}')
    lines += [
        "  classDef code fill:#dbeafe,stroke:#2563eb,color:#111",
        "  classDef doc fill:#fef3c7,stroke:#d97706,color:#111",
        "  classDef untrusted fill:#dc2626,stroke:#7f1d1d,color:#fff",
        "  classDef secret fill:#f97316,stroke:#9a3412,color:#fff",
        "  classDef trusted fill:#16a34a,stroke:#14532d,color:#fff",
        "  classDef sink fill:#7f1d1d,stroke:#450a0a,color:#fff",
        "  classDef sanitizer fill:#2563eb,stroke:#1e3a8a,color:#fff",
        "  classDef neutral fill:#6b7280,stroke:#374151,color:#fff",
        "  classDef ctx fill:#7c3aed,stroke:#4c1d95,color:#fff",
    ]
    return "\n".join(lines) + "\n"


def write_mermaid(G: nx.MultiDiGraph, path: str | Path) -> None:
    Path(path).write_text(render_mermaid(G), encoding="utf-8")


# --------------------------------------------------------------------------- HTML template

_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<script src="__VIS_URL__"></script>
<style>
:root {
  --bg: #ffffff; --panel: #f6f7f9; --fg: #111827; --muted: #6b7280; --border: #e5e7eb;
  --accent: #7c3aed; --hl: #fde68a; --det: #111827;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0f1115; --panel: #171a21; --fg: #e5e7eb; --muted: #9ca3af; --border: #2a2f3a;
    --accent: #a78bfa; --hl: #854d0e; --det: #e5e7eb;
  }
}
:root[data-theme="dark"] {
  --bg: #0f1115; --panel: #171a21; --fg: #e5e7eb; --muted: #9ca3af; --border: #2a2f3a;
  --accent: #a78bfa; --hl: #854d0e; --det: #e5e7eb;
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; background: var(--bg); color: var(--fg);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
#app { display: grid; grid-template-columns: 1fr 360px; height: 100vh; }
#graph { position: relative; min-height: 60vh; }
#net { position: absolute; inset: 0; }
#toolbar { position: absolute; top: 8px; left: 8px; z-index: 5; display: flex; gap: 6px; flex-wrap: wrap; }
#toolbar button, #toolbar label { background: var(--panel); color: var(--fg); border: 1px solid var(--border);
  border-radius: 6px; padding: 4px 8px; font: inherit; font-size: 12px; cursor: pointer; }
aside { background: var(--panel); border-left: 1px solid var(--border); overflow-y: auto; padding: 14px 16px; }
h1 { font-size: 17px; margin: 0 0 4px; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 18px 0 6px; }
.desc { color: var(--muted); margin: 0 0 8px; }
.badge { display: inline-block; border-radius: 999px; padding: 1px 8px; font-size: 11px; margin: 0 4px 4px 0;
  border: 1px solid var(--border); }
.badge.bad { background: #dc2626; color: #fff; border-color: #dc2626; }
.badge.warn { background: #f97316; color: #fff; border-color: #f97316; }
.badge.ok { background: #16a34a; color: #fff; border-color: #16a34a; }
.path { border: 1px solid var(--border); border-radius: 8px; padding: 8px; margin-bottom: 6px; cursor: pointer;
  background: var(--bg); }
.path:hover { border-color: var(--accent); }
.path.active { outline: 2px solid var(--accent); }
.path .head { font-weight: 600; }
.path .chain { color: var(--muted); font-size: 12px; margin-top: 3px; word-break: break-word; }
.legend { display: grid; grid-template-columns: 22px 1fr; gap: 4px 8px; align-items: center; font-size: 12px; }
#details { font-size: 12px; white-space: pre-wrap; word-break: break-word; background: var(--bg);
  border: 1px solid var(--border); border-radius: 8px; padding: 8px; min-height: 40px; }
.empty { color: var(--muted); font-style: italic; }
.ptag { display: inline-block; font-size: 11px; font-weight: 600; border-radius: 4px; padding: 0 6px; margin-right: 4px;
  background: var(--accent); color: #fff; }
.path .psum { font-size: 12px; margin-top: 3px; }
.pbox { border: 1px solid var(--border); border-left: 4px solid var(--accent); border-radius: 0 8px 8px 0;
  padding: 8px; margin-bottom: 8px; font-size: 12px; white-space: normal; }
.pbox .pname { font-weight: 600; font-size: 13px; margin-bottom: 4px; }
.pbox .prule { font-family: ui-monospace, monospace; color: var(--muted); margin-top: 6px; }
#details pre { margin: 0; white-space: pre-wrap; word-break: break-word; }
#patterns details { border: 1px solid var(--border); border-radius: 8px; padding: 6px 8px; margin-bottom: 6px; font-size: 12px; }
#patterns details.present { border-color: var(--accent); }
#patterns summary { cursor: pointer; }
#patterns details p { margin: 6px 0 0; }
#patterns .count { color: var(--muted); }
.vis-tooltip { max-width: 420px; white-space: pre-wrap !important; font: 12px/1.4 ui-monospace, monospace !important;
  background: var(--panel) !important; color: var(--fg) !important; border: 1px solid var(--border) !important; }
@media (max-width: 860px) {
  #app { grid-template-columns: 1fr; grid-template-rows: 65vh auto; height: auto; }
  aside { border-left: 0; border-top: 1px solid var(--border); }
}
</style>
</head>
<body>
<div id="app">
  <div id="graph">
    <div id="toolbar">
      <button id="fit" type="button">Fit</button>
      <button id="clear" type="button">Clear highlight</button>
      <label><input type="checkbox" id="showProv" checked> refers/defines</label>
      <label><input type="checkbox" id="physics"> physics</label>
    </div>
    <div id="net"></div>
  </div>
  <aside>
    <h1 id="skill"></h1>
    <p class="desc" id="desc"></p>
    <div id="badges"></div>
    <h2>Candidate paths</h2>
    <div id="paths"></div>
    <h2>Confluence</h2>
    <div id="conf"></div>
    <h2>Pattern types</h2>
    <div id="patterns"></div>
    <h2>Selected</h2>
    <div id="details" class="empty">Click a node, edge or path.</div>
    <h2>Legend</h2>
    <div class="legend" id="legend"></div>
    <h2>Notes</h2>
    <div id="notes"></div>
  </aside>
</div>
<script id="graph-data" type="application/json">__DATA__</script>
<script>
(function () {
  const payload = JSON.parse(document.getElementById("graph-data").textContent);
  const G = payload.graph, R = payload.result;
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const byId = Object.fromEntries(G.nodes.map((n) => [n.id, n]));

  const COLORS = {
    code: { background: "#dbeafe", border: "#2563eb" }, doc: { background: "#fef3c7", border: "#d97706" },
    untrusted: "#dc2626", secret: "#f97316", trusted: "#16a34a",
    sink: "#7f1d1d", sanitizer: "#2563eb", neutral: "#6b7280", ctx: "#7c3aed",
    extracted: "#2563eb", probabilistic: "#ea580c", refers: "#9ca3af", defines: "#cbd5e1",
  };

  function tooltip(obj, skip) {
    const el = document.createElement("div");
    const lines = [];
    for (const [k, v] of Object.entries(obj)) {
      if (skip.includes(k) || v === null || v === undefined) continue;
      if (k === "evidence" && v) {
        lines.push(`evidence: ${v.file}:${(v.lines || []).join("-")}\n  "${v.quote}"`);
      } else {
        lines.push(`${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`);
      }
    }
    el.textContent = lines.join("\n");
    return el;
  }

  function nodeStyle(n) {
    const fg = css("--fg");
    const s = { id: n.id, label: n.label, font: { color: fg, size: 13, face: "system-ui" }, borderWidth: 2 };
    if (n.type === "Artifact") {
      Object.assign(s, { shape: "box", color: COLORS[n.kind] || COLORS.doc, font: { color: "#111827", size: 13 },
        shapeProperties: { borderRadius: 2 }, margin: 8 });
    } else if (n.type === "Source") {
      const c = COLORS[n.trust] || COLORS.trusted;
      Object.assign(s, { shape: "diamond", size: 16, color: { background: c, border: c } });
    } else if (n.type === "Operator") {
      const c = COLORS[n.role] || COLORS.neutral;
      Object.assign(s, { shape: n.operator_kind === "script_input" ? "triangle" : "hexagon", size: 15,
        color: { background: c, border: c } });
    } else {
      Object.assign(s, { shape: "ellipse", color: { background: COLORS.ctx, border: "#4c1d95" },
        font: { color: "#ffffff", size: 20, bold: true }, margin: 18, borderWidth: 3 });
      s.label = n.label + (n.holds_untrusted ? "\n[untrusted]" : "") + (n.holds_secret ? " [secret]" : "")
        + (n.future_sessions ? "\n(+ future sessions)" : "");
    }
    if (n.default) s.shapeProperties = Object.assign({}, s.shapeProperties, { borderDashes: [5, 4] });
    s.title = tooltip(n, ["key", "label", "id"]);
    s._base = { color: s.color, font: s.font };
    return s;
  }

  function edgeStyle(e) {
    const s = { id: e.id, from: e.source, to: e.target, arrows: "to", etype: e.etype, smooth: { type: "dynamic" } };
    if (e.etype === "refers") {
      Object.assign(s, { dashes: true, color: { color: COLORS.refers }, width: 1, label: e.binds || "",
        font: { size: 10, color: css("--muted"), strokeWidth: 0 } });
    } else if (e.etype === "defines") {
      Object.assign(s, { dashes: [2, 4], color: { color: COLORS.defines }, width: 1, arrows: "" });
    } else {
      const c = e.certainty === "deterministic" ? css("--det") : COLORS[e.certainty];
      Object.assign(s, { color: { color: c }, width: 2.2, dashes: e.certainty === "probabilistic" ? [8, 5] : false,
        label: [e.via, e.binds].filter(Boolean).join(" · "),
        font: { size: 10, color: css("--muted"), strokeWidth: 0, align: "middle" } });
    }
    s.title = tooltip(e, ["source", "target", "id", "key"]);
    s._base = { color: s.color, width: s.width };
    return s;
  }

  const nodes = new vis.DataSet(G.nodes.map(nodeStyle));
  const edges = new vis.DataSet(G.edges.map(edgeStyle));
  const container = document.getElementById("net");
  const network = new vis.Network(container, { nodes, edges }, {
    physics: { solver: "forceAtlas2Based", forceAtlas2Based: { gravitationalConstant: -80, springLength: 120 },
      stabilization: { iterations: 400 } },
    interaction: { hover: true, tooltipDelay: 120, navigationButtons: false },
    edges: { arrows: { to: { scaleFactor: 0.6 } } },
  });
  network.once("stabilizationIterationsDone", () => { network.setOptions({ physics: false }); network.fit(); });

  // ---------------------------------------------------------------- side panel
  document.getElementById("skill").textContent = G.graph.skill;
  document.getElementById("desc").textContent = G.graph.description;
  const ctx = G.nodes.find((n) => n.type === "AgentContext") || {};
  const badges = document.getElementById("badges");
  function badge(text, cls) { const b = document.createElement("span"); b.className = "badge " + (cls || ""); b.textContent = text; badges.appendChild(b); }
  badge(`${G.nodes.length} nodes / ${G.edges.length} edges`);
  badge(`${R.candidates.length} candidate path(s)`, R.candidates.length ? "bad" : "ok");
  if (ctx.holds_untrusted) badge("context: untrusted", "bad");
  if (ctx.holds_secret) badge("context: secret", "warn");
  if (R.confluence.length) badge("confluence", "bad");
  const AMB = R.ambient_secrets || [];
  if (AMB.length) badge("env secret reachable", "warn");
  badge(`trigger breadth ${G.graph.trigger_breadth}`);
  badge(`extractor: ${G.graph.extractor}`);

  const pathsEl = document.getElementById("paths");
  let active = null;
  function card(rec, head, chain, parent) {
    const d = document.createElement("div");
    d.className = "path";
    const h = document.createElement("div"); h.className = "head";
    if (rec.pattern) {
      const tag = document.createElement("span"); tag.className = "ptag"; tag.textContent = rec.pattern.id;
      tag.title = rec.pattern.name;
      h.append(tag);
    }
    h.append(document.createTextNode(head));
    d.append(h);
    if (rec.pattern) {
      const ps = document.createElement("div"); ps.className = "psum";
      ps.textContent = `${rec.pattern.name}: ${rec.pattern.summary}`;
      d.append(ps);
    }
    const c = document.createElement("div"); c.className = "chain"; c.textContent = chain;
    d.append(c);
    d.addEventListener("click", () => {
      if (active) active.classList.remove("active");
      d.classList.add("active"); active = d;
      highlight(rec.path, rec.kind === "confluence" || rec.kind === "ambient_secret");
      showDetails(rec);
    });
    parent.appendChild(d);
  }
  if (!R.candidates.length) pathsEl.innerHTML = '<div class="empty">No candidate paths.</div>';
  for (const p of R.candidates) {
    const s = p.shape;
    card(p, `${p.id}: ${s.source_trust === "secret" ? "[secret] " : ""}${s.source_category} → ${s.sink_category}`,
      `${s.probabilistic_edges} probabilistic edge(s)` + (s.cross_modal ? " · cross-modal" : "") +
      (s.code_involved ? " · code" : " · doc-only") + (s.uses_defaults ? " · uses default" : "") +
      "\n" + p.path_labels.join("  →  "), pathsEl);
  }
  const confEl = document.getElementById("conf");
  if (!R.confluence.length && !AMB.length) confEl.innerHTML = '<div class="empty">No secret + untrusted confluence.</div>';
  for (const c of R.confluence) {
    card(c, `${c.id}: secret + untrusted in context`,
      `outflows: ${c.outflows.map((o) => o.label).join(", ")}`, confEl);
  }
  for (const a of AMB) {
    card(a, `${a.id}: untrusted context + secret in environment`,
      `secrets: ${a.secret_labels.join(", ")}\nvia: ${a.capabilities.map((x) => x.label).join(", ")}`, confEl);
  }

  function patternBox(pid) {
    const P = R.pattern_catalog[pid];
    const box = document.createElement("div"); box.className = "pbox";
    const n = document.createElement("div"); n.className = "pname"; n.textContent = `${pid} · ${P.name}`;
    const e = document.createElement("div"); e.textContent = P.explanation;
    const r = document.createElement("div"); r.className = "prule"; r.textContent = `Graph rule: ${P.rule}`;
    box.append(n, e, r);
    return box;
  }
  function showDetails(obj) {
    const el = document.getElementById("details");
    el.classList.remove("empty");
    el.replaceChildren();
    if (obj && obj.pattern) el.append(patternBox(obj.pattern.id));
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(obj, null, 2);
    el.append(pre);
  }

  // ---------------------------------------------------------------- pattern catalog
  const counts = {};
  for (const r of [...R.candidates, ...R.confluence, ...AMB]) counts[r.pattern.id] = (counts[r.pattern.id] || 0) + 1;
  const patEl = document.getElementById("patterns");
  for (const [pid, P] of Object.entries(R.pattern_catalog)) {
    const det = document.createElement("details");
    if (counts[pid]) { det.className = "present"; }
    const sum = document.createElement("summary");
    const tag = document.createElement("span"); tag.className = "ptag"; tag.textContent = pid;
    const cnt = document.createElement("span"); cnt.className = "count";
    cnt.textContent = counts[pid] ? `  (${counts[pid]} in this skill)` : "";
    sum.append(tag, document.createTextNode(P.name), cnt);
    const p1 = document.createElement("p"); p1.textContent = P.explanation;
    const p2 = document.createElement("p"); p2.className = "prule"; p2.style.fontFamily = "ui-monospace, monospace";
    p2.textContent = `Graph rule: ${P.rule}`;
    det.append(sum, p1, p2);
    patEl.append(det);
  }
  network.on("click", (params) => {
    if (params.nodes.length) showDetails(byId[params.nodes[0]]);
    else if (params.edges.length) showDetails(G.edges.find((e) => e.id === params.edges[0]));
  });

  function highlight(path, star) {
    const onPath = new Set(path);
    const pathEdges = new Set();
    for (let i = 0; i < path.length - 1; i++) {
      const e = G.edges.find((x) => x.source === path[i] && x.target === path[i + 1] && x.etype === "flow");
      if (e) pathEdges.add(e.id);
    }
    if (star) {  // confluence: sources -> ctx -> outflows
      const ctxId = path.find((id) => byId[id].type === "AgentContext");
      for (const e of G.edges) if (e.etype === "flow" && (e.target === ctxId || e.source === ctxId) && onPath.has(e.source) && onPath.has(e.target)) pathEdges.add(e.id);
    }
    nodes.update(nodes.get().map((n) => ({ id: n.id, opacity: onPath.has(n.id) ? 1 : 0.15 })));
    edges.update(edges.get().map((e) => pathEdges.has(e.id)
      ? { id: e.id, width: 5, color: Object.assign({}, e._base.color, { opacity: 1 }), font: { color: css("--fg") } }
      : { id: e.id, width: e._base.width, color: Object.assign({}, e._base.color, { opacity: 0.1 }),
          font: { color: "rgba(128,128,128,0.12)" } }));
    network.fit({ nodes: path, animation: true });
  }
  function clear() {
    if (active) active.classList.remove("active");
    active = null;
    nodes.update(nodes.get().map((n) => ({ id: n.id, opacity: 1 })));
    edges.update(edges.get().map((e) => ({ id: e.id, width: e._base.width, color: Object.assign({}, e._base.color, { opacity: 1 }),
      font: { color: css("--muted") } })));
  }
  document.getElementById("clear").onclick = clear;
  document.getElementById("fit").onclick = () => network.fit({ animation: true });
  document.getElementById("physics").onchange = (ev) => network.setOptions({ physics: ev.target.checked });
  document.getElementById("showProv").onchange = (ev) => {
    edges.update(edges.get().filter((e) => e.etype !== "flow").map((e) => ({ id: e.id, hidden: !ev.target.checked })));
  };

  // ---------------------------------------------------------------- legend
  const L = [
    ["box:" + COLORS.code.background + ":" + COLORS.code.border, "Artifact (code)"],
    ["box:" + COLORS.doc.background + ":" + COLORS.doc.border, "Artifact (doc)"],
    ["dia:" + COLORS.untrusted, "Source untrusted"], ["dia:" + COLORS.secret, "Source secret"],
    ["dia:" + COLORS.trusted, "Source trusted"],
    ["hex:" + COLORS.sink, "Operator sink"], ["hex:" + COLORS.sanitizer, "Operator sanitizer"],
    ["hex:" + COLORS.neutral, "Operator neutral"], ["tri:" + COLORS.neutral, "Script input port"],
    ["ell:" + COLORS.ctx, "AgentContext"],
    ["line:det", "flow deterministic"], ["line:" + COLORS.extracted, "flow extracted"],
    ["dash:" + COLORS.probabilistic, "flow probabilistic"], ["dash:" + COLORS.refers, "refers"],
    ["dot:" + COLORS.defines, "defines"], ["dashbox", "default (assumed) node"],
  ];
  const legend = document.getElementById("legend");
  function swatch(spec) {
    const [kind, a, b] = spec.split(":");
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg"); svg.setAttribute("width", "20"); svg.setAttribute("height", "14");
    let el;
    const col = a === "det" ? css("--det") : a;
    if (kind === "box" || kind === "dashbox") { el = document.createElementNS(ns, "rect"); el.setAttribute("x", 2); el.setAttribute("y", 2); el.setAttribute("width", 16); el.setAttribute("height", 10);
      el.setAttribute("fill", kind === "box" ? a : "none"); el.setAttribute("stroke", kind === "box" ? b : css("--fg")); if (kind === "dashbox") el.setAttribute("stroke-dasharray", "3 2"); }
    else if (kind === "dia") { el = document.createElementNS(ns, "polygon"); el.setAttribute("points", "10,1 18,7 10,13 2,7"); el.setAttribute("fill", a); }
    else if (kind === "hex") { el = document.createElementNS(ns, "polygon"); el.setAttribute("points", "5,1 15,1 19,7 15,13 5,13 1,7"); el.setAttribute("fill", a); }
    else if (kind === "tri") { el = document.createElementNS(ns, "polygon"); el.setAttribute("points", "10,1 19,13 1,13"); el.setAttribute("fill", a); }
    else if (kind === "ell") { el = document.createElementNS(ns, "ellipse"); el.setAttribute("cx", 10); el.setAttribute("cy", 7); el.setAttribute("rx", 9); el.setAttribute("ry", 6); el.setAttribute("fill", a); }
    else { el = document.createElementNS(ns, "line"); el.setAttribute("x1", 1); el.setAttribute("y1", 7); el.setAttribute("x2", 19); el.setAttribute("y2", 7);
      el.setAttribute("stroke", col); el.setAttribute("stroke-width", 2); if (kind === "dash") el.setAttribute("stroke-dasharray", "4 3"); if (kind === "dot") el.setAttribute("stroke-dasharray", "1 3"); }
    svg.appendChild(el);
    return svg;
  }
  for (const [spec, text] of L) { const t = document.createElement("span"); t.textContent = text; legend.append(swatch(spec), t); }

  // ---------------------------------------------------------------- notes
  const notes = document.getElementById("notes");
  const items = [];
  for (const b of R.binding_errors || []) items.push(`binding error: ${b.script} <${b.slot}> (${b.reason})`);
  for (const r of R.rejected_records || []) items.push(`rejected record ${r.record.id}: ${r.reasons.join("; ")}`);
  for (const w of R.warnings || []) items.push(`warning: ${w}`);
  if (!items.length) notes.innerHTML = '<div class="empty">No binding errors, rejected records or warnings.</div>';
  for (const t of items) { const d = document.createElement("div"); d.textContent = "• " + t; notes.appendChild(d); }

  // ---------------------------------------------------------------- theme changes
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    nodes.update(G.nodes.map((n) => { const s = nodeStyle(n); return { id: s.id, font: s.font }; }));
    edges.update(G.edges.map((e) => { const s = edgeStyle(e); return { id: s.id, color: s.color, font: s.font }; }));
  });
})();
</script>
</body>
</html>
"""
