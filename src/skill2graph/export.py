"""Serialize graphs: node-link JSON, GraphML, and path records."""

from __future__ import annotations

import json
from pathlib import Path

import networkx as nx


def to_node_link(G: nx.MultiDiGraph) -> dict:
    data = nx.node_link_data(G, edges="edges")
    # stable order: n1, n2, ... and edges in insertion order
    data["nodes"].sort(key=lambda n: int(n["id"][1:]))
    for i, e in enumerate(data["edges"], 1):
        e["id"] = f"e{i}"
    return data


def write_json(G: nx.MultiDiGraph, path: str | Path) -> None:
    Path(path).write_text(json.dumps(to_node_link(G), indent=2, default=str), encoding="utf-8")


def _scalarize(attrs: dict) -> dict:
    out = {}
    for k, v in attrs.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        else:
            out[k] = json.dumps(v, default=str)
    return out


def write_graphml(G: nx.MultiDiGraph, path: str | Path) -> None:
    H = nx.MultiDiGraph()
    H.graph.update(_scalarize(G.graph))
    for n, d in G.nodes(data=True):
        H.add_node(n, **_scalarize(d))
    for u, v, k, d in G.edges(keys=True, data=True):
        H.add_edge(u, v, key=k, **_scalarize(d))
    nx.write_graphml(H, str(path))


def write_paths(result: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
