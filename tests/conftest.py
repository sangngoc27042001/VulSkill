from pathlib import Path

import pytest

from skill2graph.build import build_graph
from skill2graph.query import run_queries

SAMPLES = Path(__file__).resolve().parent.parent / "sample_skills"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Tests must never reach the network or the LLM backend."""
    for var in ("QLAY_AI_FOUNDERY", "QLAY_AI_FOUNDERY_API_KEY", "QLAY_AI_DEPLOYMENT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SKILL2GRAPH_NO_DOTENV", "1")

    def guard(*a, **k):
        raise RuntimeError("network access is disabled in tests")

    import socket

    monkeypatch.setattr(socket.socket, "connect", guard)


@pytest.fixture(scope="session")
def analyzed():
    cache = {}

    def get(name):
        if name not in cache:
            G = build_graph(SAMPLES / name)
            cache[name] = (G, run_queries(G))
        return cache[name]

    return get
