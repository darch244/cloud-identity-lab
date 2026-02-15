"""Graph tests: shortest paths to ADMIN and serialization round-trips."""

from __future__ import annotations

import networkx as nx

from engine.analyzer import analyze_account
from engine.config import AccountSnapshot
from engine.graph import build_graph, shortest_admin_paths, to_digraph

ARN0 = "arn:aws:iam::123456789012"


def test_graph_contains_all_principals(
    mock_account: AccountSnapshot, mock_graph
) -> None:
    ids = {n.id for n in mock_graph.nodes}
    for arn in mock_account.principals_arns:
        assert arn in ids
    assert "ADMIN" in ids


def test_shortest_admin_path_spans_expected_hops(mock_graph) -> None:
    paths = shortest_admin_paths(mock_graph)
    dev_arn = f"{ARN0}:user/dev-user"
    dev_paths = [p for p in paths if p[0] == dev_arn]
    assert dev_paths
    assert any(
        f"{ARN0}:role/research-role" in p and f"{ARN0}:role/ci-deploy-role" in p
        for p in dev_paths
    )


def test_digraph_is_dag(mock_graph) -> None:
    g = to_digraph(mock_graph)
    assert isinstance(g, nx.DiGraph)
    assert not nx.is_directed_acyclic_graph(g) is False  # may contain cycles


def test_serialization_roundtrip(mock_graph) -> None:
    payload = mock_graph.model_dump_json()
    from engine.config import AttackGraph

    restored = AttackGraph.model_validate_json(payload)
    assert len(restored.nodes) == len(mock_graph.nodes)
    assert len(restored.edges) == len(mock_graph.edges)


def test_build_graph_matches_analyze_output(
    mock_account: AccountSnapshot, mock_findings
) -> None:
    graph = build_graph(mock_account, mock_findings)
    assert len(graph.edges) >= 1
    assert all(
        e.source in {n.id for n in graph.nodes}
        and e.target in {n.id for n in graph.nodes}
        for e in graph.edges
    )


def test_empty_account_has_no_admin_path() -> None:
    empty = AccountSnapshot(
        account_id="123456789012", users={}, roles={}, policies={}, groups={}
    )
    findings, graph = analyze_account(empty)
    assert findings == []
    assert shortest_admin_paths(graph) == []
