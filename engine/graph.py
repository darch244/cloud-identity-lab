"""NetworkX attack-path graph built from analyzer findings.

Nodes are principals/resources; edges are the escalation or data-flow steps
discovered by :mod:`engine.analyzer`. Shortest paths to the synthetic
``ADMIN`` node are surfaced for the CLI ``--graph`` output and the tests.
"""

from __future__ import annotations

from typing import Any

from engine.analyzer import IamAnalyzer
from engine.config import AccountSnapshot, AttackGraph, EscalationFinding


def build_graph(
    account: AccountSnapshot, findings: list[EscalationFinding]
) -> AttackGraph:
    """Derive the serializable :class:`AttackGraph` from scan findings."""
    analyzer = IamAnalyzer(account)
    return analyzer._build_graph(findings)


def to_digraph(graph: AttackGraph) -> Any:
    """Convert an :class:`AttackGraph` into a NetworkX ``networkx.DiGraph``."""
    import networkx as nx

    g: nx.DiGraph = nx.DiGraph()
    for node in graph.nodes:
        g.add_node(
            node.id,
            name=node.name,
            kind=node.kind,
            is_admin=node.is_admin,
            arn=node.arn,
        )
    for edge in graph.edges:
        g.add_edge(
            edge.source, edge.target, relationship=edge.relationship, detail=edge.detail
        )
    return g


def shortest_admin_paths(graph: AttackGraph) -> list[list[str]]:
    """Every shortest path from an origin node to the ``ADMIN`` node."""
    import networkx as nx

    g = to_digraph(graph)
    paths: list[list[str]] = []
    if "ADMIN" not in g:
        return paths
    for source in g.nodes:
        if source == "ADMIN":
            continue
        try:
            path = nx.shortest_path(g, source, "ADMIN")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        if path not in paths:
            paths.append(path)
    return paths


def summarize_paths(account: AccountSnapshot, graph: AttackGraph) -> list[str]:
    """Human-readable one-liners for each attack path to ADMIN."""
    out: list[str] = []
    for path in shortest_admin_paths(graph):
        rendered = []
        for node_id in path:
            if node_id == "ADMIN":
                rendered.append("ADMIN")
                continue
            name = node_id.split(":")[-1].split("/")[-1]
            rendered.append(name)
        out.append(" -> ".join(rendered))
    return out
