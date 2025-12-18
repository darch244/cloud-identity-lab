"""Offline AWS IAM attack-path analysis engine.

Exposes the deterministic mock account, the analyzer, graph construction, and
the CLI entry point.
"""

from __future__ import annotations

from engine.analyzer import IamAnalyzer, analyze_account
from engine.config import AccountSnapshot
from engine.graph import build_graph, shortest_admin_paths
from engine.mock_data import build_mock_account
from engine.reporters import render_ansi, render_json, render_markdown

__all__ = [
    "AccountSnapshot",
    "IamAnalyzer",
    "analyze_account",
    "build_graph",
    "build_mock_account",
    "render_ansi",
    "render_json",
    "render_markdown",
    "shortest_admin_paths",
]
