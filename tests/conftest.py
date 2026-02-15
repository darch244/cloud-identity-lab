"""Shared pytest fixtures for the engine and CLI tests."""

from __future__ import annotations

import pytest

from engine.config import AccountSnapshot
from engine.mock_data import build_mock_account


@pytest.fixture(scope="session")
def mock_account() -> AccountSnapshot:
    """Deterministic vulnerable account used across all test modules."""
    return build_mock_account()


@pytest.fixture(scope="session")
def mock_findings(mock_account: AccountSnapshot):
    """Precomputed analyzer output for the mock account."""
    from engine.analyzer import analyze_account

    findings, _graph = analyze_account(mock_account)
    return findings


@pytest.fixture(scope="session")
def mock_graph(mock_account: AccountSnapshot):
    from engine.analyzer import analyze_account

    _findings, graph = analyze_account(mock_account)
    return graph
