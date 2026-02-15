"""CLI tests: ``cloudpath analyze`` and ``cloudpath audit`` via Typer runner."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from engine.cli import app

runner = CliRunner()


def test_analyze_mock_ansi() -> None:
    result = runner.invoke(app, ["analyze"])
    assert result.exit_code == 0, result.output
    assert "IAM Attack Path Analysis" in result.output
    assert "PassRole" in result.output or "sts:AssumeRole" in result.output


def test_analyze_mock_json() -> None:
    result = runner.invoke(app, ["analyze", "--output", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["total"] > 0
    assert payload["summary"]["critical"] > 0


def test_analyze_mock_markdown_includes_shortest_paths() -> None:
    result = runner.invoke(app, ["analyze", "--output", "markdown", "--graph"])
    assert result.exit_code == 0, result.output
    assert "# IAM Attack Path Analysis" in result.output
    assert "Shortest paths to ADMIN" in result.output
    assert "dev-user" in result.output


def test_audit_requires_policy_file() -> None:
    result = runner.invoke(app, ["audit"])
    assert result.exit_code != 0


def test_audit_policy_flags_admin(tmp_path) -> None:
    policy_file = tmp_path / "admin.json"
    policy_file.write_text(
        json.dumps(
            {
                "version": "2012-10-17",
                "statement": [{"effect": "Allow", "action": ["*"], "resource": ["*"]}],
            }
        )
    )
    result = runner.invoke(app, ["audit", str(policy_file), "--output", "json"])
    assert result.exit_code == 0, result.output
    issues = json.loads(result.output)
    assert any("full admin" in i["issue"] for i in issues)
