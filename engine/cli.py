"""Typer CLI: ``cloudpath analyze`` / ``cloudpath audit``.

Runs offline with ``--mock`` by default (no AWS SDK required). Switches to a
real JSON dump when ``--account-file`` is supplied.
"""

from __future__ import annotations

import json

import typer

from engine.config import AccountSnapshot, PolicyDocument
from engine.mock_data import build_mock_account
from engine.reporters import audit_markdown, render_ansi, render_json, render_markdown

app = typer.Typer(help="AWS IAM attack-path lab (offline, deterministic).")


def _load_account(account_file: str | None) -> tuple[AccountSnapshot, str]:
    if account_file:
        with open(account_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return AccountSnapshot.model_validate(data), "file"
    return build_mock_account(), "mock"


@app.command()
def analyze(
    account_file: str | None = typer.Option(
        None, "--account-file", "-f", help="JSON account dump."
    ),
    mock: bool = typer.Option(
        True, "--mock", help="Use the deterministic built-in account (default)."
    ),
    output: str = typer.Option("ansi", "--output", help="ansi | json | markdown"),
    graph: bool = typer.Option(
        False, "--graph", help="Include attack-path graph (json/markdown)."
    ),
) -> None:
    if account_file is not None:
        account, source = _load_account(account_file)
    elif mock:
        account, source = _load_account(None)
    else:
        raise typer.BadParameter("provide --account-file or enable --mock")
    from engine.analyzer import analyze_account
    from engine.graph import build_graph

    findings, _attack_graph = analyze_account(account)
    graph_obj = build_graph(account, findings) if graph else None

    if output == "json":
        print(render_json(findings, graph_obj))
    elif output == "markdown":
        print(render_markdown(findings, graph_obj))
    else:
        render_ansi(findings, graph_obj)
        typer.echo(
            f"\n[dim]Analyzed {source} account {account.account_id} ({account.account_name})[/dim]"
        )


@app.command()
def audit(
    policy_file: str = typer.Argument(..., help="JSON policy document to audit."),
    output: str = typer.Option("ansi", "--output", help="ansi | json | markdown"),
) -> None:
    with open(policy_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    doc = PolicyDocument.model_validate(data)
    from engine.analyzer import audit_policy_document

    issues = audit_policy_document(policy_file, doc)
    if output == "markdown":
        print(audit_markdown(issues))
    elif output == "json":
        print(json.dumps([i.model_dump() for i in issues], indent=2))
    else:
        for issue in issues:
            level = "WARN" if issue.level == "warning" else "CRIT"
            typer.echo(f"[{level}] {issue.policy_name}: {issue.issue}")


def run_cli(args: list[str] | None = None) -> None:
    app(args)


if __name__ == "__main__":
    run_cli()
