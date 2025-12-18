"""Report rendering: JSON, Markdown, and ANSI/rich output for scan results."""

from __future__ import annotations

import json
from typing import Any, TextIO

from rich.console import Console
from rich.table import Table

from engine.config import (
    AttackGraph,
    AuditIssue,
    EscalationFinding,
    MitreRow,
)
from engine.graph import shortest_admin_paths


def _finding_to_dict(f: EscalationFinding) -> dict[str, Any]:
    return {
        "vector": f.vector,
        "mitre_id": f.mitre_id,
        "severity": f.severity,
        "actor": f.actor,
        "target": f.target,
        "path": f.path,
        "description": f.description,
    }


def render_json(
    findings: list[EscalationFinding], graph: AttackGraph | None = None
) -> str:
    payload: dict[str, Any] = {
        "findings": [_finding_to_dict(f) for f in findings],
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
        },
    }
    if graph is not None:
        payload["graph"] = {
            "nodes": [n.model_dump() for n in graph.nodes],
            "edges": [e.model_dump() for e in graph.edges],
            "shortest_admin_paths": shortest_admin_paths(graph),
        }
    return json.dumps(payload, indent=2)


def render_markdown(
    findings: list[EscalationFinding], graph: AttackGraph | None = None
) -> str:
    lines: list[str] = ["# IAM Attack Path Analysis", ""]
    lines.append(f"**Findings:** {len(findings)}")
    lines.append(
        f"**Critical:** {sum(1 for f in findings if f.severity == 'critical')}  **High:** {sum(1 for f in findings if f.severity == 'high')}"
    )
    lines.append("")
    lines.append("| Severity | Technique | Actor | Target | MITRE |")
    lines.append("|---|---|---|---|---|")
    for f in findings:
        actor = f.actor.split("/")[-1]
        target = f.target.split("/")[-1]
        lines.append(
            f"| {f.severity} | {f.vector} | `{actor}` | `{target}` | {f.mitre_id} |"
        )
    if graph is not None:
        paths = shortest_admin_paths(graph)
        if paths:
            lines.append("")
            lines.append("## Shortest paths to ADMIN")
            for p in paths:
                lines.append(f"- `{' -> '.join(p)}`")
    return "\n".join(lines) + "\n"


def render_ansi(
    findings: list[EscalationFinding],
    graph: AttackGraph | None = None,
    stream: TextIO | None = None,
) -> None:
    console = Console(file=stream)
    table = Table(title="IAM Attack Path Analysis")
    table.add_column("Severity", style="bold")
    table.add_column("Technique")
    table.add_column("Actor", style="cyan")
    table.add_column("Target", style="magenta")
    table.add_column("MITRE", style="dim")
    for f in findings:
        sev = f.severity.upper()
        style = "red" if f.severity == "critical" else "yellow"
        table.add_row(f"[{style}]{sev}[/]", f.vector, f.actor, f.target, f.mitre_id)
    console.print(table)
    if graph is not None:
        paths = shortest_admin_paths(graph)
        for path in paths:
            console.print(
                "    ".join(f"[bold]({node})[/]" for node in path)
            ) if paths else None


def audit_markdown(issues: list[AuditIssue]) -> str:
    lines: list[str] = ["# IAM Policy Audit", ""]
    lines.append(
        f"**Warnings:** {sum(1 for i in issues if i.level == 'warning')}  **Critical:** {sum(1 for i in issues if i.level == 'critical')}"
    )
    lines.append("")
    lines.append("| Level | Policy | Issue |")
    lines.append("|---|---|---|")
    for i in issues:
        lines.append(f"| {i.level} | `{i.policy_name}` | {i.issue} |")
    return "\n".join(lines) + "\n"


def mitre_rows() -> list[MitreRow]:
    """MITRE ATT&CK Cloud mapping surface for the report header."""
    return [
        MitreRow(
            technique_id="T1548.004",
            technique_name="Abuse Elevation Control Mechanism: Elevated Security Assignments (IAM)",
            tactic="Privilege Escalation",
            vectors=[
                "Attach/Put policy",
                "CreatePolicyVersion",
                "AddUserToGroup",
                "UpdateAssumeRolePolicy",
                "PassRole",
            ],
        ),
        MitreRow(
            technique_id="T1078.004",
            technique_name="Valid Accounts: Cloud Accounts",
            tactic="Initial Access / Defense Evasion",
            vectors=[
                "sts:AssumeRole chain",
                "iam:CreateAccessKey",
                "iam:UpdateLoginProfile",
            ],
        ),
        MitreRow(
            technique_id="T1530",
            technique_name="Data from Cloud Storage",
            tactic="Collection",
            vectors=["Public S3 GetObject/ListBucket"],
        ),
        MitreRow(
            technique_id="T1552.005",
            technique_name="Unsecured Credentials: Cloud Instance Metadata API",
            tactic="Credential Access",
            vectors=["Secrets Manager public GetSecretValue", "KMS public Decrypt"],
        ),
    ]
