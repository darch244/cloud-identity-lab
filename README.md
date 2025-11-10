# cloud-identity-lab

> **Enterprise AWS identity attack-path sandbox** — automated Terraform IaC
> scenarios, a custom Python graph-based IAM permission analyzer, privilege
> escalation chains, CloudTrail telemetry, and production Sigma detection rules.

## Focus

- Over-permissive IAM roles
- `AssumeRole` hijacking
- PassRole escalation via Lambda / EC2
- S3 / Secrets Manager exfiltration
- CloudTrail logging and alerting
- Defensive Sigma / EventBridge rules

## Author

**Mostafa Ibrahim** (`DarcHacker`) — September 2025

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Fully offline — zero AWS credentials needed
.venv/bin/cloudpath analyze --mock --output ansi
```

## Engine commands

| Command | Purpose |
|---|---|
| `cloudpath analyze --mock --output markdown --graph` | Full scan of the deterministic mock account; shortest paths to ADMIN included |
| `cloudpath analyze --account-file acct.json --output json` | Analyze a real JSON account dump |
| `cloudpath audit policy.json` | Static policy-document linter |

## Repository layout

```
.
├── terraform/
│   ├── main.tf                          # Provider config + KMS / Secrets
│   ├── variables.tf                     # All tunables (region, LocalStack endpoint)
│   ├── outputs.tf                       # ARN / name exports for reuse
│   ├── terraform.tfvars.example         # Copy-and-edit defaults
│   └── scenarios/
│       ├── 01_passrole_lambda.tf        # PassRole → Lambda admin role
│       ├── 02_assumerole_chain.tf       # dev-user → research → ci-deploy (admin)
│       └── 03_s3_exfil.tf              # Public bucket + KMS + Secrets
├── playbooks/
│   ├── 01_iam_recon_and_enum.md
│   ├── 02_passrole_escalation.md
│   ├── 03_assumerole_abuse.md
│   └── 04_data_exfiltration.md
├── engine/
│   ├── __init__.py
│   ├── cli.py                           # Typer / Rich CLI
│   ├── config.py                        # Pydantic v2 schemas
│   ├── analyzer.py                      # 15+ IAM escalation vector detection
│   ├── graph.py                         # NetworkX attack-path graph
│   ├── reporters.py                     # JSON / Markdown / ANSI renderers
│   └── mock_data.py                     # Deterministic offline account (123456789012)
├── detections/
│   ├── sigma_rules.yaml                 # Lab-tuned Sigma rules (PassRole / Chain / Exfil)
│   └── remediation_guide.md
├── tests/
│   ├── conftest.py
│   ├── test_analyzer.py
│   ├── test_graph.py
│   └── test_cli.py
├── .github/workflows/ci.yml
├── requirements.txt
├── Makefile
├── LICENSE                              # MIT — Copyright 2026 Mostafa Ibrahim
├── DISCLAIMER.md                        # Authorized research use only
└── README.md
```

## Offline mode

```bash
.venv/bin/cloudpath analyze --mock --output markdown --graph
```

The `--mock` flag loads `engine.mock_data.build_mock_account()` — a fully
deterministic, zero-network account snapshot that always produces the same
findings.

## CI gates

```bash
make ci
```

Checks: `ruff check engine tests`, `ruff format --check`, `mypy engine`,
`pytest -q`, `cloudpath analyze --mock`, and `terraform fmt -check -recursive`.

## License

MIT — Copyright 2026 Mostafa Ibrahim