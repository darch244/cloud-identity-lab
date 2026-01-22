# Playbook 01 — IAM Reconnaissance & Enumeration

**Goal:** map the blast radius of an IAM identity before firing a single
privilege-escalation primitive. Every escalation in this lab starts with a
silent recon pass.

## Prerequisites

- Python 3.11+ venv from the repo root ready:
  ```bash
  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
  ```
- If auditing real infrastructure: `aws` CLI with ReadOnly credentials
- If offline: the built-in mock account (no AWS account needed)

## 1. Inventory the account

Get the full identity picture. If you have AWS access, enumerate the obvious
high-value tags first, then dump everything the analyzer can consume.

```bash
# Live (ReadOnly):
aws iam list-users --output json > account.json
aws iam list-roles --output json >> account.json
aws iam list-policies --output json >> account.json
aws iam list-groups --output json >> account.json
# Resource policies (S3/KMS/Secrets — separate read paths):
aws s3api get-bucket-policy --bucket analytics-data
aws kms get-key-policy --key-id alias/analytics
aws secretsmanager get-secret-value --secret-id prod/api-key
```

The analyzer accepts a JSON account dump with `--account-file`. Convert the
CLI output into the `AccountSnapshot` schema (see `engine/config.py`).

## 2. Offline baseline with the mock

Run the deterministic mock first so you learn what the analyzer calls a
"finding" before touching anything real:

```bash
.venv/bin/cloudpath analyze --mock --output markdown --graph
```

Every vector the engine reports has an entry in `playbooks/02`, `03`, and
`04` with the exact TTP.

## 3. Enumerate your own (the attacker user) effective permissions

The most important recon question: **what can a compromise of this identity
actually do?** For the mock this is `dev-user`, `app-svc-user`, or any
non-admin user.

```bash
.venv/bin/cloudpath analyze --mock --output json | jq '.findings[].actor' | sort -u
```

Any actor that appears is a fishing rod with a hook on the end — its
escalation paths are the appetizer for playbooks 02–04.

## 4. Map trust relationships

Attach a trust policy list to every role. In the mock, roles are described in
`terraform/scenarios/02_assumerole_chain.tf`:

```bash
aws iam get-role --role-name research-role --query 'Role.AssumeRolePolicyDocument'
aws iam get-role --role-name ci-deploy-role --query 'Role.AssumeRolePolicyDocument'
aws iam get-role --role-name lambda-exec-role --query 'Role.AssumeRolePolicyDocument'
```

Trust statements are how the analyzer stops the BFS — a role is only
"assumable" when the trust policy admits you AND your identity policy allows
`sts:AssumeRole`.

## 5. Recon checklist / output artifacts

| Artifact                  | Command (offline equivalent)            |
|---------------------------|---|
| Full identity list        | `cloudpath analyze --mock --output json` |
| Effective-perm summary    | `awk '{print $1}'` on markdown output   |
| Trust map                 | `terraform/scenarios/*.tf` + playbook 02 |
| Public data plane         | playbook 04                              |

## 6. Where to go next

- `playbooks/02_passrole_escalation.md` — `app-svc-user` → `lambda-exec-role`
- `playbooks/03_assumerole_abuse.md` — `dev-user` → `research-role` → `ci-deploy-role`
- `playbooks/04_data_exfiltration.md` — S3 / KMS / Secrets Manager public reads