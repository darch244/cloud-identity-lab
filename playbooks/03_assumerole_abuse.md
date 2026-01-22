# Playbook 03 — AssumeRole Chain Abuse (`dev-user` → `ci-deploy-role` admin)

**Scenario Terraform:** [`terraform/scenarios/02_assumerole_chain.tf`](../terraform/scenarios/02_assumerole_chain.tf)

**Engine vector:** `sts:AssumeRole chain -> privileged role` (MITRE `T1078.004`)

## Root cause

`research-role` trusts `dev-user` (and `app-svc-user`), and `ci-deploy-role`
trusts `research-role`. `ci-deploy-role` also holds `AdministratorAccess`. The
chain itself is a legitimate pattern on paper, but the *first hop* is a
feather-touch contract: any holder of a `research-role` credential — or anyone
able to compromise `dev-user` — wins the whole stack via two unremarkable
`sts:AssumeRole` calls.

Additionally, `dev-user`'s trust edge (a permission edge in the graph) means
a bare `dev-user` KMS/S3 object read leak converts directly into admin.

## PoC (offline — graph shortest-path already shows the route)

```bash
.venv/bin/cloudpath analyze --mock --output markdown --graph
# Shortest paths to ADMIN includes:
# arn:aws:iam::123456789012:user/dev-user ->
#   role/research-role -> role/ci-deploy-role -> ADMIN
```

## Live walkthrough (LocalStack or sandbox AWS)

1. As `dev-user`, obtain a token for `research-role`:
   ```bash
   export AWS_PROFILE=dev
   aws sts assume-role --role-arn arn:aws:iam::<acct>:role/research-role \
     --role-session-name dev-investigator
   # returns AccessKeyId / SecretAccessKey / SessionToken
   ```
2. With those credentials, hop to `ci-deploy-role`:
   ```bash
   export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
   aws sts assume-role --role-arn arn:aws:iam::<acct>:role/ci-deploy-role \
     --role-session-name chain-to-admin
   ```
3. Confirm:
   ```bash
   aws sts get-caller-identity   # Arn: ...:role/ci-deploy-role
   aws iam list-attached-role-policies --role-name ci-deploy-role
   # AdministratorAccess is attached
   ```

## Why the chain is worse than a single trust hop

- Each hop is individually low-risk-looking (trust a *service account*
  role), so reviewers approve them in turn.
- The graph engine flags the **entire path** — not just each edge — which is
  what a human review tends to miss.

## Detection

- CloudTrail `sts:AssumeRole` events where source identity is a user and
  target is a privileged role the source could never use directly.
- Alert on `sts:AssumeRole` followed within seconds by another
  `sts:AssumeRole` (chain pattern).
- `GetCallerIdentity` immediately after a chain (credential validation).
- Sigma rule: see `detections/sigma_rules.yaml` (role-chain).

## Remediation

- Reduce trust: `research-role` should trust a *role*, not individual users.
- Shorten chains: use a Roles-anywhere/break-glass path instead.
- Apply a `permissions_boundary` on `ci-deploy-role` so even assumption can't
  mutate IAM.
- Require MFA + ConfusedDeputy protection serial numbers in trust policies.