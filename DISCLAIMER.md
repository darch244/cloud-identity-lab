# SIMULATION & TESTING LAB ONLY — READ BEFORE RUNNING ANYTHING

**cloud-identity-lab** is an **authorized attack-path simulation and detection
engineering sandbox**. It exists to demonstrate how over-permissive AWS IAM
configurations translate into exploitable privilege-escalation chains, and to
train defenders on the CloudTrail/EventBridge telemetry that exposes them.

## 1. Authorization Required

- Deploying the Terraform scenarios or running the engine against a **live AWS
  account** is only permitted when you have **explicit written authorization**
  from the account owner(s). This includes your own account (best practice:
  an isolated, throwaway account used *solely* for this lab).
- The `engine` is fully functional in **offline/mock mode** (`--mock`) and
  requires no cloud access or credentials. Use that mode for learning and CI.
- `--account-file` mode expects a dump of *your own* IAM inventory that you are
  authorized to analyze. Do not point it at IAM data you do not own.

## 2. What This Repo Simulates

| Scenario | Simulated misconfiguration | Malicious-actor step |
|---|---|---|
| `01_passrole_lambda` | `iam:PassRole` scoped to an `AdministratorAccess` role + `lambda:CreateFunction` | Weaponize a role via a malicious Lambda |
| `02_assumerole_chain` | Trust chain `dev-user → research-role → ci-deploy-role(Admin)` | Multi-hop AssumeRole hopping to admin |
| `03_s3_exfil` | Public bucket policy + public KMS decrypt + public Secrets Manager | Data exfiltration / credential theft |

All three are **realistic but intentionally broken**; they mirror publicly
documented breach primitives. Do not apply them to production accounts.

## 3. Data, Credentials, And Secrets

- The engine contains **fabricated** synthetic IAM dumps (mock data). No real
  account IDs, access keys, or secrets are embedded. All ARNs use the fictional
  account id `123456789012`.
- The Terraform `secretsmanager_secret` in scenario 03 seeds a placeholder
  secret value; replace/remove it if you deploy. Defaulted to a clearly fake
  test value.
- Collateral contacts: treating this lab as "free real estate" inside a
  corporate account, or running it against targets you do not own, is exactly
  the kind of activity that ends authorizations. **Stay in an isolated lab
  account or offline.**

## 4. Ethical Use Policy

By using this repository you agree:

1. You have the legal right to test any environment you apply it to.
2. You will not use it to attack production identities without authorization.
3. You will not exfiltrate/destroy real data.
4. You will clean up any deployed lab resources (`terraform destroy`) when done.
5. You remain solely responsible for the consequences of your choices.

The author (Mostafa Ibrahim, DarcHacker) provides this for educational and
authorized red-team use. Use responsibly.