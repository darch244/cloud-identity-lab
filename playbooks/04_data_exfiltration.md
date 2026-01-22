# Playbook 04 — Data Exfiltration (public S3 / KMS / Secrets Manager)

**Scenario Terraform:** [`terraform/scenarios/03_s3_exfil.tf`](../terraform/scenarios/03_s3_exfil.tf) + KMS key / secret in [`terraform/main.tf`](../terraform/main.tf)

**Engine vectors:** `S3 bucket public read`, `KMS key public decrypt`, `Secrets Manager secret public read`
(MITRE `T1530`, `T1552.005`)

## Root cause

Three resources all allow `Principal: "*"`:

| Resource | Policy allows | Data exposed |
|---|---|---|
| `analytics-data` bucket | `s3:GetObject`, `s3:ListBucket` (any principal) | `reports/Q3-summary.csv` + anything later uploaded |
| KMS key `alias/analytics` | `kms:Decrypt` (any principal) | ciphertext stored in the bucket |
| Secrets Manager `prod/api-key` | `secretsmanager:GetSecretValue` (any principal) | live API key |

## PoC (offline — deterministic finding)

```bash
.venv/bin/cloudpath analyze --mock --output markdown
# high | S3 bucket public read          | analytics-data
# high | KMS key public decrypt        | analytics
# high | Secrets Manager secret public read | prod/api-key
```

## Live walkthrough (LocalStack or a sandbox account)

1. Unauthenticated S3 read — note this requires *no* credentials beyond a
   valid AWS session (any IAM principal):
   ```bash
   aws s3 ls s3://analytics-data --no-sign-request
   aws s3 cp s3://analytics-data/reports/Q3-summary.csv . --no-sign-request
   ```
2. Decrypt a file stored under `analytics-data` encrypted with the KMS key:
   ```bash
   aws kms decrypt \
     --key-id alias/analytics \
     --ciphertext-blob fileb://<cipher>.enc    # printed via kms:encrypt earlier
   ```
3. Exfiltrate the API key as any principal (including the unauth session):
   ```bash
   aws secretsmanager get-secret-value --secret-id prod/api-key --no-sign-request
   ```

The first two steps form an exfiltration chain alone; step 3 turns data theft
into credential theft that can then reach the IAM attack paths in playbooks
02/03.

## Defense-in-depth note (what the engine cannot recover)

The engine reports the *permission* problem. Whether the data is actually
sensitive depends on object encryption + access logging + bucket policy
history — enable `s3:PutObject` versioning and `aws:s3:server-side-encryption`
conditions to make the leak recoverable in forensics.

## Detection

- CloudTrail `s3:GetObject` / `s3:ListBucket` with a resource ARN containing
  a bucket whose policy allows `"Principal": {"AWS": "*"}`.
- `secretsmanager:GetSecretValue` with `userIdentity.arn` = `root` or a
  non-privileged identity, on a secret named like `prod/*`.
- `kms:Decrypt` with no prior `kms:Encrypt` in the same session profile
  (retro decrypt = theft signature).
- Sigma: `detections/sigma_rules.yaml` (public-secret).

## Remediation

- Grant bucket/secret/KMS access to specific roles (or account-constrained
  `AWS` principals), never `*`.
- Store secrets behind `secretsmanager:GetSecretValue` for a narrow set of
  service-linked roles; rotate on exposure.
- Block `kms:Decrypt` for any principal not linked to a decrypt-needing
  workload; log decrypt events.
- Apply bucket `aws:PrincipalArn` conditions and object versioning.