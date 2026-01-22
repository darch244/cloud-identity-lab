# Remediation Guide — cloud-identity-lab

Corresponds to every vector the engine detects. Use this as a reference when
writing the mitigating controls after walking through playbooks 02–04.

---

## PassRole + Lambda compute (playbook 02)

| Risk | `iam:PassRole` on `*` + `lambda:CreateFunction` lets an attacker create
  a function that executes as any privileged role. |

**Mitigations**

- Scope `iam:PassRole` to a finite list of role ARNs — never `*`.
- Remove the `lambda:CreateFunction` permission from `app-svc-user` if the
  user does not create functions (only `lambda:InvokeFunction` is needed for
  existing workloads).
- Apply a permissions boundary on `app-svc-user` that denies `lambda:*`
  write actions.
- Monitor CloudTrail for `lambda:CreateFunction` events where
  `requestParameters.roleArn` differs from the caller's ARN.

---

## AssumeRole chain (playbook 03)

| Risk | `dev-user` → `research-role` → `ci-deploy-role` (admin) via two hops.
  First hop is the only real trust boundary; second hop is invisible to a
  reviewer who only checks the policy attached to `dev-user`. |

**Mitigations**

- Replace user-to-role trust with role-to-role trust:
  `research-role` trust policy should reference `dev-*` *roles* instead of
  user ARNs directly, which forces workload identity control.
- Shorten the chain to at most one hop wherever possible.
- Use an explicit `aws:PrincipalTag` or session condition in each trust
  policy so assumption is only allowed for specific workload types.
- Add a `permissions_boundary` to `ci-deploy-role` so even an assumed
  identity cannot attach `AdministratorAccess` to other resources.
- Require `sts:ExternalId` for any role-to-role trust to block confused-deputy.
- Rotate role trust statements quarterly and audit cross-role chains with the
  engine graph output.

---

## Data exfiltration — public resources (playbook 04)

| Risk | S3 bucket, KMS key, and Secrets Manager secret all allow `Principal:
  "*"`. An unauthenticated attacker with a valid AWS session can read all. |

**S3 bucket (`analytics-data`)**

- Replace `Principal: AWS: ["*"]` with an explicit list of allowed role
  ARNs or an SCP-gated account condition.
- Enable S3 server-side encryption with `aws:kms` so bucket contents cannot
  be read without KMS permissions.
- Enable bucket access logging and alert on `s3:GetObject` calls originating
  from outside the owning account.

**KMS key (`alias/analytics`)**

- Replace the `kms:Decrypt` wildcard principal with a narrow set of role
  ARNs.
- Enable key rotation (`enable_key_rotation = true`).
- Log all `kms:Decrypt` / `kms:Encrypt` events via CloudTrail and monitor
  for calls outside normal operating profiles.

**Secrets Manager (`prod/api-key`)**

- Remove the `Principal: AWS: ["*"]` block entirely; use resource-based
  policies only for cross-account access that is explicitly authorized.
- Rotate the exposed key immediately (`aws secretsmanager rotate-secret`).
- Store the rotation function identity in a secrets policy so only the
  service needing the key can call `GetSecretValue`.

---

## Cross-cutting controls

| Control | Applies to |
|---|---|
| **Permissions boundaries** | All non-root identities — caps the blast radius |
| **SCPs on `sts:AssumeRole`** | Prevent cross-account assumption chains |
| **CloudTrail alerts** | PassRole → Compute-Create, AssumeRole chains, GetSecretValue |
| **IAM Access Analyzer** | Periodic scan for over-permissive policies |
| **AWS Config rules** | `iam-policy-no-statements-with-admin-access`, `s3-bucket-public-read-prohibited` |
| **Terraform `plan` in CI** | Never deploy IAM mutations without plan+review |