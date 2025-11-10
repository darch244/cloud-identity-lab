data "aws_caller_identity" "current" {}

output "admin_user_arn" {
  description = "ARN of the intentionally-admin user (baseline, never attacked)"
  value       = aws_iam_user.admin.arn
}

output "passrole_target_role_arn" {
  description = "Role the PassRole escalation can inject into (admin privileges)"
  value       = aws_iam_role.lambda_exec.arn
}

output "ci_deploy_role_arn" {
  description = "End of the assume-role chain (admin privileges)"
  value       = aws_iam_role.ci_deploy.arn
}

output "public_bucket" {
  description = "Name of the intentionally-public S3 bucket"
  value       = aws_s3_bucket.analytics.id
}

output "public_secret_name" {
  description = "Name of the intentionally-public Secrets Manager secret"
  value       = aws_secretsmanager_secret.api_keys.name
}

output "kms_alias" {
  description = "Alias of the intentionally-public-decrypt KMS key"
  value       = aws_kms_alias.analytics.name
}