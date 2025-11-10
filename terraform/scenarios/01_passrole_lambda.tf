# ------------------------------------------------------------------ scenario 01
# iam:PassRole + lambda:CreateFunction/InvokeFunction
#
# app-svc-user can PassRole lambda-exec-role (a privileged, admin-role) and
# create lambda functions. An attacker would inject a malicious function that
# assumes lambda-exec-role under the hood -> full admin.

# The privileged target role the escalation lands on.
resource "aws_iam_role" "lambda_exec" {
  name = "lambda-exec-role"
  # Same string as the mock: trust allows the lambda service.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "TrustLambdaService"
        Effect    = "Allow"
        Principal = { Service = ["lambda.amazonaws.com"] }
        Action    = ["sts:AssumeRole"]
      }
    ]
  })
}

resource "aws_iam_policy" "admin" {
  name = "AdministratorAccess"
  # Explicitly matches AWS's read-only-agnostic admin doc for the lab.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "FullAdmin"
        Effect    = "Allow"
        Action    = ["*"]
        Resource  = ["*"]
      }
    ]
  })
}

# policy is admin -> the target is a privileged role.
resource "aws_iam_role_policy_attachment" "admin_on_lambda_exec" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.admin.arn
}

resource "aws_iam_user" "app_svc" {
  name = "app-svc-user"
}

resource "aws_iam_policy" "lambda_deploy" {
  name = "lambda-deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "LambdaDeploy"
        Effect   = "Allow"
        Action   = ["lambda:CreateFunction", "lambda:InvokeFunction"]
        Resource = ["*"]
      },
      {
        Sid      = "PassRole"
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = ["*"]
      },
    ]
  })
}

resource "aws_iam_user_policy_attachment" "lambda_deploy_on_app_svc" {
  user       = aws_iam_user.app_svc.name
  policy_arn = aws_iam_policy.lambda_deploy.arn
}

# Attacker creates the function, then PassRole lambda-exec-role into deploy.
resource "aws_iam_user_policy_attachment" "app_svc_lambda" {
  user       = aws_iam_user.app_svc.name
  policy_arn = aws_iam_policy.lambda_deploy.arn
}