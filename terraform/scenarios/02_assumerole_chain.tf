# ------------------------------------------------------------------ scenario 02
# chained sts:AssumeRole: dev-user -> research-role -> ci-deploy-role (admin)
#
# dev-user can assume research-role; research-role can assume ci-deploy-role
# which is attached the admin policy. Walking the chain yields full admin.

resource "aws_iam_role" "research" {
  name = "research-role"
  # Same trust as the mock: dev-user and app-svc-user may assume it.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "TrustDevAndSvc"
        Effect    = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/dev-user",
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/app-svc-user",
          ]
        }
        Action = ["sts:AssumeRole"]
      }
    ]
  })
}

resource "aws_iam_role" "ci_deploy" {
  name = "ci-deploy-role"
  # Research-role may hop into CI deploy.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "TrustResearch"
        Effect    = "Allow"
        Principal = {
          AWS = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/research-role"]
        }
        Action = ["sts:AssumeRole"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_on_ci_deploy" {
  role       = aws_iam_role.ci_deploy.name
  policy_arn = aws_iam_policy.admin.arn
}

resource "aws_iam_user" "dev" {
  name = "dev-user"
}

resource "aws_iam_policy" "dev_assume_research" {
  name = "dev-assume-research"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AssumeResearch"
        Effect    = "Allow"
        Action    = ["sts:AssumeRole"]
        Resource  = [aws_iam_role.research.arn]
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "dev_assume_research_attach" {
  user       = aws_iam_user.dev.name
  policy_arn = aws_iam_policy.dev_assume_research.arn
}

resource "aws_iam_role_policy" "research_hop_ci" {
  role = aws_iam_role.research.name
  name = "research-hop-ci"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "HopCiDeploy"
        Effect    = "Allow"
        Action    = ["sts:AssumeRole"]
        Resource  = [aws_iam_role.ci_deploy.arn]
      }
    ]
  })
}

# Baseline identity used as the "already admin" fixture in the analyzer output.
resource "aws_iam_user" "admin" {
  name = "admin-user"
}

resource "aws_iam_user_policy_attachment" "admin_on_admin_user" {
  user       = aws_iam_user.admin.name
  policy_arn = aws_iam_policy.admin.arn
}