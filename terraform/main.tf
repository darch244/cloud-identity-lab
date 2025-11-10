terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region

  # LocalStack / minio-style endpoints keep the lab fully offline when set.
  dynamic "endpoints" {
    for_each = var.localstack_endpoint != "" ? [1] : []
    content {
      iam             = var.localstack_endpoint
      s3              = var.localstack_endpoint
      kms             = var.localstack_endpoint
      lambda          = var.localstack_endpoint
      secretsmanager  = var.localstack_endpoint
      sts             = var.localstack_endpoint
      ec2             = var.localstack_endpoint
      cloudformation  = var.localstack_endpoint
    }
  }

  # Never auto-apply in CI; the lab exercises misconfigurations on purpose.
  skip_credentials_validation = var.skip_credentials_validation
}

resource "aws_kms_alias" "analytics" {
  name          = "alias/analytics"
  target_key_id = aws_kms_key.analytics.key_id
}

resource "aws_kms_key" "analytics" {
  description          = "Analytics encryption key (intentionally public-decryptable for the lab)"
  enable_key_rotation  = false
  deletion_window_in_days = 7
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicDecrypt"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["kms:Decrypt"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_secretsmanager_secret" "api_keys" {
  name        = "prod/api-key"
  description = "Lab secret (intentionally publicly readable)"
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id = aws_secretsmanager_secret.api_keys.id
  secret_string = jsonencode({
    api_key = "sub_sk_lab_1234567890abcdef_do_not_use"
  })
}