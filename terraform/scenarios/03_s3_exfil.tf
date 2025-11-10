# ------------------------------------------------------------------ scenario 03
# data exfiltration: S3 bucket + KMS key + Secrets Manager secret all allow "*".
#
# The bucket policy grants s3:GetObject / s3:ListBucket to every AWS principal
# ("*"), the KMS key allows kms:Decrypt to "*", and the prod API key secret
# allows secretsmanager:GetSecretValue to "*". These three together let an
# unauthenticated caller read production data, decrypt anything encrypted by
# the analytics key, and steal the API key.

resource "aws_s3_bucket" "analytics" {
  bucket = "analytics-data"
  tags = {
    Environment = var.environment
    Team        = var.team
  }
}

resource "aws_s3_bucket_policy" "analytics_public" {
  bucket = aws_s3_bucket.analytics.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = { AWS = ["*"] }
        Action    = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "${aws_s3_bucket.analytics.arn}",
          "${aws_s3_bucket.analytics.arn}/*",
        ]
      }
    ]
  })
}

resource "aws_s3_object" "analytics_sample" {
  bucket = aws_s3_bucket.analytics.id
  key    = "reports/Q3-summary.csv"
  content = "quarter,customers,revenue\nQ3,4821,1234500\n"
}