variable "region" {
  description = "AWS region for the lab resources"
  type        = string
  default     = "us-east-1"
}

variable "localstack_endpoint" {
  description = "Optional LocalStack endpoint to keep the lab fully offline (e.g. http://localhost:4566)"
  type        = string
  default     = ""
}

variable "skip_credentials_validation" {
  description = "Skip AWS credential validation (required when running against LocalStack/minio)"
  type        = bool
  default     = false
}

variable "environment" {
  description = "Environment tag (lab / staging / prod) - always 'lab' in this repo"
  type        = string
  default     = "lab"
}

variable "team" {
  description = "Owner tag for lab resources"
  type        = string
  default     = "security-engineering"
}