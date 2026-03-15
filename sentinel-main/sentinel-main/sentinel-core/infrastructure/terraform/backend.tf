# Terraform Remote State Backend
#
# Prerequisites — run once before `terraform init`:
#
#   aws s3api create-bucket \
#     --bucket <YOUR_STATE_BUCKET> \
#     --region us-east-1
#
#   aws s3api put-bucket-versioning \
#     --bucket <YOUR_STATE_BUCKET> \
#     --versioning-configuration Status=Enabled
#
#   aws s3api put-bucket-encryption \
#     --bucket <YOUR_STATE_BUCKET> \
#     --server-side-encryption-configuration \
#       '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
#
#   aws dynamodb create-table \
#     --table-name sentinel-terraform-locks \
#     --attribute-definitions AttributeName=LockID,AttributeType=S \
#     --key-schema AttributeName=LockID,KeyType=HASH \
#     --billing-mode PAY_PER_REQUEST \
#     --region us-east-1
#
# Replace the placeholder values below with your actual bucket name and
# AWS account ID, then run:  terraform init -reconfigure

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Replace with your state bucket name — must be globally unique
    bucket = "sentinel-terraform-state-REPLACE_WITH_ACCOUNT_ID"
    key    = "sentinel/terraform.tfstate"
    region = "us-east-1"

    # DynamoDB table for state locking
    dynamodb_table = "sentinel-terraform-locks"

    # Encrypt state at rest
    encrypt = true

    # Enable server-side encryption with KMS (optional — remove if using default SSE-S3)
    # kms_key_id = "alias/sentinel-terraform-state"
  }
}
