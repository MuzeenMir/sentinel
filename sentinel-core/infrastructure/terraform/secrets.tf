# AWS Secrets Manager resources for SENTINEL
#
# Stores credentials that must NEVER appear in plaintext in ECS task
# environment variables or Terraform state.
#
# After `terraform apply`, populate the secret values with:
#   aws secretsmanager put-secret-value \
#     --secret-id <secret_arn> \
#     --secret-string '{"password":"<your-password>"}'

# KMS key for Secrets Manager encryption
resource "aws_kms_key" "sentinel_secrets" {
  description             = "KMS key for SENTINEL Secrets Manager"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "${var.environment}-sentinel-secrets-kms"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_kms_alias" "sentinel_secrets" {
  name          = "alias/${var.environment}-sentinel-secrets"
  target_key_id = aws_kms_key.sentinel_secrets.key_id
}

# ── RDS credentials ──────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "rds_credentials" {
  name                    = "${var.environment}/sentinel/rds-credentials"
  description             = "PostgreSQL credentials for SENTINEL auth-service"
  kms_key_id              = aws_kms_key.sentinel_secrets.arn
  recovery_window_in_days = var.environment == "production" ? 30 : 7

  tags = {
    Name        = "${var.environment}-sentinel-rds-credentials"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# Stores the initial password.  Rotate via Secrets Manager rotation lambda
# after first apply.  Do NOT commit var.rds_password to source control;
# pass it via TF_VAR_rds_password environment variable or a secrets backend.
resource "aws_secretsmanager_secret_version" "rds_credentials" {
  secret_id = aws_secretsmanager_secret.rds_credentials.id
  secret_string = jsonencode({
    username = var.rds_username
    password = var.rds_password
    host     = aws_db_instance.sentinel_postgres.address
    port     = 5432
    dbname   = var.rds_database_name
  })

  lifecycle {
    # Prevent Terraform from overwriting a manually rotated password
    ignore_changes = [secret_string]
  }
}

# ── Redis AUTH token ─────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "redis_auth" {
  name                    = "${var.environment}/sentinel/redis-auth-token"
  description             = "Redis AUTH token for SENTINEL ElastiCache"
  kms_key_id              = aws_kms_key.sentinel_secrets.arn
  recovery_window_in_days = var.environment == "production" ? 30 : 7

  tags = {
    Name        = "${var.environment}-sentinel-redis-auth"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_secretsmanager_secret_version" "redis_auth" {
  count     = var.redis_auth_token != "" ? 1 : 0
  secret_id = aws_secretsmanager_secret.redis_auth.id
  secret_string = jsonencode({
    auth_token = var.redis_auth_token
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ── IAM: allow ECS task execution role to read secrets ───────────────────────

resource "aws_iam_role_policy" "ecs_secrets_policy" {
  name = "${var.environment}-sentinel-ecs-secrets-policy"
  role = aws_iam_role.ecs_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.rds_credentials.arn,
          aws_secretsmanager_secret.redis_auth.arn,
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.sentinel_secrets.arn
      }
    ]
  })
}

# ── Outputs (ARNs consumed by ecs.tf for secrets injection) ──────────────────

output "rds_secret_arn" {
  description = "ARN of the RDS credentials secret"
  value       = aws_secretsmanager_secret.rds_credentials.arn
  sensitive   = true
}

output "redis_secret_arn" {
  description = "ARN of the Redis auth token secret"
  value       = aws_secretsmanager_secret.redis_auth.arn
  sensitive   = true
}
