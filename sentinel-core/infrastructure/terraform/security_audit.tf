# AWS Security Audit Resources: CloudTrail, GuardDuty, Security Hub

# ── CloudTrail — audit of all AWS API calls ───────────────────────────────────

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${var.environment}-sentinel-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = var.environment != "production"

  tags = {
    Name        = "${var.environment}-sentinel-cloudtrail-logs"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.sentinel_secrets.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "sentinel" {
  name                          = "${var.environment}-sentinel-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = var.environment == "production"
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.sentinel_secrets.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name        = "${var.environment}-sentinel-trail"
    Environment = var.environment
    Project     = "SENTINEL"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cloudtrail/${var.environment}-sentinel"
  retention_in_days = 90

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${var.environment}-sentinel-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
    }]
  })

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "${var.environment}-sentinel-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# ── GuardDuty — continuous threat intelligence ────────────────────────────────

resource "aws_guardduty_detector" "sentinel" {
  enable = true

  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }

  tags = {
    Name        = "${var.environment}-sentinel-guardduty"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# Route GuardDuty findings to SNS for alerting
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.environment}-sentinel-guardduty-findings"
  description = "Capture GuardDuty HIGH/CRITICAL findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", 7] }] }
  })

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.sentinel_alarms[0].arn
}

# ── Security Hub — centralised security posture ───────────────────────────────

resource "aws_securityhub_account" "sentinel" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
  depends_on    = [aws_securityhub_account.sentinel]
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.sentinel]
}
