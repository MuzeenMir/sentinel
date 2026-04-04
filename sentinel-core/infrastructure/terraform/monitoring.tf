# ── CloudWatch Log Groups ──────────────────────────────────────────────

locals {
  service_names = [
    "api-gateway",
    "auth-service",
    "ai-engine",
    "drl-engine",
    "alert-service",
    "data-collector",
    "policy-orchestrator",
    "compliance-engine",
    "xai-service",
    "hardening-service",
    "hids-agent",
    "xdp-collector",
  ]
}

resource "aws_cloudwatch_log_group" "services" {
  for_each = toset(local.service_names)

  name              = "/sentinel/${var.environment}/${each.value}"
  retention_in_days = var.log_retention_days

  tags = {
    Name    = "${local.name_prefix}-${each.value}-logs"
    Service = each.value
  }
}

# ── SNS Topic for Alarms ──────────────────────────────────────────────

resource "aws_sns_topic" "sentinel_alerts" {
  name = "${local.name_prefix}-alerts"

  tags = {
    Name = "${local.name_prefix}-alerts"
  }
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.sentinel_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "sentinel_alerts" {
  arn = aws_sns_topic.sentinel_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowCloudWatchAlarms"
      Effect = "Allow"
      Principal = {
        Service = "cloudwatch.amazonaws.com"
      }
      Action   = "sns:Publish"
      Resource = aws_sns_topic.sentinel_alerts.arn
    }]
  })
}

# ── CloudWatch Alarms ─────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "eks_cpu_high" {
  alarm_name          = "${local.name_prefix}-eks-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "node_cpu_utilization"
  namespace           = "ContainerInsights"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "EKS node CPU utilization exceeds 80% for 15 minutes"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  ok_actions          = [aws_sns_topic.sentinel_alerts.arn]

  dimensions = {
    ClusterName = aws_eks_cluster.sentinel.name
  }

  tags = {
    Name = "${local.name_prefix}-eks-cpu-high"
  }
}

resource "aws_cloudwatch_metric_alarm" "eks_memory_high" {
  alarm_name          = "${local.name_prefix}-eks-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "node_memory_utilization"
  namespace           = "ContainerInsights"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "EKS node memory utilization exceeds 80% for 15 minutes"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  ok_actions          = [aws_sns_topic.sentinel_alerts.arn]

  dimensions = {
    ClusterName = aws_eks_cluster.sentinel.name
  }

  tags = {
    Name = "${local.name_prefix}-eks-memory-high"
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx_high" {
  alarm_name          = "${local.name_prefix}-alb-5xx-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_description   = "ALB 5xx error count exceeds 50 in 10 minutes"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  ok_actions          = [aws_sns_topic.sentinel_alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.sentinel.arn_suffix
  }

  tags = {
    Name = "${local.name_prefix}-alb-5xx-high"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_storage_low" {
  alarm_name          = "${local.name_prefix}-rds-storage-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 10737418240  # 10 GiB
  alarm_description   = "RDS free storage below 10 GiB"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  ok_actions          = [aws_sns_topic.sentinel_alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.sentinel_postgres.identifier
  }

  tags = {
    Name = "${local.name_prefix}-rds-storage-low"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu_high" {
  alarm_name          = "${local.name_prefix}-rds-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU utilization exceeds 80% for 15 minutes"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  ok_actions          = [aws_sns_topic.sentinel_alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.sentinel_postgres.identifier
  }

  tags = {
    Name = "${local.name_prefix}-rds-cpu-high"
  }
}

resource "aws_cloudwatch_metric_alarm" "redis_cpu_high" {
  alarm_name          = "${local.name_prefix}-redis-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Redis CPU utilization exceeds 80% for 15 minutes"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  ok_actions          = [aws_sns_topic.sentinel_alerts.arn]

  dimensions = {
    ReplicationGroupId = aws_elasticache_replication_group.sentinel.id
  }

  tags = {
    Name = "${local.name_prefix}-redis-cpu-high"
  }
}
