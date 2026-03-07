# ECS Cluster for SENTINEL Microservices

# ECS Cluster
resource "aws_ecs_cluster" "sentinel" {
  name = "${var.environment}-sentinel-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "${var.environment}-sentinel-cluster"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# ECS Cluster Capacity Providers
resource "aws_ecs_cluster_capacity_providers" "sentinel" {
  cluster_name = aws_ecs_cluster.sentinel.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

# CloudWatch Log Group for ECS
resource "aws_cloudwatch_log_group" "sentinel_ecs" {
  name              = "/ecs/${var.environment}-sentinel"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.environment}-sentinel-ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# IAM Role for ECS Tasks
resource "aws_iam_role" "ecs_task_role" {
  name = "${var.environment}-sentinel-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# Policy for ECS Tasks to access required services
resource "aws_iam_role_policy" "ecs_task_policy" {
  name = "${var.environment}-sentinel-ecs-task-policy"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.sentinel_models.arn,
          "${aws_s3_bucket.sentinel_models.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sagemaker:InvokeEndpoint"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kafka:DescribeCluster",
          "kafka:GetBootstrapBrokers"
        ]
        Resource = aws_msk_cluster.sentinel.arn
      }
    ]
  })
}

# Security Group for ECS Tasks
resource "aws_security_group" "ecs_tasks" {
  name        = "${var.environment}-sentinel-ecs-tasks-sg"
  description = "Security group for SENTINEL ECS tasks"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description     = "Allow traffic from ALB"
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.api_lb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-sentinel-ecs-tasks-sg"
    Environment = var.environment
  }
}

# ECR Repository for SENTINEL images
resource "aws_ecr_repository" "sentinel_services" {
  for_each = toset([
    "api-gateway",
    "auth-service",
    "alert-service",
    "data-collector",
    "ai-engine",
    "drl-engine",
    "policy-orchestrator",
    "xai-service",
    "compliance-engine",
    "hids-agent",
    "hardening-service",
    "admin-console"
  ])

  name                 = "${var.environment}-sentinel-${each.key}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name        = "${var.environment}-sentinel-${each.key}"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# Service Discovery Namespace
resource "aws_service_discovery_private_dns_namespace" "sentinel" {
  name        = "sentinel.local"
  description = "SENTINEL service discovery namespace"
  vpc         = aws_vpc.sentinel_vpc.id

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# ECS Task Definition for AI Engine
resource "aws_ecs_task_definition" "ai_engine" {
  family                   = "${var.environment}-sentinel-ai-engine"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 2048
  memory                   = 4096
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name  = "ai-engine"
      image = "${aws_ecr_repository.sentinel_services["ai-engine"].repository_url}:latest"
      
      portMappings = [
        {
          containerPort = 5003
          protocol      = "tcp"
        }
      ]
      
      environment = [
        {
          name  = "REDIS_URL"
          value = "redis://${aws_elasticache_cluster.sentinel_redis.cache_nodes[0].address}:6379"
        },
        {
          name  = "KAFKA_BOOTSTRAP_SERVERS"
          value = aws_msk_cluster.sentinel.bootstrap_brokers_tls
        },
        {
          name  = "MODEL_PATH"
          value = "/models"
        }
      ]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.sentinel_ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ai-engine"
        }
      }
      
      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:5003/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# ECS Service for AI Engine
resource "aws_ecs_service" "ai_engine" {
  name            = "${var.environment}-sentinel-ai-engine"
  cluster         = aws_ecs_cluster.sentinel.id
  task_definition = aws_ecs_task_definition.ai_engine.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private_subnets[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.ai_engine.arn
    container_name   = "ai-engine"
    container_port   = 5003
  }

  service_registries {
    registry_arn = aws_service_discovery_service.ai_engine.arn
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# Service Discovery for AI Engine
resource "aws_service_discovery_service" "ai_engine" {
  name = "ai-engine"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.sentinel.id
    
    dns_records {
      ttl  = 10
      type = "A"
    }
    
    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

# Target Group for AI Engine
resource "aws_lb_target_group" "ai_engine" {
  name        = "${var.environment}-ai-engine-tg"
  port        = 5003
  protocol    = "HTTP"
  vpc_id      = aws_vpc.sentinel_vpc.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 3
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# ── ECS task definitions and services for remaining Fargate services ──

locals {
  fargate_services = {
    api-gateway = {
      port   = 8080
      cpu    = 512
      memory = 1024
      env    = []
    }
    auth-service = {
      port   = 5000
      cpu    = 512
      memory = 1024
      env = [
        { name = "DATABASE_URL", value = "postgresql://sentinel:change-in-production@${aws_db_instance.sentinel_postgres.address}:5432/sentinel_db" },
        { name = "REDIS_URL", value = "redis://${aws_elasticache_cluster.sentinel_redis.cache_nodes[0].address}:6379" },
      ]
    }
    alert-service = {
      port   = 5002
      cpu    = 256
      memory = 512
      env = [
        { name = "REDIS_URL", value = "redis://${aws_elasticache_cluster.sentinel_redis.cache_nodes[0].address}:6379" },
      ]
    }
    data-collector = {
      port   = 5001
      cpu    = 512
      memory = 1024
      env = [
        { name = "KAFKA_BOOTSTRAP_SERVERS", value = aws_msk_cluster.sentinel.bootstrap_brokers_tls },
        { name = "REDIS_URL", value = "redis://${aws_elasticache_cluster.sentinel_redis.cache_nodes[0].address}:6379" },
      ]
    }
    drl-engine = {
      port   = 5005
      cpu    = 1024
      memory = 2048
      env = [
        { name = "REDIS_URL", value = "redis://${aws_elasticache_cluster.sentinel_redis.cache_nodes[0].address}:6379" },
      ]
    }
    policy-orchestrator = {
      port   = 5004
      cpu    = 256
      memory = 512
      env = [
        { name = "REDIS_URL", value = "redis://${aws_elasticache_cluster.sentinel_redis.cache_nodes[0].address}:6379" },
      ]
    }
    xai-service = {
      port   = 5006
      cpu    = 256
      memory = 512
      env = [
        { name = "REDIS_URL", value = "redis://${aws_elasticache_cluster.sentinel_redis.cache_nodes[0].address}:6379" },
      ]
    }
    compliance-engine = {
      port   = 5007
      cpu    = 256
      memory = 512
      env = [
        { name = "REDIS_URL", value = "redis://${aws_elasticache_cluster.sentinel_redis.cache_nodes[0].address}:6379" },
      ]
    }
  }
}

resource "aws_ecs_task_definition" "services" {
  for_each = local.fargate_services

  family                   = "${var.environment}-sentinel-${each.key}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name  = each.key
      image = "${aws_ecr_repository.sentinel_services[each.key].repository_url}:latest"
      portMappings = [{ containerPort = each.value.port, protocol = "tcp" }]
      environment  = each.value.env
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.sentinel_ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = each.key
        }
      }
      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:${each.value.port}/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
    }
  ])

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
    Service     = each.key
  }
}

resource "aws_service_discovery_service" "services" {
  for_each = local.fargate_services

  name = each.key

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.sentinel.id
    dns_records {
      ttl  = 10
      type = "A"
    }
    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_ecs_service" "services" {
  for_each = local.fargate_services

  name            = "${var.environment}-sentinel-${each.key}"
  cluster         = aws_ecs_cluster.sentinel.id
  task_definition = aws_ecs_task_definition.services[each.key].arn
  desired_count   = each.key == "api-gateway" ? 2 : 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private_subnets[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.services[each.key].arn
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
    Service     = each.key
  }
}

# ── WAF for API Load Balancer ──

resource "aws_wafv2_web_acl" "sentinel_api" {
  count = var.enable_waf ? 1 : 0

  name        = "${var.environment}-sentinel-api-waf"
  description = "WAF for SENTINEL API Gateway"
  scope       = "REGIONAL"

  default_action { allow {} }

  rule {
    name     = "rate-limit"
    priority = 1

    action { block {} }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.environment}-sentinel-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-managed-common-rules"
    priority = 2

    override_action { none {} }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.environment}-sentinel-common-rules"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-managed-sqli-rules"
    priority = 3

    override_action { none {} }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.environment}-sentinel-sqli-rules"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.environment}-sentinel-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_wafv2_web_acl_association" "sentinel_api" {
  count = var.enable_waf ? 1 : 0

  resource_arn = aws_lb.sentinel_api_lb.arn
  web_acl_arn  = aws_wafv2_web_acl.sentinel_api[0].arn
}

# ── CloudWatch Alarms ──

resource "aws_sns_topic" "sentinel_alarms" {
  count = var.enable_cloudwatch_alarms ? 1 : 0
  name  = "${var.environment}-sentinel-alarms"

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_sns_topic_subscription" "alarm_email" {
  count     = var.enable_cloudwatch_alarms && var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.sentinel_alarms[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.environment}-sentinel-api-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "API Gateway 5xx errors exceeded threshold"
  alarm_actions       = [aws_sns_topic.sentinel_alarms[0].arn]

  dimensions = {
    LoadBalancer = aws_lb.sentinel_api_lb.arn_suffix
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.environment}-sentinel-rds-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU utilization exceeds 80%"
  alarm_actions       = [aws_sns_topic.sentinel_alarms[0].arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.sentinel_postgres.identifier
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_cpu" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.environment}-sentinel-ecs-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 75
  alarm_description   = "ECS cluster CPU utilization exceeds 75%"
  alarm_actions       = [aws_sns_topic.sentinel_alarms[0].arn]

  dimensions = {
    ClusterName = aws_ecs_cluster.sentinel.name
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}
