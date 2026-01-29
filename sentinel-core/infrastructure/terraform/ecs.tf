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
    security_groups = [aws_security_group.api_lb.id]
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
    "compliance-engine"
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
