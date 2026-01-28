provider "aws" {
  region = var.aws_region
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# VPC Configuration
resource "aws_vpc" "sentinel_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-sentinel-vpc"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "sentinel_igw" {
  vpc_id = aws_vpc.sentinel_vpc.id

  tags = {
    Name        = "${var.environment}-sentinel-igw"
    Environment = var.environment
  }
}

# Public Subnets
resource "aws_subnet" "public_subnets" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.sentinel_vpc.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.environment}-public-subnet-${count.index}"
    Environment = var.environment
  }
}

# Private Subnets
resource "aws_subnet" "private_subnets" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.sentinel_vpc.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name        = "${var.environment}-private-subnet-${count.index}"
    Environment = var.environment
  }
}

# Route Table for Public Subnets
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.sentinel_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sentinel_igw.id
  }

  tags = {
    Name        = "${var.environment}-public-route-table"
    Environment = var.environment
  }
}

# Associate Public Subnets with Route Table
resource "aws_route_table_association" "public_assoc" {
  count          = length(aws_subnet.public_subnets)
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_rt.id
}

# RDS Subnet Group
resource "aws_db_subnet_group" "sentinel_rds_subnet_group" {
  name       = "${var.environment}-sentinel-rds-subnet-group"
  subnet_ids = aws_subnet.private_subnets[*].id

  tags = {
    Name        = "${var.environment}-sentinel-rds-subnet-group"
    Environment = var.environment
  }
}

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "sentinel_redis_subnet_group" {
  name       = "${var.environment}-sentinel-redis-subnet-group"
  subnet_ids = aws_subnet.private_subnets[*].id

  tags = {
    Name        = "${var.environment}-sentinel-redis-subnet-group"
    Environment = var.environment
  }
}

# Security Groups

# Database Security Group
resource "aws_security_group" "database_sg" {
  name        = "${var.environment}-sentinel-database-sg"
  description = "Security group for database instances"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description     = "PostgreSQL access from VPC"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    cidr_blocks     = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-sentinel-database-sg"
    Environment = var.environment
  }
}

# Cache Security Group
resource "aws_security_group" "cache_sg" {
  name        = "${var.environment}-sentinel-cache-sg"
  description = "Security group for Redis cache"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description = "Redis access from VPC"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-sentinel-cache-sg"
    Environment = var.environment
  }
}

# Kafka Security Group
resource "aws_security_group" "kafka_sg" {
  name        = "${var.environment}-sentinel-kafka-sg"
  description = "Security group for Kafka brokers"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description = "Kafka access from VPC"
    from_port   = 9092
    to_port     = 9092
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "Zookeeper access from VPC"
    from_port   = 2181
    to_port     = 2181
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-sentinel-kafka-sg"
    Environment = var.environment
  }
}

# Data Collector Security Group
resource "aws_security_group" "data_collector_sg" {
  name        = "${var.environment}-sentinel-data-collector-sg"
  description = "Security group for data collector instances"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Should be restricted in production
  }

  ingress {
    description = "Data collector API"
    from_port   = 5001
    to_port     = 5001
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-sentinel-data-collector-sg"
    Environment = var.environment
  }
}

# API Load Balancer Security Group
resource "aws_security_group" "api_lb_sg" {
  name        = "${var.environment}-sentinel-api-lb-sg"
  description = "Security group for API load balancer"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description = "HTTPS access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP access (redirect to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-sentinel-api-lb-sg"
    Environment = var.environment
  }
}

# RDS Instance
resource "aws_db_instance" "sentinel_postgres" {
  identifier              = "${var.environment}-sentinel-postgres"
  allocated_storage       = var.rds_allocated_storage
  engine                  = "postgres"
  engine_version          = "13.7"
  instance_class          = var.rds_instance_class
  db_name                 = var.rds_database_name
  username                = var.rds_username
  password                = var.rds_password
  vpc_security_group_ids  = [aws_security_group.database_sg.id]
  db_subnet_group_name    = aws_db_subnet_group.sentinel_rds_subnet_group.name
  skip_final_snapshot     = var.environment != "production"
  backup_retention_period = 7
  deletion_protection     = var.environment == "production"

  tags = {
    Name        = "${var.environment}-sentinel-postgres"
    Environment = var.environment
  }
}

# ElastiCache Redis Cluster
resource "aws_elasticache_cluster" "sentinel_redis" {
  cluster_id           = "${var.environment}-sentinel-redis"
  engine               = "redis"
  node_type            = var.redis_node_type
  num_cache_nodes      = var.redis_num_nodes
  parameter_group_name = "default.redis6.x"
  engine_version       = "6.2"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.sentinel_redis_subnet_group.name
  security_group_ids   = [aws_security_group.cache_sg.id]

  tags = {
    Name        = "${var.environment}-sentinel-redis"
    Environment = var.environment
  }
}

# MSK Kafka Cluster
resource "aws_msk_cluster" "sentinel_kafka" {
  cluster_name           = "${var.environment}-sentinel-kafka"
  kafka_version          = "2.8.1"
  number_of_broker_nodes = var.kafka_broker_nodes

  broker_node_group_info {
    instance_type   = var.kafka_instance_type
    client_subnets  = aws_subnet.private_subnets[*].id
    security_groups = [aws_security_group.kafka_sg.id]

    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  tags = {
    Name        = "${var.environment}-sentinel-kafka"
    Environment = var.environment
  }
}

# API Gateway Load Balancer
resource "aws_lb" "sentinel_api_lb" {
  name               = "${var.environment}-sentinel-api-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.api_lb_sg.id]
  subnets            = aws_subnet.public_subnets[*].id

  tags = {
    Name        = "${var.environment}-sentinel-api-lb"
    Environment = var.environment
  }
}

# API Gateway Target Group
resource "aws_lb_target_group" "sentinel_api_tg" {
  name        = "${var.environment}-sentinel-api-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.sentinel_vpc.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }

  tags = {
    Name        = "${var.environment}-sentinel-api-tg"
    Environment = var.environment
  }
}

# API Gateway Listener
resource "aws_lb_listener" "sentinel_api_https" {
  load_balancer_arn = aws_lb.sentinel_api_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.ssl_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.sentinel_api_tg.arn
  }
}

# HTTP to HTTPS redirect
resource "aws_lb_listener" "sentinel_api_http_redirect" {
  load_balancer_arn = aws_lb.sentinel_api_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
