# ── ElastiCache Security Group ──────────────────────────────────────────

resource "aws_security_group" "redis" {
  name        = "${local.name_prefix}-redis-sg"
  description = "Security group for SENTINEL ElastiCache Redis"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description              = "Redis from EKS nodes"
    from_port                = 6379
    to_port                  = 6379
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.eks_nodes.id
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-redis-sg"
  }
}

# ── ElastiCache Subnet Group ──────────────────────────────────────────

resource "aws_elasticache_subnet_group" "sentinel" {
  name       = "${local.name_prefix}-redis-subnet-group"
  subnet_ids = aws_subnet.private_subnets[*].id

  tags = {
    Name = "${local.name_prefix}-redis-subnet-group"
  }
}

# ── ElastiCache Parameter Group ───────────────────────────────────────

resource "aws_elasticache_parameter_group" "sentinel" {
  name   = "${local.name_prefix}-redis7-params"
  family = "redis7"

  parameter {
    name  = "maxmemory-policy"
    value = "volatile-lru"
  }

  parameter {
    name  = "notify-keyspace-events"
    value = "Ex"
  }

  tags = {
    Name = "${local.name_prefix}-redis7-params"
  }
}

# ── KMS Key for ElastiCache ──────────────────────────────────────────

resource "aws_kms_key" "redis" {
  description             = "KMS key for SENTINEL ElastiCache encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-redis-kms"
  }
}

resource "aws_kms_alias" "redis" {
  name          = "alias/${local.name_prefix}-redis"
  target_key_id = aws_kms_key.redis.key_id
}

# ── ElastiCache Replication Group ─────────────────────────────────────

resource "aws_elasticache_replication_group" "sentinel" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "SENTINEL Redis replication group"

  node_type            = var.redis_node_type
  num_cache_clusters   = var.redis_num_cache_clusters
  parameter_group_name = aws_elasticache_parameter_group.sentinel.name

  port               = 6379
  subnet_group_name  = aws_elasticache_subnet_group.sentinel.name
  security_group_ids = [aws_security_group.redis.id]

  auth_token                 = var.redis_auth_token != "" ? var.redis_auth_token : null
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.redis.arn

  automatic_failover_enabled = var.redis_num_cache_clusters > 1
  multi_az_enabled           = var.redis_num_cache_clusters > 1 && var.environment == "production"

  engine_version       = "7.0"
  maintenance_window   = "Mon:05:00-Mon:06:00"
  snapshot_window      = "02:00-03:00"
  snapshot_retention_limit = var.environment == "production" ? 7 : 1

  auto_minor_version_upgrade = true

  tags = {
    Name = "${local.name_prefix}-redis"
  }
}
