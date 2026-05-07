# ── RDS Security Group ──────────────────────────────────────────────────

resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds-sg"
  description = "Security group for SENTINEL RDS PostgreSQL"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description              = "PostgreSQL from EKS nodes"
    from_port                = 5432
    to_port                  = 5432
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
    Name = "${local.name_prefix}-rds-sg"
  }
}

# ── RDS Subnet Group ───────────────────────────────────────────────────

resource "aws_db_subnet_group" "sentinel" {
  name       = "${local.name_prefix}-rds-subnet-group"
  subnet_ids = aws_subnet.private_subnets[*].id

  tags = {
    Name = "${local.name_prefix}-rds-subnet-group"
  }
}

# ── RDS Parameter Group ────────────────────────────────────────────────

resource "aws_db_parameter_group" "sentinel" {
  name   = "${local.name_prefix}-pg15-params"
  family = "postgres15"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  tags = {
    Name = "${local.name_prefix}-pg15-params"
  }
}

# ── KMS Key for RDS ────────────────────────────────────────────────────

resource "aws_kms_key" "rds" {
  description             = "KMS key for SENTINEL RDS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-rds-kms"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.name_prefix}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# ── RDS Instance ───────────────────────────────────────────────────────

resource "aws_db_instance" "sentinel_postgres" {
  identifier = "${local.name_prefix}-postgres"

  engine               = "postgres"
  engine_version       = "15"
  instance_class       = var.db_instance_class
  allocated_storage    = var.rds_allocated_storage
  max_allocated_storage = var.rds_max_allocated_storage
  storage_type         = "gp3"
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.rds.arn

  db_name  = var.rds_database_name
  username = var.rds_username
  password = var.rds_password

  multi_az               = var.environment == "production"
  db_subnet_group_name   = aws_db_subnet_group.sentinel.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.sentinel.name

  backup_retention_period = var.environment == "production" ? 30 : 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  deletion_protection       = var.environment == "production"
  skip_final_snapshot       = var.environment != "production"
  final_snapshot_identifier = var.environment == "production" ? "${local.name_prefix}-postgres-final" : null
  copy_tags_to_snapshot     = true

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = aws_kms_key.rds.arn

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  auto_minor_version_upgrade = true

  tags = {
    Name = "${local.name_prefix}-postgres"
  }

  lifecycle {
    ignore_changes = [password]
  }
}
