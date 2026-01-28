# Amazon MSK (Managed Streaming for Apache Kafka) for SENTINEL

# Security Group for MSK
resource "aws_security_group" "msk" {
  name        = "${var.environment}-sentinel-msk-sg"
  description = "Security group for SENTINEL MSK cluster"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description = "Kafka plaintext"
    from_port   = 9092
    to_port     = 9092
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "Kafka TLS"
    from_port   = 9094
    to_port     = 9094
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "Zookeeper"
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
    Name        = "${var.environment}-sentinel-msk-sg"
    Environment = var.environment
  }
}

# KMS Key for MSK encryption
resource "aws_kms_key" "msk" {
  description             = "KMS key for SENTINEL MSK encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_kms_alias" "msk" {
  name          = "alias/${var.environment}-sentinel-msk"
  target_key_id = aws_kms_key.msk.key_id
}

# CloudWatch Log Group for MSK
resource "aws_cloudwatch_log_group" "msk" {
  name              = "/msk/${var.environment}-sentinel"
  retention_in_days = 14

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# MSK Configuration
resource "aws_msk_configuration" "sentinel" {
  name              = "${var.environment}-sentinel-msk-config"
  kafka_versions    = ["3.4.0"]
  
  server_properties = <<PROPERTIES
auto.create.topics.enable=true
delete.topic.enable=true
log.retention.hours=168
log.retention.bytes=1073741824
num.partitions=3
default.replication.factor=2
min.insync.replicas=1
PROPERTIES

  lifecycle {
    create_before_destroy = true
  }
}

# MSK Cluster
resource "aws_msk_cluster" "sentinel" {
  cluster_name           = "${var.environment}-sentinel-msk"
  kafka_version          = "3.4.0"
  number_of_broker_nodes = 2

  broker_node_group_info {
    instance_type   = var.msk_instance_type
    client_subnets  = aws_subnet.private_subnets[*].id
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info {
        volume_size = var.msk_ebs_volume_size
      }
    }
  }

  encryption_info {
    encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn
    
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.sentinel.arn
    revision = aws_msk_configuration.sentinel.latest_revision
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
    }
  }

  tags = {
    Name        = "${var.environment}-sentinel-msk"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# Outputs for MSK
output "msk_bootstrap_brokers" {
  description = "MSK bootstrap brokers for plaintext connection"
  value       = aws_msk_cluster.sentinel.bootstrap_brokers
  sensitive   = true
}

output "msk_bootstrap_brokers_tls" {
  description = "MSK bootstrap brokers for TLS connection"
  value       = aws_msk_cluster.sentinel.bootstrap_brokers_tls
  sensitive   = true
}

output "msk_zookeeper_connect_string" {
  description = "MSK Zookeeper connection string"
  value       = aws_msk_cluster.sentinel.zookeeper_connect_string
  sensitive   = true
}
