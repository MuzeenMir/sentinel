# Amazon SageMaker for SENTINEL ML Model Training

# S3 Bucket for ML Models and Training Data
resource "aws_s3_bucket" "sentinel_models" {
  bucket = "${var.environment}-sentinel-ml-models-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "${var.environment}-sentinel-ml-models"
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_s3_bucket_versioning" "sentinel_models" {
  bucket = aws_s3_bucket.sentinel_models.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sentinel_models" {
  bucket = aws_s3_bucket.sentinel_models.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "sentinel_models" {
  bucket = aws_s3_bucket.sentinel_models.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# IAM Role for SageMaker
resource "aws_iam_role" "sagemaker_execution_role" {
  name = "${var.environment}-sentinel-sagemaker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "sagemaker.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_iam_role_policy" "sagemaker_policy" {
  name = "${var.environment}-sentinel-sagemaker-policy"
  role = aws_iam_role.sagemaker_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
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
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:CreateLogGroup",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:CreateNetworkInterfacePermission",
          "ec2:DeleteNetworkInterface",
          "ec2:DeleteNetworkInterfacePermission",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeVpcs",
          "ec2:DescribeDhcpOptions",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

# Security Group for SageMaker
resource "aws_security_group" "sagemaker" {
  name        = "${var.environment}-sentinel-sagemaker-sg"
  description = "Security group for SENTINEL SageMaker"
  vpc_id      = aws_vpc.sentinel_vpc.id

  ingress {
    description = "Allow internal traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-sentinel-sagemaker-sg"
    Environment = var.environment
  }
}

# SageMaker Domain for Studio
resource "aws_sagemaker_domain" "sentinel" {
  domain_name = "${var.environment}-sentinel-sagemaker"
  auth_mode   = "IAM"
  vpc_id      = aws_vpc.sentinel_vpc.id
  subnet_ids  = aws_subnet.private_subnets[*].id

  default_user_settings {
    execution_role = aws_iam_role.sagemaker_execution_role.arn

    security_groups = [aws_security_group.sagemaker.id]

    sharing_settings {
      notebook_output_option = "Allowed"
      s3_output_path         = "s3://${aws_s3_bucket.sentinel_models.bucket}/studio-outputs"
    }
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# SageMaker Model for AI Detection
resource "aws_sagemaker_model" "threat_detector" {
  name               = "${var.environment}-sentinel-threat-detector"
  execution_role_arn = aws_iam_role.sagemaker_execution_role.arn

  primary_container {
    image          = "763104351884.dkr.ecr.${var.aws_region}.amazonaws.com/pytorch-inference:1.13.1-cpu-py39"
    model_data_url = "s3://${aws_s3_bucket.sentinel_models.bucket}/models/threat-detector/model.tar.gz"
    environment = {
      SAGEMAKER_PROGRAM = "inference.py"
    }
  }

  vpc_config {
    security_group_ids = [aws_security_group.sagemaker.id]
    subnets            = aws_subnet.private_subnets[*].id
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }

  lifecycle {
    ignore_changes = [primary_container[0].model_data_url]
  }
}

# SageMaker Endpoint Configuration
resource "aws_sagemaker_endpoint_configuration" "threat_detector" {
  name = "${var.environment}-sentinel-threat-detector-config"

  production_variants {
    variant_name           = "primary"
    model_name             = aws_sagemaker_model.threat_detector.name
    initial_instance_count = 1
    instance_type          = var.sagemaker_instance_type
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# SageMaker Endpoint
resource "aws_sagemaker_endpoint" "threat_detector" {
  name                 = "${var.environment}-sentinel-threat-detector"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.threat_detector.name

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# Outputs for SageMaker
output "sagemaker_model_bucket" {
  description = "S3 bucket for SageMaker models"
  value       = aws_s3_bucket.sentinel_models.bucket
}

output "sagemaker_endpoint_name" {
  description = "SageMaker endpoint name"
  value       = aws_sagemaker_endpoint.threat_detector.name
}

output "sagemaker_domain_id" {
  description = "SageMaker Studio domain ID"
  value       = aws_sagemaker_domain.sentinel.id
}
