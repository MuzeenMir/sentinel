# SENTINEL Terraform Variables
# Enterprise-grade infrastructure configuration for security platform

# ================================
# Core Configuration
# ================================

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

# ================================
# Network Configuration
# ================================

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.20.0/24"]
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway (for cost savings in non-production)"
  type        = bool
  default     = true
}

# ================================
# Database (RDS) Variables
# ================================

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "rds_allocated_storage" {
  description = "Allocated storage for RDS in GB"
  type        = number
  default     = 20
}

variable "rds_database_name" {
  description = "Database name"
  type        = string
  default     = "sentinel_db"
}

variable "rds_username" {
  description = "Database master username"
  type        = string
  default     = "sentinel_admin"
  sensitive   = true
}

variable "rds_password" {
  description = "Database master password (use secrets manager in production)"
  type        = string
  sensitive   = true
}

variable "rds_multi_az" {
  description = "Enable Multi-AZ for RDS (recommended for production)"
  type        = bool
  default     = false
}

variable "rds_backup_retention_period" {
  description = "Number of days to retain RDS backups"
  type        = number
  default     = 7
}

# ================================
# Cache (Redis) Variables
# ================================

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.medium"
}

variable "redis_num_nodes" {
  description = "Number of cache nodes (use 2+ for production)"
  type        = number
  default     = 1
}

variable "redis_engine_version" {
  description = "Redis engine version"
  type        = string
  default     = "6.2"
}

variable "redis_auth_token" {
  description = "Redis AUTH token for transit encryption"
  type        = string
  default     = ""
  sensitive   = true
}

# ================================
# Kafka (MSK) Variables
# ================================

variable "kafka_broker_nodes" {
  description = "Number of Kafka broker nodes (minimum 2 for production)"
  type        = number
  default     = 2
}

variable "kafka_instance_type" {
  description = "MSK broker instance type"
  type        = string
  default     = "kafka.t3.small"
}

variable "kafka_ebs_volume_size" {
  description = "EBS volume size for MSK brokers in GB"
  type        = number
  default     = 100
}

variable "kafka_version" {
  description = "Kafka version"
  type        = string
  default     = "2.8.1"
}

# ================================
# SageMaker Variables
# ================================

variable "sagemaker_instance_type" {
  description = "SageMaker endpoint instance type"
  type        = string
  default     = "ml.t3.medium"
}

# ================================
# Security Variables
# ================================

variable "ssl_certificate_arn" {
  description = "ARN of SSL certificate for HTTPS listener"
  type        = string
  default     = ""
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed for SSH access (restrict in production)"
  type        = list(string)
  default     = []
}

variable "enable_waf" {
  description = "Enable AWS WAF for API load balancer"
  type        = bool
  default     = false
}

# ================================
# Monitoring Variables
# ================================

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for all services"
  type        = bool
  default     = true
}

variable "alarm_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
  default     = ""
}

# ================================
# Tags
# ================================

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Project   = "SENTINEL"
    ManagedBy = "Terraform"
  }
}
