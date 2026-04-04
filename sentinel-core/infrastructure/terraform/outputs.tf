output "eks_cluster_endpoint" {
  description = "EKS cluster API server endpoint"
  value       = aws_eks_cluster.sentinel.endpoint
}

output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.sentinel.name
}

output "eks_cluster_certificate_authority" {
  description = "EKS cluster CA certificate (base64)"
  value       = aws_eks_cluster.sentinel.certificate_authority[0].data
  sensitive   = true
}

output "eks_oidc_provider_arn" {
  description = "OIDC provider ARN for IRSA"
  value       = aws_iam_openid_connect_provider.eks.arn
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.sentinel_postgres.endpoint
}

output "rds_address" {
  description = "RDS PostgreSQL hostname"
  value       = aws_db_instance.sentinel_postgres.address
}

output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = aws_elasticache_replication_group.sentinel.primary_endpoint_address
}

output "redis_reader_endpoint" {
  description = "ElastiCache Redis reader endpoint"
  value       = aws_elasticache_replication_group.sentinel.reader_endpoint_address
}

output "s3_ml_models_bucket" {
  description = "S3 bucket name for ML model storage"
  value       = aws_s3_bucket.ml_models.id
}

output "s3_ml_models_arn" {
  description = "S3 bucket ARN for ML model storage"
  value       = aws_s3_bucket.ml_models.arn
}

output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.sentinel.dns_name
}

output "alb_zone_id" {
  description = "ALB hosted zone ID (for Route 53 alias records)"
  value       = aws_lb.sentinel.zone_id
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.sentinel_vpc.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private_subnets[*].id
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = aws_subnet.public_subnets[*].id
}

output "sns_alerts_topic_arn" {
  description = "SNS topic ARN for CloudWatch alerts"
  value       = aws_sns_topic.sentinel_alerts.arn
}
