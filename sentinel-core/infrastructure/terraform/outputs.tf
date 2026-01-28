# VPC Outputs
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.sentinel_vpc.id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = aws_vpc.sentinel_vpc.cidr_block
}

# Subnet Outputs
output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = aws_subnet.public_subnets[*].id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private_subnets[*].id
}

# Load Balancer Outputs
output "api_load_balancer_dns" {
  description = "DNS name of the API load balancer"
  value       = aws_lb.sentinel_api_lb.dns_name
}

output "api_load_balancer_arn" {
  description = "ARN of the API load balancer"
  value       = aws_lb.sentinel_api_lb.arn
}

output "api_target_group_arn" {
  description = "ARN of the API target group"
  value       = aws_lb_target_group.sentinel_api_tg.arn
}

# Database Outputs
output "rds_subnet_group_name" {
  description = "Name of the RDS subnet group"
  value       = aws_db_subnet_group.sentinel_rds_subnet_group.name
}

# Cache Outputs
output "elasticache_subnet_group_name" {
  description = "Name of the ElastiCache subnet group"
  value       = aws_elasticache_subnet_group.sentinel_redis_subnet_group.name
}

# Internet Gateway Output
output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.sentinel_igw.id
}

# Route Table Output
output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public_rt.id
}
