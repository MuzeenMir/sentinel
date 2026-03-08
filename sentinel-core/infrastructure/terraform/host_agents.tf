# Host Agent Deployment: hids-agent and hardening-service
#
# These services require direct access to host kernel interfaces (eBPF, /etc, /proc)
# and therefore CANNOT run on Fargate.  They are deployed as systemd services on
# EC2 instances using SSM Run Command and EC2 user-data.
#
# Architecture:
#   EC2 Auto Scaling Group (Amazon Linux 2023, private subnets)
#   → SSM-managed (no SSH ingress required)
#   → Docker installed via user-data
#   → hids-agent and hardening-service containers started at boot

# ── Variables ─────────────────────────────────────────────────────────────────

variable "host_agent_instance_type" {
  description = "EC2 instance type for host-agent nodes"
  type        = string
  default     = "t3.small"
}

variable "host_agent_min_size" {
  description = "Minimum number of host-agent EC2 instances"
  type        = number
  default     = 1
}

variable "host_agent_max_size" {
  description = "Maximum number of host-agent EC2 instances"
  type        = number
  default     = 10
}

variable "host_agent_desired_capacity" {
  description = "Desired number of host-agent EC2 instances"
  type        = number
  default     = 2
}

# ── IAM ───────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "host_agent" {
  name = "${var.environment}-sentinel-host-agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

resource "aws_iam_role_policy_attachment" "host_agent_ssm" {
  role       = aws_iam_role.host_agent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "host_agent_ecr" {
  role       = aws_iam_role.host_agent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy" "host_agent_secrets" {
  name = "${var.environment}-sentinel-host-agent-secrets"
  role = aws_iam_role.host_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.redis_auth.arn]
    }]
  })
}

resource "aws_iam_instance_profile" "host_agent" {
  name = "${var.environment}-sentinel-host-agent-profile"
  role = aws_iam_role.host_agent.name

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }
}

# ── Security Group ────────────────────────────────────────────────────────────

resource "aws_security_group" "host_agent" {
  name        = "${var.environment}-sentinel-host-agent-sg"
  description = "Security group for SENTINEL host-agent EC2 instances"
  vpc_id      = aws_vpc.sentinel_vpc.id

  # No inbound SSH — use SSM Session Manager only
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound (required for SSM, ECR, Kafka, Redis)"
  }

  tags = {
    Name        = "${var.environment}-sentinel-host-agent-sg"
    Environment = var.environment
  }
}

# ── AMI data source ───────────────────────────────────────────────────────────

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ── Launch Template ───────────────────────────────────────────────────────────

resource "aws_launch_template" "host_agent" {
  name_prefix   = "${var.environment}-sentinel-host-agent-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = var.host_agent_instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.host_agent.name
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.host_agent.id]
  }

  # IMDSv2 only (security hardening)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  monitoring { enabled = true }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  user_data = base64encode(templatefile("${path.module}/templates/host_agent_userdata.sh.tpl", {
    aws_region           = var.aws_region
    environment          = var.environment
    kafka_bootstrap      = aws_msk_cluster.sentinel.bootstrap_brokers_tls
    redis_address        = aws_elasticache_replication_group.sentinel_redis.primary_endpoint_address
    ecr_base_url         = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
    hids_image           = "${aws_ecr_repository.sentinel_services["hids-agent"].repository_url}:latest"
    hardening_image      = "${aws_ecr_repository.sentinel_services["hardening-service"].repository_url}:latest"
    redis_secret_arn     = aws_secretsmanager_secret.redis_auth.arn
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "${var.environment}-sentinel-host-agent"
      Environment = var.environment
      Project     = "SENTINEL"
      Role        = "host-agent"
    }
  }

  tags = {
    Environment = var.environment
    Project     = "SENTINEL"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ── Auto Scaling Group ────────────────────────────────────────────────────────

resource "aws_autoscaling_group" "host_agent" {
  name_prefix         = "${var.environment}-sentinel-host-agent-"
  vpc_zone_identifier = aws_subnet.private_subnets[*].id
  min_size            = var.host_agent_min_size
  max_size            = var.host_agent_max_size
  desired_capacity    = var.host_agent_desired_capacity

  launch_template {
    id      = aws_launch_template.host_agent.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.environment}-sentinel-host-agent"
    propagate_at_launch = true
  }
  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }
  tag {
    key                 = "Project"
    value               = "SENTINEL"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [desired_capacity]
  }
}
