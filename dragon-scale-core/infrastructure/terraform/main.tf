terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "s3" {
    bucket         = "dragon-scale-terraform-state"
    key            = "dragon-scale/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "dragon-scale-terraform-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "DRAGON_SCALE"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name_prefix = "${var.environment}-dragon-scale"
  azs         = slice(data.aws_availability_zones.available.names, 0, 3)
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.name
}
