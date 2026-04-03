terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "secureflow-terraform-state"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "secureflow-terraform-lock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "secureflow"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}

# ─────────────────────────────────────────
# Variables
# ─────────────────────────────────────────
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

# ─────────────────────────────────────────
# Modules
# ─────────────────────────────────────────
module "vpc" {
  source = "../../modules/vpc"

  project_name       = "secureflow"
  environment        = "dev"
  vpc_cidr           = "10.0.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b"]
}

module "eks" {
  source = "../../modules/eks-cluster"

  project_name       = "secureflow"
  environment        = "dev"
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  kubernetes_version = "1.29"
  node_instance_types = ["t3.medium"]
  node_desired_size  = 2
}

module "ecr" {
  source = "../../modules/ecr"

  project_name = "secureflow"
  environment  = "dev"
  services     = ["auth-service", "transaction-service", "frontend"]
}

# ─────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────
output "cluster_name" {
  value = module.eks.cluster_name
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "ecr_repositories" {
  value = module.ecr.repository_urls
}

output "configure_kubectl" {
  value = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}
