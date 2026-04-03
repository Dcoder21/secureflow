variable "project_name" {
  type    = string
  default = "secureflow"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "services" {
  type    = list(string)
  default = ["auth-service", "transaction-service", "frontend"]
}

# ─────────────────────────────────────────
# ECR Repositories (one per microservice)
# ─────────────────────────────────────────
resource "aws_ecr_repository" "services" {
  for_each = toset(var.services)

  name                 = "${var.project_name}/${each.value}"
  image_tag_mutability = "IMMUTABLE"  # Prevent tag overwriting for supply chain security

  image_scanning_configuration {
    scan_on_push = true  # AWS-native scanning as additional layer
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Service     = each.value
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "terraform"
  }
}

# ─────────────────────────────────────────
# Lifecycle Policy — keep only last 10 images
# ─────────────────────────────────────────
resource "aws_ecr_lifecycle_policy" "cleanup" {
  for_each   = toset(var.services)
  repository = aws_ecr_repository.services[each.key].name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = {
        type = "expire"
      }
    }]
  })
}

# ─────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────
output "repository_urls" {
  value = { for k, v in aws_ecr_repository.services : k => v.repository_url }
}
