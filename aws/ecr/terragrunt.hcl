terraform {
  source = "git::https://github.com/KaribuLab/terraform-aws-ecr.git?ref=v0.2.0"
}

locals {
  serverless    = read_terragrunt_config(find_in_parent_folders("serverless.hcl"))
  registry_name = "${local.serverless.locals.service_name}-ecr-${local.serverless.locals.stage}"
  common_tags   = local.serverless.locals.common_tags
}

include {
  path = find_in_parent_folders()
}

inputs = {
  name                 = local.registry_name
  image_tag_mutability = "MUTABLE"
  lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        action = {
          type = "expire"
        },
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
      }
    ]
  })
  tags = merge(local.common_tags, {
    Name = local.registry_name
  })
}
