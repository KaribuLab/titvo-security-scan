resource "aws_ecr_repository" "ecr" {
  name = var.name
  image_tag_mutability = "MUTABLE"
  tags = var.common_tags
}

resource "aws_ecr_lifecycle_policy" "ecr" {
  repository = aws_ecr_repository.ecr.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Mantener ultimas 10 imagenes"
      action = {
        type = "expire"
      }
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
    }]
  })
}