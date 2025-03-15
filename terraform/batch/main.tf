data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name               = "${var.name}-batch-exec-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "ecs_instance_role" {
  name = "ecs_${var.name}_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  tags = var.common_tags
}

resource "aws_iam_role_policy_attachment" "ecs_instance_role" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "ecs_instance_role" {
  name = "${var.name}_ecs_role"
  role = aws_iam_role.ecs_instance_role.name
  tags = var.common_tags
}

resource "aws_iam_role" "aws_batch_service_role" {
  name = "${var.name}_batch_service_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "batch.amazonaws.com"
        }
      }
    ]
  })
  tags = var.common_tags
}

resource "aws_iam_role_policy_attachment" "aws_batch_service_role" {
  role       = aws_iam_role.aws_batch_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
}

resource "aws_security_group" "batch" {
  name   = "${var.name}-sg"
  vpc_id = var.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = var.common_tags
}

resource "aws_batch_compute_environment" "batch" {
  compute_environment_name = "${var.name}-env"
  compute_resources {
    max_vcpus = var.max_vcpus
    security_group_ids = [
      aws_security_group.batch.id
    ]
    subnets = var.subnet_ids
    type    = "FARGATE"
  }

  service_role = aws_iam_role.aws_batch_service_role.arn
  type         = "MANAGED"
  depends_on   = [aws_iam_role_policy_attachment.aws_batch_service_role]
  tags         = var.common_tags
}

resource "aws_batch_job_queue" "batch" {
  name     = "${var.name}-job-queue"
  state    = "ENABLED"
  priority = 1
  compute_environment_order {
    order               = 1
    compute_environment = aws_batch_compute_environment.batch.arn
  }
  tags = var.common_tags
}

resource "aws_iam_role" "batch" {
  name = "${var.name}_job_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
  tags = var.common_tags
}

# S3 read/write policy
resource "aws_iam_policy" "batch" {
  name   = "${var.name}-job-policy"
  policy = var.job_policy
  tags   = var.common_tags
}
# Attach the policy to the job role
resource "aws_iam_role_policy_attachment" "batch" {
  role       = aws_iam_role.batch.name
  policy_arn = aws_iam_policy.batch.arn
}

resource "aws_batch_job_definition" "batch" {
  name = "${var.name}-job-definition"
  type = "container"
  platform_capabilities = [
    "FARGATE",
  ]
  container_properties = jsonencode({
    command    = var.job_command,
    image      = "${var.ecr_repository_url}:latest",
    jobRoleArn = "${aws_iam_role.batch.arn}",
    fargatePlatformConfiguration = {
      platformVersion = "LATEST"
    },
    networkConfiguration = {
      assignPublicIp : "ENABLED"
    },
    environment = var.job_environment,
    resourceRequirements = [
      { type = "VCPU", "value" = tostring(var.job_vcpu) },
      { type = "MEMORY", "value" = tostring(var.job_memory) }
    ],
    executionRoleArn = "${aws_iam_role.ecs_task_execution_role.arn}"
  })
  tags = var.common_tags
}