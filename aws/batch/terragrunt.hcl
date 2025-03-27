terraform {
  source = "${get_parent_terragrunt_dir()}/terraform/batch"
}

locals {
  serverless  = read_terragrunt_config(find_in_parent_folders("serverless.hcl"))
  batch_name  = "${local.serverless.locals.service_name}-batch-${local.serverless.locals.stage}"
  common_tags = local.serverless.locals.common_tags
  base_path   = "${local.serverless.locals.parameter_path}/${local.serverless.locals.stage}"
}

include {
  path = find_in_parent_folders()
}

dependency ecr {
  config_path = "${get_parent_terragrunt_dir()}/aws/ecr"
  mock_outputs = {
    ecr_repository_url = "00000000000.dkr.ecr.us-east-1.amazonaws.com/tvo-github-security-scan-test"
  }
}

dependency parameters {
  config_path = "${get_parent_terragrunt_dir()}/aws/parameter"
  mock_outputs = {
    parameters = {
      "/tvo/security-scan/test/infra/vpc-id"                = "vpc-000000000000000"
      "/tvo/security-scan/test/infra/subnet1"               = "subnet-0c4b3b6b1b7b3b3b3"
      "/tvo/security-scan/test/infra/dynamo-task-table-arn" = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-task-table-test"
      "/tvo/security-scan/prod/infra/vpc-id"                = "vpc-000000000000000"
      "/tvo/security-scan/prod/infra/subnet1"               = "subnet-0c4b3b6b1b7b3b3b3"
      "/tvo/security-scan/prod/infra/dynamo-task-table-arn" = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-task-table-prod"
      "/tvo/security-scan/prod/infra/secret-manager-arn"    = "arn:aws:secretsmanager:us-east-1:000000000000:secret:/tvo/security-scan/prod"
    }
  }
}

inputs = {
  subnet_ids = [
    dependency.parameters.outputs.parameters["${local.base_path}/infra/subnet1"],
  ]
  name               = local.batch_name
  common_tags        = local.common_tags
  ecr_repository_url = dependency.ecr.outputs.ecr_repository_url
  max_vcpus          = 16
  job_vcpu           = 2
  job_memory         = 4096
  job_command        = ["python", "main.py"]
  vpc_id             = dependency.parameters.outputs.parameters["${local.base_path}/infra/vpc-id"]
  job_environment = [
    {
      name : "AWS_STAGE",
      value : local.serverless.locals.stage
    }
  ]
  job_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ssm:GetParameter",
        ],
        "Resource" : [
          "arn:aws:ssm:*:*:parameter${local.base_path}/task-trigger*",
          "arn:aws:ssm:*:*:parameter${local.base_path}/github-security-scan*",
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
        ],
        "Resource" : [
          dependency.parameters.outputs.parameters["${local.base_path}/infra/dynamo-task-table-arn"],
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "secretsmanager:GetSecretValue"
        ],
        "Resource" : [
          "arn:aws:secretsmanager:*:*:secret:/tvo/security-scan/prod*"
        ]
      }
    ]
  })
}
