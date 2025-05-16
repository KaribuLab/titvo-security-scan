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
      "/tvo/security-scan/test/infra/vpc-id"                      = "vpc-000000000000000"
      "/tvo/security-scan/test/infra/subnet1"                     = "subnet-0c4b3b6b1b7b3b3b3"
      "/tvo/security-scan/test/infra/dynamo-task-table-arn"       = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-task-table-test"
      "/tvo/security-scan/test/infra/dynamo-repository-table-arn" = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-repository-table-test"
      "/tvo/security-scan/test/infra/dynamo-hint-table-arn"       = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-hint-table-test"
      "/tvo/security-scan/test/infra/dynamo-cli-files-table-arn"  = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-cli-files-table-test"
      "/tvo/security-scan/test/infra/dynamo-prompt-table-arn"     = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-prompt-table-test"
      "/tvo/security-scan/test/infra/encryption-key-name"         = "/tvo/security-scan/test/infra/encryption-key"
      "/tvo/security-scan/prod/infra/vpc-id"                      = "vpc-000000000000000"
      "/tvo/security-scan/prod/infra/subnet1"                     = "subnet-0c4b3b6b1b7b3b3b3"
      "/tvo/security-scan/prod/infra/dynamo-task-table-arn"       = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-task-table-prod"
      "/tvo/security-scan/prod/infra/secret-manager-arn"          = "arn:aws:secretsmanager:us-east-1:000000000000:secret:/tvo/security-scan/prod",
      "/tvo/security-scan/prod/infra/report-bucket-arn"           = "arn:aws:s3:::devsecops-titvo-com-report-bucket"
      "/tvo/security-scan/prod/infra/dynamo-cli-files-table-arn"  = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-cli-files-table-prod"
      "/tvo/security-scan/prod/infra/dynamo-prompt-table-arn"     = "arn:aws:dynamodb:us-east-1:000000000000:table/tvo-github-security-scan-prompt-table-prod"
      "/tvo/security-scan/prod/infra/encryption-key-name"         = "/tvo/security-scan/prod/infra/encryption-key"
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
  job_command        = ["python", "/app/container_runner.py"]
  vpc_id             = dependency.parameters.outputs.parameters["${local.base_path}/infra/vpc-id"]
  job_environment = [
    {
      name : "TITVO_DYNAMO_TASK_TABLE_NAME",
      value : dependency.parameters.outputs.parameters["${local.base_path}/infra/dynamo-task-table-name"]
    },
    {
      name  = "TITVO_DYNAMO_CONFIGURATION_TABLE_NAME"
      value = dependency.parameters.outputs.parameters["${local.base_path}/infra/dynamo-configuration-table-name"]
    },
    {
      name  = "TITVO_DYNAMO_HINT_TABLE_NAME"
      value = dependency.parameters.outputs.parameters["${local.base_path}/infra/dynamo-hint-table-name"]
    },
    {
      name  = "TITVO_DYNAMO_CLI_FILES_TABLE_NAME"
      value = dependency.parameters.outputs.parameters["${local.base_path}/infra/dynamo-cli-files-table-name"]
    },
    {
      name  = "TITVO_DYNAMO_CLI_FILES_BUCKET_NAME"
      value = dependency.parameters.outputs.parameters["${local.base_path}/infra/cli-files-bucket-name"]
    },
    {
      name  = "TITVO_ENCRYPTION_KEY_NAME"
      value = dependency.parameters.outputs.parameters["${local.base_path}/infra/encryption-key-name"]
    }
  ]
  job_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
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
          "dynamodb:GetItem",
        ],
        "Resource" : [
          dependency.parameters.outputs.parameters["${local.base_path}/infra/dynamo-repository-table-arn"],
          dependency.parameters.outputs.parameters["${local.base_path}/infra/dynamo-configuration-table-arn"],
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "dynamodb:Query"
        ],
        "Resource" : [
          dependency.parameters.outputs.parameters["${local.base_path}/infra/dynamo-cli-files-table-arn"],
          "${dependency.parameters.outputs.parameters["${local.base_path}/infra/dynamo-cli-files-table-arn"]}/index/*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket"
        ],
        "Resource" : [
          dependency.parameters.outputs.parameters["${local.base_path}/infra/cli-files-bucket-arn"],
          "${dependency.parameters.outputs.parameters["${local.base_path}/infra/cli-files-bucket-arn"]}/*"
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
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:PutObjectTagging"
        ],
        "Resource" : [
          dependency.parameters.outputs.parameters["${local.base_path}/infra/report-bucket-arn"],
          "${dependency.parameters.outputs.parameters["${local.base_path}/infra/report-bucket-arn"]}/*"
        ]
      }
    ]
  })
}
