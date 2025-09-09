terraform {
  source = "git::https://github.com/KaribuLab/terraform-aws-parameter-upsert.git?ref=v0.5.1"
}

locals {
  serverless  = read_terragrunt_config(find_in_parent_folders("serverless.hcl"))
  base_path   = "${local.serverless.locals.parameter_path}/${local.serverless.locals.stage}/infra"
  common_tags = local.serverless.locals.common_tags
}

dependency "batch" {
  config_path = "${get_parent_terragrunt_dir()}/aws/batch"
  mock_outputs = {
    job_definition_arn = "arn:aws:batch:us-east-1:012345678901:job-definition/security-scan-batch-arn"
    job_queue_arn      = "arn:aws:batch:us-east-1:012345678901:job-queue/security-scan-job-queue-arn"
  }
}

dependency "ecr" {
  config_path = "${get_parent_terragrunt_dir()}/aws/ecr"
  mock_outputs = {
    ecr_repository_url = "012345678901.dkr.ecr.us-east-1.amazonaws.com"
    ecr_repository_arn = "arn:aws:ecr:us-east-1:012345678901:repository/security-scan-repository"
  }
}


include {
  path = find_in_parent_folders()
}

inputs = {
  base_path      = local.base_path
  binary_version = "v0.5.5"
  tags           = local.common_tags
  parameters = [
    {
      path        = "security-scan-batch-arn"
      type        = "String"
      tier        = "Standard"
      description = "Security Scan Batch ARN"
      value       = join(":", slice(split(":", dependency.batch.outputs.job_definition_arn), 0, length(split(":", dependency.batch.outputs.job_definition_arn)) - 1))
    },
    {
      path        = "security-scan-job-queue-arn"
      type        = "String"
      tier        = "Standard"
      description = "Security Scan Job Queue ARN"
      value       = dependency.batch.outputs.job_queue_arn
    },
    {
      path        = "ecr-registry-url"
      type        = "String"
      tier        = "Standard"
      description = "ECR Registry URL"
      value       = dependency.ecr.outputs.ecr_repository_url
    },
    {
      path        = "ecr-registry-arn"
      type        = "String"
      tier        = "Standard"
      description = "ECR Repository ARN"
      value       = dependency.ecr.outputs.ecr_repository_arn
    }
  ]
}
