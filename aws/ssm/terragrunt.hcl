terraform {
  source = "${get_parent_terragrunt_dir()}/terraform/ssm-parameter"
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

include {
  path = find_in_parent_folders()
}

inputs = {
  base_path   = local.base_path
  common_tags = local.common_tags
  parameters = [
    {
      name  = "security-scan-batch-arn"
      type  = "String"
      value = dependency.batch.outputs.job_definition_arn
    },
    {
      name  = "security-scan-job-queue-arn"
      type  = "String"
      value = dependency.batch.outputs.job_queue_arn
    }
  ]
}