terraform {
  source = "${get_parent_terragrunt_dir()}/terraform/ecr"
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
  name        = local.registry_name
  common_tags = local.common_tags
}
