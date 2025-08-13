terraform {
  source = "git::https://github.com/KaribuLab/terraform-aws-parameter-lookup.git?ref=v0.1.0"
  extra_arguments "disable_backend" {
    commands  = ["init"]
    arguments = ["-backend=false"]
  }
}

locals {
  serverless = read_terragrunt_config(find_in_parent_folders("serverless.hcl"))
  base_path  = "${local.serverless.locals.parameter_path}/${local.serverless.locals.stage}"
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
  terraform {
    required_providers {
      aws = {
        source  = "hashicorp/aws"
        version = "${local.serverless.locals.provider_version}"
      }
    }
  }
  provider "aws" {
    region = "${local.serverless.locals.region}"
  }
EOF
}

inputs = {
  base_path = local.base_path
}
