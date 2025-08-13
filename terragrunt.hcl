locals {
  serverless = read_terragrunt_config(find_in_parent_folders("serverless.hcl"))
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

generate "backend" {
  path      = "backend.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
  terraform {
    backend "s3" {}
  }
EOF
}

remote_state {
  backend = "s3"
  config = {
    bucket                      = "${local.serverless.locals.service_bucket}"
    key                         = "${path_relative_to_include()}/terraform.tfstate"
    region                      = "${local.serverless.locals.region}"
    dynamodb_table              = "${local.serverless.locals.service_bucket}-tfstate-lock"
    skip_region_validation      = true
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
  }
}

inputs = merge(local.serverless.locals)