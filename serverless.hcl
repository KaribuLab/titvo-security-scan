locals {
  region        = get_env("AWS_REGION")
  stage         = get_env("AWS_STAGE")
  account_id    = get_env("AWS_ACCOUNT_ID", "")
  bucket_suffix = local.account_id == "" ? "" : "-${local.account_id}"
  stages = {
    test = {
      name = "Testing"
    }
    prod = {
      name = "Production"
    }
  }
  provider_version = "6.7.0"
  parameter_path   = "/tvo/security-scan"
  service_name     = "tvo-security-scan"
  service_bucket   = "${local.service_name}-${local.region}${local.bucket_suffix}"
  log_retention    = 7
  tags_file_path   = "${get_terragrunt_dir()}/common_tags.json"
  common_tags = fileexists(local.tags_file_path) ? jsondecode(file(local.tags_file_path)) : {
    Project = "Titvo Security Scan Runner"
  }
}
