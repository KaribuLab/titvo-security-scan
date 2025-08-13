locals {
  region = get_env("AWS_REGION")
  stage  = get_env("AWS_STAGE")
  stages = {
    test = {
      name = "Testing"
    }
    prod = {
      name = "Production"
    }
  }
  provider_version = "6.7.0"
  parameter_path   = get_env("PARAMETER_PATH", "/tvo/security-scan")
  service_name     = get_env("PROJECT_NAME", "tvo-security-scan")
  service_bucket   = get_env("BUCKET_STATE_NAME", "${local.service_name}-${local.region}")
  log_retention    = 7
  tags_file_path   = "${get_terragrunt_dir()}/common_tags.json"
  common_tags = fileexists(local.tags_file_path) ? jsondecode(file(local.tags_file_path)) : {
    Project     = "Titvo Security Scan"
    Customer    = "Titvo"
    Team        = "Area Creacion"
    Environment = "${local.stages[local.stage].name}"
  }
}
