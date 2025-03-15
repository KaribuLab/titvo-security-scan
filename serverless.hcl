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
  parameter_path = "/tvo/security-scan"
  service_name   = "tvo-github-security-scan"
  service_bucket = "${local.service_name}-${local.region}"
  log_retention  = 7
  common_tags = {
    Project  = "Github Security Scan"
    Customer = "Titvo"
    Team     = "Area Creacion"
    Ambiente = "${local.stages[local.stage].name}"
  }
}
