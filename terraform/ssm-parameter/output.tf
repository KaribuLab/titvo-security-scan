output "parameters" {
  value = aws_ssm_parameter.parameters
  sensitive = true
  description = "The parameters created"
}
