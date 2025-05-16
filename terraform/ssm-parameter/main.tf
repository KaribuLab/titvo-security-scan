resource "aws_ssm_parameter" "parameters" {
  count     = length(var.parameters)
  name      = "${var.base_path}/${var.parameters[count.index].name}"
  type      = var.parameters[count.index].type
  value     = var.parameters[count.index].value
  overwrite = true
  tags      = var.common_tags
}
