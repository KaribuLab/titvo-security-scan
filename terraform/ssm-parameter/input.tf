variable "base_path" {
  type = string
  description = "The base path for the parameters"
}

variable "parameters" {
  type = list(object({
    name = string
    type = string
    value = string
  }))
  description = "The parameters to create"
}

variable "common_tags" {
  type = map(string)
  description = "The common tags to apply to the parameters"
}

