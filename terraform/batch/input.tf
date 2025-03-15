variable "subnet_ids" {
  type = list(string)
}

variable "common_tags" {
  type = map(any)
}

variable "name" {
  type = string
}

variable "max_vcpus" {
  type = number
}


variable "job_vcpu" {
  type = number
}

variable "job_environment" {
  type = list(map(string))
  default = []
}

variable "job_memory" {
  type = number
}

variable "job_command" {
  type = list(string)
}

variable "vpc_id" {
  type = string
}

variable "job_policy" {
  type = string
}

variable "ecr_repository_url" {
  type = string
}
