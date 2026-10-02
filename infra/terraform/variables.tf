variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "vpc_id" {
  type = string
}

variable "tenant_account_ids" {
  description = "Customer AWS account IDs that have onboarded remediation"
  type        = list(string)
  default     = []
}
