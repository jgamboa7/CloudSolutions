variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}

variable "eksAdmin" {
  description = "ARN value of the Cluster Admin"
  type        = string
  sensitive   = true
}