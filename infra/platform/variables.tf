variable "region" { type = string }
variable "name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.name))
    error_message = "Use 3-25 lowercase letters, digits or hyphens."
  }
}
variable "vpc_id" { type = string }
variable "private_subnet_ids" {
  type = list(string)
  validation {
    condition     = length(distinct(var.private_subnet_ids)) >= 2
    error_message = "At least two private subnets in distinct availability zones are required."
  }
}
variable "application_security_group_id" {
  description = "Existing private application security group permitted to connect to PostgreSQL."
  type        = string
}
variable "audit_bucket_name" { type = string }
variable "production_profile" {
  type    = bool
  default = false
}
variable "final_snapshot_identifier" { type = string }
variable "target_role_arns" {
  type    = list(string)
  default = []
}
