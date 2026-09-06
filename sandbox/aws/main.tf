terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
variable "region" {
  type    = string
  default = "us-east-1"
}
variable "expected_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Supply the 12-digit sandbox account ID."
  }
}
variable "name" {
  type    = string
  default = "eda-sandbox"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.name))
    error_message = "Use 3-25 lowercase letters, digits and hyphens."
  }
}
variable "trusted_principal_arn" {
  description = "Existing IAM user/role used by your local short-lived session; not a root or STS session ARN."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:(role|user)/.+$", var.trusted_principal_arn))
    error_message = "Use an explicit IAM user or role ARN."
  }
}
variable "run_instance" {
  description = "False stops the instance while retaining its charged disk."
  type        = bool
  default     = false
}
provider "aws" {
  region              = var.region
  allowed_account_ids = [var.expected_account_id]
  default_tags { tags = { Project = "EDA", Environment = "sandbox" } }
}
data "aws_ssm_parameter" "ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}
data "aws_availability_zones" "available" { state = "available" }
resource "aws_vpc" "sandbox" {
  cidr_block = "10.87.0.0/24"
}
resource "aws_subnet" "sandbox" {
  vpc_id                  = aws_vpc.sandbox.id
  cidr_block              = "10.87.0.0/26"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
}
resource "aws_security_group" "isolated" {
  name_prefix = "${var.name}-"
  description = "Inspection target only; no ingress or egress"
  vpc_id      = aws_vpc.sandbox.id
  ingress     = []
  egress      = []
}
resource "aws_instance" "test" {
  ami                         = data.aws_ssm_parameter.ami.value
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.sandbox.id
  vpc_security_group_ids      = [aws_security_group.isolated.id]
  associate_public_ip_address = false
  credit_specification { cpu_credits = "standard" }
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }
  tags = { Name = "${var.name}-inspection-target" }
  lifecycle { ignore_changes = [ami] }
}
resource "aws_ec2_instance_state" "test" {
  instance_id = aws_instance.test.id
  state       = var.run_instance ? "running" : "stopped"
}
resource "aws_s3_bucket" "test" {
  bucket        = "${var.name}-${var.expected_account_id}-${var.region}"
  force_destroy = false
}
resource "aws_s3_bucket_public_access_block" "test" {
  bucket                  = aws_s3_bucket.test.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "test" {
  bucket = aws_s3_bucket.test.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.test.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Deny", Principal = "*", Action = "s3:*",
    Resource  = [aws_s3_bucket.test.arn, "${aws_s3_bucket.test.arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}
resource "aws_s3_object" "sample" {
  bucket       = aws_s3_bucket.test.id
  key          = "samples/fake-record.json"
  content_type = "application/json"
  content      = jsonencode({ synthetic = true, customer = "Example", value = 42 })
}
resource "aws_iam_role" "collector" {
  name                 = "${var.name}-metadata-reader"
  max_session_duration = 3600
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { AWS = var.trusted_principal_arn }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_iam_role_policy" "metadata" {
  name = "${var.name}-metadata-read"
  role = aws_iam_role.collector.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:ListAllMyBuckets", "iam:ListRoles"], Resource = "*" },
    { Effect = "Allow", Action = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"], Resource = "*",
    Condition = { StringEquals = { "aws:RequestedRegion" = var.region } } }
  ] })
}
output "local_settings" {
  value = {
    AWS_REGION             = var.region
    AWS_EXPECTED_ACCOUNT   = var.expected_account_id
    AWS_COLLECTOR_ROLE_ARN = aws_iam_role.collector.arn
    AWS_TEST_INSTANCE_ID   = aws_instance.test.id
    AWS_TEST_BUCKET        = aws_s3_bucket.test.id
  }
}
