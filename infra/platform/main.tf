locals {
  tags      = { Project = "EDA", Deployment = var.name, ManagedBy = "Terraform" }
  ecs_trust = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_kms_key" "data" {
  description             = "${var.name} storage encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}
resource "aws_kms_key" "audit" {
  description             = "${var.name} audit encryption; separate administration must be configured before production"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}
resource "aws_s3_bucket" "audit" {
  bucket              = var.audit_bucket_name
  object_lock_enabled = true
  force_destroy       = false
  tags                = local.tags
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket     = aws_s3_bucket.audit.id
  depends_on = [aws_s3_bucket_versioning.audit]
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 30
    }
  }
}
resource "aws_s3_bucket_policy" "audit_tls" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid       = "RequireTLS", Effect = "Deny", Principal = "*", Action = "s3:*",
    Resource  = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}
resource "aws_db_subnet_group" "database" {
  name       = var.name
  subnet_ids = var.private_subnet_ids
  tags       = local.tags
}
resource "aws_security_group" "database" {
  name_prefix = "${var.name}-db-"
  description = "PostgreSQL from the designated application security group only"
  vpc_id      = var.vpc_id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.application_security_group_id]
  }
  tags = local.tags
}
resource "aws_db_instance" "database" {
  identifier                    = var.name
  engine                        = "postgres"
  engine_version                = "16"
  instance_class                = var.production_profile ? "db.t4g.medium" : "db.t4g.micro"
  allocated_storage             = 20
  max_allocated_storage         = 100
  storage_type                  = "gp3"
  storage_encrypted             = true
  kms_key_id                    = aws_kms_key.data.arn
  db_name                       = "eda"
  username                      = "eda_bootstrap"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.data.arn
  publicly_accessible           = false
  multi_az                      = var.production_profile
  db_subnet_group_name          = aws_db_subnet_group.database.name
  vpc_security_group_ids        = [aws_security_group.database.id]
  backup_retention_period       = var.production_profile ? 14 : 7
  deletion_protection           = var.production_profile
  skip_final_snapshot           = false
  final_snapshot_identifier     = var.final_snapshot_identifier
  auto_minor_version_upgrade    = true
  copy_tags_to_snapshot         = true
  tags                          = local.tags
}
resource "aws_sqs_queue" "dead_letters" {
  name                      = "${var.name}-dead-letters"
  kms_master_key_id         = aws_kms_key.data.arn
  message_retention_seconds = 1209600
  tags                      = local.tags
}
resource "aws_sqs_queue" "jobs" {
  name                       = "${var.name}-jobs"
  kms_master_key_id          = aws_kms_key.data.arn
  visibility_timeout_seconds = 120
  redrive_policy             = jsonencode({ deadLetterTargetArn = aws_sqs_queue.dead_letters.arn, maxReceiveCount = 3 })
  tags                       = local.tags
}
resource "aws_ecr_repository" "application" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }
  tags = local.tags
}
resource "aws_cloudwatch_log_group" "application" {
  name              = "/eda/${var.name}"
  retention_in_days = 30
  tags              = local.tags
}
resource "aws_ecs_cluster" "application" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = local.tags
}
resource "aws_iam_role" "application" {
  name               = "${var.name}-application"
  assume_role_policy = local.ecs_trust
  tags               = local.tags
}
resource "aws_iam_role" "broker" {
  name               = "${var.name}-broker"
  assume_role_policy = local.ecs_trust
  tags               = local.tags
}
resource "aws_iam_role_policy" "broker_targets" {
  count  = length(var.target_role_arns) > 0 ? 1 : 0
  role   = aws_iam_role.broker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"], Resource = var.target_role_arns }] })
}
resource "aws_iam_role" "collector" {
  name               = "${var.name}-collector"
  assume_role_policy = local.ecs_trust
  tags               = local.tags
}
resource "aws_cloudwatch_metric_alarm" "dead_letters" {
  alarm_name          = "${var.name}-dead-letter-messages"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dead_letters.name }
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  period              = 60
  statistic           = "Maximum"
  treat_missing_data  = "notBreaching"
  tags                = local.tags
}
