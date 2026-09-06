mock_provider "aws" {}
variables {
  region                        = "us-east-1"
  name                          = "eda-test"
  vpc_id                        = "vpc-12345678"
  private_subnet_ids            = ["subnet-12345678", "subnet-87654321"]
  application_security_group_id = "sg-12345678"
  audit_bucket_name             = "eda-test-audit-fixture"
  final_snapshot_identifier     = "eda-test-final-fixture"
}
run "private_encrypted_foundation" {
  command = plan
  assert {
    condition     = aws_db_instance.database.storage_encrypted && !aws_db_instance.database.publicly_accessible
    error_message = "Database must be encrypted and private."
  }
  assert {
    condition     = aws_db_instance.database.manage_master_user_password && !aws_db_instance.database.skip_final_snapshot
    error_message = "Use managed credentials and preserve final snapshots."
  }
  assert {
    condition     = aws_s3_bucket.audit.object_lock_enabled && !aws_s3_bucket.audit.force_destroy
    error_message = "Audit evidence must be retained."
  }
  assert {
    condition     = length(aws_iam_role_policy.broker_targets) == 0
    error_message = "Broker receives no default target authority."
  }
}
run "production_database_resilience" {
  command = plan
  variables { production_profile = true }
  assert {
    condition     = aws_db_instance.database.multi_az && aws_db_instance.database.deletion_protection
    error_message = "Production data must enable redundancy and deletion protection."
  }
}
run "reject_single_subnet" {
  command = plan
  variables { private_subnet_ids = ["subnet-12345678"] }
  expect_failures = [var.private_subnet_ids]
}
