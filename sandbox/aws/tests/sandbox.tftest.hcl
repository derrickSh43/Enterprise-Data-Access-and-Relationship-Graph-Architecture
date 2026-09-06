mock_provider "aws" {}
override_data {
  target = data.aws_ssm_parameter.ami
  values = { value = "ami-0123456789abcdef0" }
}
override_data {
  target = data.aws_availability_zones.available
  values = { names = ["us-east-1a"] }
}
variables {
  expected_account_id   = "123456789012"
  trusted_principal_arn = "arn:aws:iam::123456789012:role/local-sandbox-login"
}
run "small_private_sandbox" {
  command = plan
  assert {
    condition     = aws_ec2_instance_state.test.state == "stopped" && !aws_instance.test.associate_public_ip_address
    error_message = "Default target must be stopped and private."
  }
  assert {
    condition     = length(aws_security_group.isolated.ingress) == 0 && length(aws_security_group.isolated.egress) == 0
    error_message = "Inspection target requires no network traffic."
  }
  assert {
    condition     = aws_instance.test.credit_specification[0].cpu_credits == "standard" && aws_instance.test.root_block_device[0].encrypted
    error_message = "Avoid surplus CPU charges and encrypt the test disk."
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.test.block_public_policy && !aws_s3_bucket.test.force_destroy
    error_message = "Keep bucket private and do not erase unknown objects."
  }
  assert {
    condition     = alltrue([for statement in jsondecode(aws_iam_role_policy.metadata.policy).Statement : alltrue([for action in statement.Action : contains(["s3:ListAllMyBuckets", "iam:ListRoles", "ec2:DescribeInstances", "ec2:DescribeSecurityGroups"], action)])])
    error_message = "Collector must only have declared metadata reads."
  }
}
run "reject_root_trust" {
  command = plan
  variables { trusted_principal_arn = "arn:aws:iam::123456789012:root" }
  expect_failures = [var.trusted_principal_arn]
}
