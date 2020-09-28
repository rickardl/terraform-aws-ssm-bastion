# ------------------------------------------------------------------------------
# Resources
# ------------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_kms_key" "ssmkey" {
    name = var.kms_key_id
}

data "aws_iam_policy_document" "kms_access" {
  statement {
    sid = "KMS Key Default"
    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = [
      "kms:*",
    ]

    resources = ["*"]

  }

  statement {
    sid = "CloudWatchLogsEncryption"
    principals {
      type = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]

    resources = ["*"]
  }

}

data "aws_iam_policy_document" "ssm_s3_cloudwatch_log_access" {
  # A custom policy for S3 bucket access
  # https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/setup-instance-profile.html#instance-profile-custom-s3-policy
  statement {
    sid = "S3BucketAccessForSessionManager"

    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:PutObjectVersionAcl",
    ]

    resources = [
      "${var.session_logs_bucket_arn}",
      "${var.session_logs_bucket_arn}/*",
    ]
  }

  statement {
    sid = "S3EncryptionForSessionManager"

    actions = [
      "s3:GetEncryptionConfiguration",
    ]

    resources = [
      "${aws_s3_bucket.session_logs_bucket.arn}",
    ]
  }


  # A custom policy for CloudWatch Logs access
  # https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/permissions-reference-cwl.html
  statement {
    sid = "CloudWatchLogsAccessForSessionManager"

    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]

    resources = ["*"]
  }

  statement {
    sid = "KMSEncryptionForSessionManager"

    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:Encrypt",
    ]

    resources = ["${aws_kms_key.ssmkey.arn}"]
  }

}

resource "aws_iam_policy" "ssm_s3_cloudwatch_log_access" {
  name       = "ssm_s3_cloudwatch_log_access"
  path       = "/"
  policy     = data.aws_iam_policy_document.ssm_s3_cwl_access.json
}

resource "aws_iam_role_policy_attachment" "ssm_s3_cwl_policy_attach" {
  role       = module.asg.role_name
  policy_arn = aws_iam_policy.ssm_s3_cloudwatch_log_access.arn
}

resource "aws_iam_instance_profile" "ssm_profile" {
  name       = "ssm_profile"
  role       = module.asg.role_name
}

# Create VPC Endpoints For Session Manager
resource "aws_security_group" "main" {
  count               = var.vpc_endpoints_enabled ? 1 : 0
  name                = "ssm-sg"
  description         = "Allow TLS inbound To AWS Systems Manager Session Manager"
  vpc_id              = var.vpc_id

  ingress {
    description       = "HTTPS from VPC"
    from_port         = 443
    to_port           = 443
    protocol          = "tcp"
    cidr_blocks       = [var.vpc_endpoints_cidr]
  }

  egress {
    description       = "Allow All Egress"
    from_port         = 0
    to_port           = 0
    protocol          = "-1"
    cidr_blocks       = ["0.0.0.0/0"]
  }
  tags                = var.tags

lifecycle {
    create_before_destroy = true
  }
}

resource "aws_ssm_document" "session_manager_prefs" {
  name                    = "SSM-SessionManagerRunShell"
  document_type           = "Session"
  document_format         = "JSON"
  target_type = "AWS::EC2::Instance"
 tags = merge(
    var.tags,
    {
      "Name" = "${var.name_prefix}-session-manager-prefs"
    },
  )
  content = jsonencode({
    "schemaVersion" = "1.0"
    "description" = "Document to hold regional settings for Session Manager"
    "sessionType" = "Standard_Stream"
    "inputs" = {
        "s3BucketName" = "${var.enable_log_to_s3 ? aws_s3_bucket.ssm_session_logs_bucket.id : ""}"
        "s3EncryptionEnabled" = "${var.enable_log_to_s3 ? "true" : "false"}"
        "cloudWatchLogGroupName" = "${var.enable_log_to_cloudwatch ? var.cloudwatch_log_group_name : "" }"
        "cloudWatchEncryptionEnabled" = "${var.enable_log_to_cloudwatch ? "true" : "false"}"
        "kmsKeyId" = aws_kms_key.ssm_encrypt.key_id
    }
  })
}


resource "aws_ssm_association" "session_manager_prefs" {
  name = "${aws_ssm_document.session_manager_prefs.name}"

  targets = {
    key    = "tag:ManagedSSM"
    values = ["true"]
  }
}

module "asg" {
  source  = "telia-oss/asg/aws"
  version = "3.3.0"

  name_prefix          = "${var.name_prefix}-asg"
  vpc_id               = var.vpc_id
  subnet_ids           = var.subnet_ids
  instance_ami         = var.instance_ami
  instance_type        = var.instance_type
  instance_volume_size = var.instance_volume_size
  min_size             = 1
  max_size             = 1
 tags = merge(
    var.tags,
    {
      "Name" = "${var.name_prefix}-session-manager-prefs"
    },
  )
}

resource "aws_security_group_rule" "allow_all_ping" {
  security_group_id = module.asg.security_group_id
  type              = "ingress"
  protocol          = "icmp"
  from_port         = 8
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
}

module "ssm_agent_policy" {
  source  = "telia-oss/ssm-agent-policy/aws"
  version = "3.0.0"

  name_prefix = "${var.name_prefix}-ssm-policy"
  role        = module.asg.role_name
}
