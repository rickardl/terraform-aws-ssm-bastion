# ------------------------------------------------------------------------------
# Resources
# ------------------------------------------------------------------------------

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "ssm_encrypt" {
  description             = "Session Manager KMS key."
  deletion_window_in_days = 30
  policy = data.aws_iam_policy_document.kms_access.json
  tags = merge(
    var.tags,
    {
      "Name" = "${var.name_prefix}-session-manager-kms-key"
    },
  )
}

resource "aws_kms_alias" "ssm_encrypt_alias" {
  name          = "alias/${var.name_prefix}-session-manager-kms-key"
  target_key_id = aws_kms_key.ssm_encrypt.key_id
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

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
    }
    resources = ["*"]
  }

}

resource "aws_cloudwatch_log_group" "session_manager_log_group" {
  name                    = var.cloudwatch_log_group_name
  retention_in_days       = var.cloudwatch_logs_retention
  kms_key_id              = aws_kms_key.ssm_encrypt.arn

  tags = var.tags
}

resource "aws_s3_bucket" "ssm_session_logs_bucket" {

  bucket                  = "${data.aws_caller_identity.current.account_id}-${var.name_prefix}-ssm-session-logs"
  acl                     = "private"
  region                  = data.aws_region.current.name
  force_destroy           = true
   tags = merge(
    var.tags,
    {
      "Name" = "${data.aws_caller_identity.current.account_id}-${var.name_prefix}-ssm-session-logs"
    },
  )

  versioning {
    enabled               = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.ssm_encrypt.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  lifecycle_rule {
    id                    = "archive_after_X_days"
    enabled               = true

    transition {
      days                = var.log_archive_days
      storage_class       = "GLACIER"
    }

    expiration {
      days                = var.log_expire_days
    }
  }

  logging {
    target_bucket         = aws_s3_bucket.ssm_access_logs_bucket.id
    target_prefix         = "log/"
  }

}

resource "aws_s3_bucket_public_access_block" "ssm_session_logs_bucket" {
  bucket                  = aws_s3_bucket.ssm_session_logs_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket" "ssm_access_logs_bucket" {
  bucket = "${data.aws_caller_identity.current.account_id}-${var.name_prefix}-ssm-access-logs"
  acl                     = "log-delivery-write"
  region                  = data.aws_region.current.name
  force_destroy           = true

   tags = merge(
    var.tags,
    {
      "Name" = "${data.aws_caller_identity.current.account_id}-${var.name_prefix}-ssm-access-logs"
    },
  )

  versioning {
    enabled               = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.ssm_encrypt.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  lifecycle_rule {
    id                    = "delete_after_X_days"
    enabled               = true

    expiration {
      days                = var.access_log_expire_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs_bucket" {
  bucket                  = aws_s3_bucket.ssm_access_logs_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
