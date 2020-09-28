# ------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------
output "name_prefix" {
  value = var.name_prefix
}

output "tags" {
  value = var.tags
}

output "ssm_session_logs_bucket_name" {
  value = aws_s3_bucket.ssm_session_logs_bucket.id
}

output "ssm_access_logs_bucket_name" {
  value = aws_s3_bucket.ssm_access_logs_bucket.id
}

output "session_manager_log_group_arn" {
  value = aws_cloudwatch_log_group.session_manager_log_group.arn
}

output "kms_key_arn" {
  value = aws_kms_key.ssm_encrypt.arn
}
