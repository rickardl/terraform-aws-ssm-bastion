# ------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------

output "name_prefix" {
  value = module.baseline.name_prefix
}

output "session_logs_bucket_name" {
  value = module.baseline.ssm_session_logs_bucket_name
}

output "access_log_bucket_name" {
  value = module.baseline.ssm_access_log_bucket_name
}

output "cloudwatch_log_group_arn" {
  value = module.baseline.session_manager_log_group_arn
}

output "kms_key_arn" {
  value = module.baseline.kms_key_arn
}
