# ------------------------------------------------------------------------------
# Variables
# ------------------------------------------------------------------------------
variable "name_prefix" {
  description = "A prefix used for naming resources."
  type        = string
}

variable "tags" {
  description = "A map of tags (key-value pairs) passed to resources."
  type        = map(string)
  default     = {}
}

variable "bucket_name" {
  description = "Name of S3 bucket to store session logs"
  type        = string
}

variable "kms_key_deletion_window" {
  description = "Waiting period for scheduled KMS Key deletion.  Can be 7-30 days."
  type        = number
  default     = 7
}

variable "kms_key_alias" {
  description = "Alias of the KMS key.  Must start with alias/ followed by a name"
  type        = string
  default     = "alias/ssm-key"
}

variable "cloudwatch_logs_retention" {
  description = "Number of days to retain Session Logs in CloudWatch"
  type        = number
  default     = 30
}

variable "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for storing SSM Session Logs"
  type        = string
  default     = "/ssm/session-logs"
}

variable "vpc_id" {
  description = "VPC ID to deploy endpoints into"
  type        = string
  default     = null
}

variable "enable_log_to_s3" {
  description = "Enable Session Manager to Log to S3"
  type        = bool
  default     = true
}

variable "enable_log_to_cloudwatch" {
  description = "Enable Session Manager to Log to CloudWatch Logs"
  type        = bool
  default     = true
}

variable "vpc_endpoints_enabled" {
  description = "Create VPC Endpoints"
  type        = bool
  default     = false
}
