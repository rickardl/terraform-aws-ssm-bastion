variable "log_archive_days" {
  description = "Number of days to wait before archiving to Glacier"
  type        = number
  default     = 30
}

variable "log_expire_days" {
  description = "Number of days to wait before deleting"
  type        = number
  default     = 365
}

variable "access_log_expire_days" {
  description = "Number of days to wait before deleting access logs"
  type        = number
  default     = 30
}

variable "name_prefix" {
  description = "A prefix used for naming resources."
  type        = string
}

variable "tags" {
  description = "A map of tags (key-value pairs) passed to resources."
  type        = map(string)
  default     = {}
}


variable "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for storing SSM Session Logs"
  type        = string
  default     = "/ssm/session-logs"
}

variable "cloudwatch_logs_retention" {
  description = "Number of days to retain Session Logs in CloudWatch"
  type        = number
  default     = 30
}

variable "ssm_session_logs_bucket" {
  description = "Name of S3 bucket to store session logs"
  type        = string
  default  = "ssm-session-logs"
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
