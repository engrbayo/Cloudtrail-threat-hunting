locals {
  name_prefix = "${var.project_name}-${var.environment}"
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.name

  # Glue / Athena database and table names
  glue_database_name = replace("${local.name_prefix}_cloudtrail", "-", "_")
  glue_table_name    = "cloudtrail_events"

  common_tags = {
    Project     = "CloudTrail-Threat-Hunting-Copilot"
    Environment = var.environment
    ManagedBy   = "Terraform"
    CostCenter  = "SecurityEngineering"
    DataClass   = "Confidential"
  }
}
