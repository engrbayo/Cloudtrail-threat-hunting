# ─────────────────────────────────────────────────────────────────────────────
# SSM Parameter Store — secure configuration under /security/ai/threat-hunting/
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_ssm_parameter" "bedrock_model_id" {
  name        = "/security/ai/threat-hunting/bedrock-model-id"
  description = "Bedrock model ID used by the Copilot Lambda"
  type        = "String"
  value       = var.bedrock_model_id
  tags        = { Name = "bedrock-model-id" }
}

resource "aws_ssm_parameter" "athena_database" {
  name        = "/security/ai/threat-hunting/athena-database"
  description = "Glue/Athena database name for CloudTrail logs"
  type        = "String"
  value       = local.glue_database_name
  tags        = { Name = "athena-database" }
}

resource "aws_ssm_parameter" "athena_workgroup" {
  name        = "/security/ai/threat-hunting/athena-workgroup"
  description = "Athena workgroup name"
  type        = "String"
  value       = aws_athena_workgroup.copilot.name
  tags        = { Name = "athena-workgroup" }
}

resource "aws_ssm_parameter" "api_gateway_url" {
  name        = "/security/ai/threat-hunting/api-gateway-url"
  description = "API Gateway invoke URL for the Streamlit UI"
  type        = "String"
  value       = "https://${aws_api_gateway_rest_api.copilot.id}.execute-api.${local.region}.amazonaws.com/${var.environment}"
  tags        = { Name = "api-gateway-url" }
}

resource "aws_ssm_parameter" "cloudtrail_logs_bucket" {
  name        = "/security/ai/threat-hunting/cloudtrail-logs-bucket"
  description = "S3 bucket name containing CloudTrail logs"
  type        = "String"
  value       = aws_s3_bucket.cloudtrail_logs.id
  tags        = { Name = "cloudtrail-logs-bucket" }
}

resource "aws_ssm_parameter" "audit_bucket" {
  name        = "/security/ai/threat-hunting/audit-bucket"
  description = "S3 bucket name for audit outputs, Athena results, analyses"
  type        = "String"
  value       = aws_s3_bucket.audit.id
  tags        = { Name = "audit-bucket" }
}

resource "aws_ssm_parameter" "sns_topic_arn" {
  name        = "/security/ai/threat-hunting/sns-topic-arn"
  description = "SNS topic ARN for threat hunt alert notifications"
  type        = "String"
  value       = aws_sns_topic.hunt_alerts.arn
  tags        = { Name = "sns-topic-arn" }
}

resource "aws_ssm_parameter" "ecr_repo_url" {
  name        = "/security/ai/threat-hunting/ecr-repo-url"
  description = "ECR repository URL for the Streamlit container image"
  type        = "String"
  value       = aws_ecr_repository.streamlit.repository_url
  tags        = { Name = "ecr-repo-url" }
}
