# ─────────────────────────────────────────────────────────────────────────────
# Outputs — reference values needed for CI/CD, Streamlit config, and operations
# ─────────────────────────────────────────────────────────────────────────────

# ── Networking ───────────────────────────────────────────────────────────────
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (Lambda, ECS)"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "Public subnet IDs (ALB)"
  value       = aws_subnet.public[*].id
}

# ── S3 ───────────────────────────────────────────────────────────────────────
output "cloudtrail_logs_bucket" {
  description = "S3 bucket storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "audit_bucket" {
  description = "S3 bucket for Athena results and AI-generated analyses"
  value       = aws_s3_bucket.audit.id
}

# ── CloudTrail ───────────────────────────────────────────────────────────────
output "cloudtrail_trail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "cloudtrail_lake_arn" {
  description = "ARN of the CloudTrail Lake event data store (empty if disabled)"
  value       = var.enable_cloudtrail_lake ? aws_cloudtrail_event_data_store.main[0].arn : ""
}

# ── Glue / Athena ────────────────────────────────────────────────────────────
output "glue_database_name" {
  description = "Glue catalog database name for CloudTrail logs"
  value       = aws_glue_catalog_database.cloudtrail.name
}

output "glue_table_name" {
  description = "Glue catalog table name"
  value       = aws_glue_catalog_table.cloudtrail_events.name
}

output "athena_workgroup_name" {
  description = "Athena workgroup for all copilot queries"
  value       = aws_athena_workgroup.copilot.name
}

# ── Lambda ───────────────────────────────────────────────────────────────────
output "copilot_lambda_arn" {
  description = "ARN of the Copilot Lambda function"
  value       = aws_lambda_function.copilot.arn
}

output "copilot_lambda_name" {
  description = "Name of the Copilot Lambda function"
  value       = aws_lambda_function.copilot.function_name
}

output "scheduled_hunt_lambda_name" {
  description = "Name of the Scheduled Hunt Lambda function"
  value       = aws_lambda_function.scheduled_hunt.function_name
}

# ── API Gateway ──────────────────────────────────────────────────────────────
output "api_gateway_invoke_url" {
  description = "Base invoke URL for the Copilot REST API"
  value       = "https://${aws_api_gateway_rest_api.copilot.id}.execute-api.${local.region}.amazonaws.com/${var.environment}"
}

output "api_gateway_query_endpoint" {
  description = "Full POST endpoint for submitting threat hunt questions"
  value       = "https://${aws_api_gateway_rest_api.copilot.id}.execute-api.${local.region}.amazonaws.com/${var.environment}/query"
}

# ── ECS / Streamlit UI ───────────────────────────────────────────────────────
output "ecr_repository_url" {
  description = "ECR repository URL — push Streamlit image here"
  value       = aws_ecr_repository.streamlit.repository_url
}

output "alb_dns_name" {
  description = "ALB DNS name — configure your DNS CNAME to this"
  value       = aws_lb.streamlit.dns_name
}

output "streamlit_url" {
  description = "Public HTTPS URL for the Streamlit Threat Hunting Copilot UI"
  value       = "https://${var.streamlit_domain}"
}

# ── Notifications ────────────────────────────────────────────────────────────
output "sns_topic_arn" {
  description = "SNS topic ARN for threat hunt alerts"
  value       = aws_sns_topic.hunt_alerts.arn
}

# ── CloudWatch ───────────────────────────────────────────────────────────────
output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${local.region}#dashboards:name=${aws_cloudwatch_dashboard.copilot.dashboard_name}"
}

# ── Quick-start commands ──────────────────────────────────────────────────────
output "next_steps" {
  description = "Post-deploy commands to build and push the Streamlit container image"
  value       = <<-EOT
    ── Post-deploy steps ──────────────────────────────────────────────────────
    1. Authenticate Docker to ECR:
       aws ecr get-login-password --region ${local.region} | \
         docker login --username AWS --password-stdin ${aws_ecr_repository.streamlit.repository_url}

    2. Build and push the Streamlit image (use --platform linux/amd64 on Apple Silicon):
       cd streamlit/
       docker build --platform linux/amd64 -t ${aws_ecr_repository.streamlit.repository_url}:latest .
       docker push ${aws_ecr_repository.streamlit.repository_url}:latest

    3. Point your DNS record to the ALB:
       CNAME  ${var.streamlit_domain}  →  ${aws_lb.streamlit.dns_name}

    4. Validate the ACM certificate (DNS record output):
       terraform output -json | jq '.streamlit_url'

    5. Test the copilot API directly:
       curl -X POST ${aws_api_gateway_rest_api.copilot.id}.execute-api.${local.region}.amazonaws.com/${var.environment}/query \
         -H "Content-Type: application/json" \
         -d '{"question": "Show all root account logins in the last 7 days"}'

    6. Open the dashboard:
       https://console.aws.amazon.com/cloudwatch/home?region=${local.region}#dashboards:name=${aws_cloudwatch_dashboard.copilot.dashboard_name}
    ───────────────────────────────────────────────────────────────────────────
  EOT
}
