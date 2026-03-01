# ─────────────────────────────────────────────────────────────────────────────
# Package Lambda source code into zip archives using archive_file
# ─────────────────────────────────────────────────────────────────────────────
data "archive_file" "copilot" {
  type        = "zip"
  source_file = "${path.module}/lambda/copilot/handler.py"
  output_path = "${path.module}/.build/copilot.zip"
}

data "archive_file" "scheduled_hunt" {
  type        = "zip"
  source_file = "${path.module}/lambda/scheduled_hunt/handler.py"
  output_path = "${path.module}/.build/scheduled_hunt.zip"
}

# ─────────────────────────────────────────────────────────────────────────────
# SNS Topic — threat hunt alert notifications
# Declared here (before Lambda) because Lambda env vars reference the ARN
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_sns_topic" "hunt_alerts" {
  name              = "${local.name_prefix}-hunt-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = { Name = "${local.name_prefix}-hunt-alerts" }
}

resource "aws_sns_topic_subscription" "alert_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.hunt_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ─────────────────────────────────────────────────────────────────────────────
# Lambda — Copilot (NL → SQL → Athena → Bedrock analysis)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_lambda_function" "copilot" {
  function_name = "${local.name_prefix}-copilot"
  description   = "CloudTrail Threat Hunting Copilot — NL to Athena SQL + Bedrock analysis"

  filename         = data.archive_file.copilot.output_path
  source_code_hash = data.archive_file.copilot.output_base64sha256
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"

  role        = aws_iam_role.copilot_lambda.arn
  timeout     = var.lambda_timeout
  memory_size = var.lambda_memory_size

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      BEDROCK_MODEL_ID      = var.bedrock_model_id
      ATHENA_DATABASE       = local.glue_database_name
      ATHENA_TABLE          = local.glue_table_name
      ATHENA_WORKGROUP      = aws_athena_workgroup.copilot.name
      ATHENA_OUTPUT_BUCKET  = aws_s3_bucket.audit.id
      ATHENA_RESULTS_PREFIX = var.athena_results_prefix
      QUERY_LIMIT           = tostring(var.athena_query_limit)
    }
  }

  tracing_config { mode = "Active" }

  depends_on = [
    aws_iam_role_policy.copilot_lambda_inline,
    aws_iam_role_policy_attachment.copilot_vpc_execution,
    aws_cloudwatch_log_group.copilot_lambda,
  ]

  tags = { Name = "${local.name_prefix}-copilot" }
}

resource "aws_cloudwatch_log_group" "copilot_lambda" {
  name              = "/aws/lambda/${local.name_prefix}-copilot"
  retention_in_days = var.cloudwatch_log_retention_days
}

# Allow API Gateway to invoke the copilot Lambda
resource "aws_lambda_permission" "api_gateway_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.copilot.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.copilot.execution_arn}/*/*"
}

# ─────────────────────────────────────────────────────────────────────────────
# Lambda — Scheduled Threat Hunt
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_lambda_function" "scheduled_hunt" {
  function_name = "${local.name_prefix}-scheduled-hunt"
  description   = "Runs a predefined set of threat hunt queries on a schedule"

  filename         = data.archive_file.scheduled_hunt.output_path
  source_code_hash = data.archive_file.scheduled_hunt.output_base64sha256
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"

  role        = aws_iam_role.scheduled_hunt_lambda.arn
  timeout     = var.lambda_timeout
  memory_size = var.lambda_memory_size

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      COPILOT_FUNCTION_NAME = aws_lambda_function.copilot.function_name
      SNS_TOPIC_ARN         = aws_sns_topic.hunt_alerts.arn
      ALERT_THRESHOLD       = "HIGH"
    }
  }

  tracing_config { mode = "Active" }

  depends_on = [
    aws_iam_role_policy.scheduled_hunt_lambda_inline,
    aws_iam_role_policy_attachment.scheduled_hunt_vpc_execution,
    aws_cloudwatch_log_group.scheduled_hunt_lambda,
  ]

  tags = { Name = "${local.name_prefix}-scheduled-hunt" }
}

resource "aws_cloudwatch_log_group" "scheduled_hunt_lambda" {
  name              = "/aws/lambda/${local.name_prefix}-scheduled-hunt"
  retention_in_days = var.cloudwatch_log_retention_days
}

# Allow EventBridge Scheduler to invoke the scheduled hunt Lambda
resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeSchedulerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scheduled_hunt.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = local.scheduler_schedule_arn
}
