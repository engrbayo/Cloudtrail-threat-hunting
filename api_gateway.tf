# ─────────────────────────────────────────────────────────────────────────────
# API Gateway REST API — Copilot query endpoint
# The Streamlit UI POSTs questions here; API GW proxies to the copilot Lambda
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_api_gateway_rest_api" "copilot" {
  name        = "${local.name_prefix}-api"
  description = "CloudTrail Threat Hunting Copilot REST API"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = { Name = "${local.name_prefix}-api" }
}

# ── /query resource ───────────────────────────────────────────────────────────
resource "aws_api_gateway_resource" "query" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  parent_id   = aws_api_gateway_rest_api.copilot.root_resource_id
  path_part   = "query"
}

# POST /query — main threat hunt endpoint
resource "aws_api_gateway_method" "query_post" {
  rest_api_id   = aws_api_gateway_rest_api.copilot.id
  resource_id   = aws_api_gateway_resource.query.id
  http_method   = "POST"
  authorization = "NONE" # WAF + VPC enforces access; add Cognito/IAM in prod

  request_validator_id = aws_api_gateway_request_validator.body.id

  request_models = {
    "application/json" = aws_api_gateway_model.query_request.name
  }
}

resource "aws_api_gateway_model" "query_request" {
  rest_api_id  = aws_api_gateway_rest_api.copilot.id
  name         = "QueryRequest"
  description  = "Schema for POST /query request body"
  content_type = "application/json"

  schema = jsonencode({
    "$schema" = "http://json-schema.org/draft-04/schema#"
    title     = "QueryRequest"
    type      = "object"
    required  = ["question"]
    properties = {
      question = {
        type      = "string"
        minLength = 5
        maxLength = 1000
      }
    }
  })
}

resource "aws_api_gateway_request_validator" "body" {
  rest_api_id           = aws_api_gateway_rest_api.copilot.id
  name                  = "ValidateBody"
  validate_request_body = true
}

# Lambda proxy integration
resource "aws_api_gateway_integration" "query_post" {
  rest_api_id             = aws_api_gateway_rest_api.copilot.id
  resource_id             = aws_api_gateway_resource.query.id
  http_method             = aws_api_gateway_method.query_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.copilot.invoke_arn
  timeout_milliseconds    = 29000 # API GW max is 29 s; Lambda itself runs up to 5 min
}

resource "aws_api_gateway_method_response" "query_200" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  resource_id = aws_api_gateway_resource.query.id
  http_method = aws_api_gateway_method.query_post.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
  }
}

# ── OPTIONS /query — CORS preflight ──────────────────────────────────────────
resource "aws_api_gateway_method" "query_options" {
  rest_api_id   = aws_api_gateway_rest_api.copilot.id
  resource_id   = aws_api_gateway_resource.query.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "query_options" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  resource_id = aws_api_gateway_resource.query.id
  http_method = aws_api_gateway_method.query_options.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "query_options_200" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  resource_id = aws_api_gateway_resource.query.id
  http_method = aws_api_gateway_method.query_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "query_options" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  resource_id = aws_api_gateway_resource.query.id
  http_method = aws_api_gateway_method.query_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

# ── /health resource ──────────────────────────────────────────────────────────
resource "aws_api_gateway_resource" "health" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  parent_id   = aws_api_gateway_rest_api.copilot.root_resource_id
  path_part   = "health"
}

resource "aws_api_gateway_method" "health_get" {
  rest_api_id   = aws_api_gateway_rest_api.copilot.id
  resource_id   = aws_api_gateway_resource.health.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "health_get" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_get.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "health_200" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_get.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "health_get" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  resource_id = aws_api_gateway_resource.health.id
  http_method = aws_api_gateway_method.health_get.http_method
  status_code = "200"

  response_templates = {
    "application/json" = "{\"status\":\"healthy\",\"service\":\"threat-hunting-copilot\"}"
  }
}

# ── Deployment + Stage ────────────────────────────────────────────────────────
resource "aws_api_gateway_deployment" "copilot" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id

  # Force redeploy when any method/integration changes
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.query,
      aws_api_gateway_method.query_post,
      aws_api_gateway_integration.query_post,
      aws_api_gateway_resource.health,
      aws_api_gateway_method.health_get,
      aws_api_gateway_integration.health_get,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_integration.query_post,
    aws_api_gateway_integration.query_options,
    aws_api_gateway_integration.health_get,
  ]
}

resource "aws_api_gateway_stage" "copilot" {
  rest_api_id   = aws_api_gateway_rest_api.copilot.id
  deployment_id = aws_api_gateway_deployment.copilot.id
  stage_name    = var.environment

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId          = "$context.requestId"
      ip                 = "$context.identity.sourceIp"
      caller             = "$context.identity.caller"
      user               = "$context.identity.user"
      requestTime        = "$context.requestTime"
      httpMethod         = "$context.httpMethod"
      resourcePath       = "$context.resourcePath"
      status             = "$context.status"
      protocol           = "$context.protocol"
      responseLength     = "$context.responseLength"
      integrationLatency = "$context.integrationLatency"
    })
  }

  xray_tracing_enabled = true

  tags = { Name = "${local.name_prefix}-api-stage" }
}

resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.copilot.id
  stage_name  = aws_api_gateway_stage.copilot.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled        = true
    logging_level          = "INFO"
    data_trace_enabled     = false
    throttling_burst_limit = 50
    throttling_rate_limit  = 20
  }
}

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${local.name_prefix}"
  retention_in_days = var.cloudwatch_log_retention_days
}

# IAM role that lets API Gateway write to CloudWatch Logs
resource "aws_api_gateway_account" "copilot" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_cw.arn
}

resource "aws_iam_role" "api_gateway_cw" {
  name               = "${local.name_prefix}-apigw-cw-role"
  assume_role_policy = data.aws_iam_policy_document.apigw_assume.json
}

data "aws_iam_policy_document" "apigw_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "api_gateway_cw" {
  role       = aws_iam_role.api_gateway_cw.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

# ── Usage Plan + API Key (optional auth layer) ────────────────────────────────
resource "aws_api_gateway_usage_plan" "copilot" {
  name        = "${local.name_prefix}-usage-plan"
  description = "Rate limiting for the Threat Hunting Copilot API"

  api_stages {
    api_id = aws_api_gateway_rest_api.copilot.id
    stage  = aws_api_gateway_stage.copilot.stage_name
  }

  throttle_settings {
    burst_limit = 50
    rate_limit  = 20
  }

  quota_settings {
    limit  = 1000
    period = "DAY"
  }
}
