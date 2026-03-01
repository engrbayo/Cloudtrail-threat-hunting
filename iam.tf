# ─────────────────────────────────────────────────────────────────────────────
# IAM — Copilot Lambda execution role
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "copilot_lambda" {
  name               = "${local.name_prefix}-copilot-lambda-role"
  description        = "Execution role for the CloudTrail Threat Hunting Copilot Lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "copilot_lambda_inline" {
  name   = "${local.name_prefix}-copilot-lambda-policy"
  role   = aws_iam_role.copilot_lambda.id
  policy = data.aws_iam_policy_document.copilot_lambda_permissions.json
}

data "aws_iam_policy_document" "copilot_lambda_permissions" {
  # CloudWatch Logs — write Lambda logs
  statement {
    sid    = "AllowLambdaLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}-*:*"]
  }

  # VPC — attach Lambda to VPC ENIs
  statement {
    sid    = "AllowVpcAccess"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
    ]
    resources = ["*"]
  }

  # Amazon Bedrock — invoke only the configured Claude model
  statement {
    sid    = "AllowBedrockInvoke"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel",
    ]
    resources = [
      "arn:aws:bedrock:*::foundation-model/anthropic.claude-*",
      "arn:aws:bedrock:${local.region}:${local.account_id}:inference-profile/${var.bedrock_model_id}",
    ]
  }

  # Athena — run queries, get results
  statement {
    sid    = "AllowAthenaQuery"
    effect = "Allow"
    actions = [
      "athena:StartQueryExecution",
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:StopQueryExecution",
      "athena:ListQueryExecutions",
    ]
    resources = [
      aws_athena_workgroup.copilot.arn,
    ]
  }

  # Glue — read the CloudTrail catalog
  statement {
    sid    = "AllowGlueCatalogRead"
    effect = "Allow"
    actions = [
      "glue:GetDatabase",
      "glue:GetTable",
      "glue:GetPartitions",
      "glue:GetPartition",
    ]
    resources = [
      "arn:aws:glue:${local.region}:${local.account_id}:catalog",
      "arn:aws:glue:${local.region}:${local.account_id}:database/${local.glue_database_name}",
      "arn:aws:glue:${local.region}:${local.account_id}:table/${local.glue_database_name}/*",
    ]
  }

  # S3 — read CloudTrail logs + write Athena results
  statement {
    sid    = "AllowS3CloudTrailRead"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.cloudtrail_logs.arn,
      "${aws_s3_bucket.cloudtrail_logs.arn}/*",
    ]
  }

  statement {
    sid    = "AllowS3AthenaResults"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:AbortMultipartUpload",
      "s3:GetObjectVersion",
    ]
    resources = [
      aws_s3_bucket.audit.arn,
      "${aws_s3_bucket.audit.arn}/*",
    ]
  }

  # SNS — publish threat hunt alerts
  statement {
    sid       = "AllowSNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.hunt_alerts.arn]
  }

  # CloudWatch — publish custom hunt metrics
  statement {
    sid    = "AllowCloudWatchMetrics"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["ThreatHuntingCopilot"]
    }
  }

  # SSM Parameter Store — read configuration values
  statement {
    sid    = "AllowSSMParameterRead"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]
    resources = [
      "arn:aws:ssm:${local.region}:${local.account_id}:parameter/security/ai/threat-hunting/*",
    ]
  }
}

# Attach AWS-managed policy for VPC Lambda basic execution
resource "aws_iam_role_policy_attachment" "copilot_vpc_execution" {
  role       = aws_iam_role.copilot_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM — Scheduled Hunt Lambda execution role
# Identical permissions + ability to invoke the copilot Lambda
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "scheduled_hunt_lambda" {
  name               = "${local.name_prefix}-sched-hunt-lambda-role"
  description        = "Execution role for the Scheduled Threat Hunt Lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "scheduled_hunt_lambda_inline" {
  name   = "${local.name_prefix}-sched-hunt-policy"
  role   = aws_iam_role.scheduled_hunt_lambda.id
  policy = data.aws_iam_policy_document.scheduled_hunt_permissions.json
}

data "aws_iam_policy_document" "scheduled_hunt_permissions" {
  statement {
    sid    = "AllowLambdaLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}-*:*"]
  }

  statement {
    sid    = "AllowVpcAccess"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
    ]
    resources = ["*"]
  }

  # Invoke the copilot Lambda synchronously
  statement {
    sid    = "AllowInvokeCopilotLambda"
    effect = "Allow"
    actions = [
      "lambda:InvokeFunction",
    ]
    resources = [aws_lambda_function.copilot.arn]
  }

  statement {
    sid       = "AllowSNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.hunt_alerts.arn]
  }

  statement {
    sid    = "AllowCloudWatchMetrics"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["ThreatHuntingCopilot"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "scheduled_hunt_vpc_execution" {
  role       = aws_iam_role.scheduled_hunt_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM — Glue Crawler role (for S3+Glue catalog path)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "glue_crawler" {
  name               = "${local.name_prefix}-glue-crawler-role"
  description        = "Glue crawler role to catalog CloudTrail logs from S3"
  assume_role_policy = data.aws_iam_policy_document.glue_assume.json
}

data "aws_iam_policy_document" "glue_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["glue.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "glue_service" {
  role       = aws_iam_role.glue_crawler.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "glue_s3_access" {
  name   = "${local.name_prefix}-glue-s3-policy"
  role   = aws_iam_role.glue_crawler.id
  policy = data.aws_iam_policy_document.glue_s3_permissions.json
}

data "aws_iam_policy_document" "glue_s3_permissions" {
  statement {
    sid    = "AllowCloudTrailS3Read"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.cloudtrail_logs.arn,
      "${aws_s3_bucket.cloudtrail_logs.arn}/*",
    ]
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM — ECS Task Execution Role (pulls ECR image, writes logs)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "ecs_task_execution" {
  name               = "${local.name_prefix}-ecs-exec-role"
  description        = "ECS task execution role for Streamlit Fargate task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_managed" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM — ECS Task Role (Streamlit app permissions at runtime)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "ecs_task" {
  name               = "${local.name_prefix}-ecs-task-role"
  description        = "Runtime role for the Streamlit Fargate container"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy" "ecs_task_inline" {
  name   = "${local.name_prefix}-ecs-task-policy"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.ecs_task_permissions.json
}

data "aws_iam_policy_document" "ecs_task_permissions" {
  # Streamlit calls API Gateway — no direct AWS SDK calls needed.
  # Grant only CloudWatch for container-level metrics.
  statement {
    sid    = "AllowCWMetrics"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData",
    ]
    resources = ["*"]
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM — CloudTrail S3 bucket write policy
# Allows CloudTrail service to deliver logs to the S3 bucket
# ─────────────────────────────────────────────────────────────────────────────
data "aws_iam_policy_document" "cloudtrail_s3_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/${var.cloudtrail_log_prefix}AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}
