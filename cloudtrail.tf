# ─────────────────────────────────────────────────────────────────────────────
# CloudTrail — Multi-region trail delivering logs to S3
# (Always created so Glue/Athena have log data to query)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  s3_key_prefix                 = var.cloudtrail_log_prefix
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # Capture management events (read + write)
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # Also capture S3 data events for exfil detection
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw.arn

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_cloudwatch_log_group.cloudtrail,
  ]

  tags = { Name = "${local.name_prefix}-trail" }
}

# CloudWatch Log Group for CloudTrail (enables real-time metric filters)
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.name_prefix}"
  retention_in_days = var.cloudwatch_log_retention_days
}

# IAM role that CloudTrail uses to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cw" {
  name               = "${local.name_prefix}-cloudtrail-cw-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "cloudtrail_cw_inline" {
  name   = "${local.name_prefix}-cloudtrail-cw-policy"
  role   = aws_iam_role.cloudtrail_cw.id
  policy = data.aws_iam_policy_document.cloudtrail_cw_permissions.json
}

data "aws_iam_policy_document" "cloudtrail_cw_permissions" {
  statement {
    sid    = "AllowCloudTrailCWWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# CloudTrail Lake — Event Data Store (optional, toggled by variable)
# Higher cost but provides native SQL querying without Glue/Athena setup
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_cloudtrail_event_data_store" "main" {
  count = var.enable_cloudtrail_lake ? 1 : 0

  name                           = "${local.name_prefix}-lake"
  multi_region_enabled           = true
  organization_enabled           = false
  retention_period               = var.cloudtrail_lake_retention_days
  termination_protection_enabled = false

  advanced_event_selector {
    name = "Capture all management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "Capture S3 data events for exfil detection"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
  }

  tags = { Name = "${local.name_prefix}-lake" }
}
