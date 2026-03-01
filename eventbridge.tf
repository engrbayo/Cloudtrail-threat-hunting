# ─────────────────────────────────────────────────────────────────────────────
# EventBridge Scheduler — nightly automated threat hunt
# ─────────────────────────────────────────────────────────────────────────────

# IAM role for EventBridge Scheduler to invoke Lambda
resource "aws_iam_role" "scheduler" {
  name               = "${local.name_prefix}-scheduler-role"
  description        = "Role that EventBridge Scheduler uses to invoke the scheduled hunt Lambda"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role_policy" "scheduler_invoke" {
  name   = "${local.name_prefix}-scheduler-invoke-policy"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_invoke_permissions.json
}

data "aws_iam_policy_document" "scheduler_invoke_permissions" {
  statement {
    sid    = "AllowInvokeScheduledHuntLambda"
    effect = "Allow"
    actions = [
      "lambda:InvokeFunction",
    ]
    resources = [
      aws_lambda_function.scheduled_hunt.arn,
      "${aws_lambda_function.scheduled_hunt.arn}:*",
    ]
  }
}

# Nightly threat hunt schedule
resource "aws_scheduler_schedule" "nightly_hunt" {
  count = var.scheduled_hunt_enabled ? 1 : 0

  name        = "${local.name_prefix}-nightly-hunt"
  description = "Runs predefined CloudTrail threat hunt queries every night"
  group_name  = "default"

  schedule_expression          = var.scheduled_hunt_cron
  schedule_expression_timezone = "UTC"

  flexible_time_window {
    mode                      = "FLEXIBLE"
    maximum_window_in_minutes = 15 # allow up to 15-min window for load spreading
  }

  target {
    arn      = aws_lambda_function.scheduled_hunt.arn
    role_arn = aws_iam_role.scheduler.arn

    input = jsonencode({
      source    = "eventbridge-scheduler"
      hunt_type = "nightly"
    })

    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = 3600
    }
  }

  state = var.scheduled_hunt_enabled ? "ENABLED" : "DISABLED"
}

# Use a dummy resource when scheduled_hunt_enabled = false so lambda.tf
# reference to aws_scheduler_schedule.nightly_hunt.arn still resolves.
# When disabled the lambda permission is still created but points to a
# placeholder ARN — Lambda invoke will never fire.
resource "aws_scheduler_schedule" "nightly_hunt_disabled" {
  count = var.scheduled_hunt_enabled ? 0 : 1

  name        = "${local.name_prefix}-nightly-hunt-disabled"
  description = "Placeholder (scheduled hunts are disabled via variable)"
  group_name  = "default"

  schedule_expression = "rate(1 day)"

  flexible_time_window { mode = "OFF" }

  target {
    arn      = aws_lambda_function.scheduled_hunt.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = "{}"
  }

  state = "DISABLED"
}

# Resolve the correct schedule ARN depending on the enabled flag
locals {
  scheduler_schedule_arn = var.scheduled_hunt_enabled ? aws_scheduler_schedule.nightly_hunt[0].arn : aws_scheduler_schedule.nightly_hunt_disabled[0].arn
}
