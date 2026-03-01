# ─────────────────────────────────────────────────────────────────────────────
# CloudWatch — Dashboards, Metric Filters, and Alarms
# ─────────────────────────────────────────────────────────────────────────────

# ── Operational Dashboard ─────────────────────────────────────────────────────
resource "aws_cloudwatch_dashboard" "copilot" {
  dashboard_name = "${local.name_prefix}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Row 1 — Hunt metrics
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
        height = 6
        properties = {
          title  = "Threats Detected Per Run"
          period = 86400
          stat   = "Sum"
          metrics = [
            ["ThreatHuntingCopilot", "TotalThreatsPerRun"]
          ]
          view   = "timeSeries"
          region = local.region
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6
        properties = {
          title  = "Hunt Executions"
          period = 86400
          stat   = "Sum"
          metrics = [
            ["ThreatHuntingCopilot", "HuntExecuted"]
          ]
          view   = "timeSeries"
          region = local.region
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6
        properties = {
          title  = "Risk Score Distribution"
          period = 86400
          stat   = "Maximum"
          metrics = [
            ["ThreatHuntingCopilot", "RiskScore"]
          ]
          view   = "timeSeries"
          region = local.region
        }
      },
      # Row 2 — Lambda performance
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Copilot Lambda Duration (ms)"
          period = 300
          stat   = "p95"
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", "${local.name_prefix}-copilot"]
          ]
          view   = "timeSeries"
          region = local.region
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Copilot Lambda Errors"
          period = 300
          stat   = "Sum"
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", "${local.name_prefix}-copilot"],
            ["AWS/Lambda", "Throttles", "FunctionName", "${local.name_prefix}-copilot"]
          ]
          view   = "timeSeries"
          region = local.region
        }
      },
      # Row 3 — API Gateway
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "API Gateway Requests"
          period = 300
          stat   = "Sum"
          metrics = [
            ["AWS/ApiGateway", "Count", "ApiName", "${local.name_prefix}-api"],
            ["AWS/ApiGateway", "5XXError", "ApiName", "${local.name_prefix}-api"]
          ]
          view   = "timeSeries"
          region = local.region
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "API Gateway Latency (ms)"
          period = 300
          stat   = "p95"
          metrics = [
            ["AWS/ApiGateway", "IntegrationLatency", "ApiName", "${local.name_prefix}-api"],
            ["AWS/ApiGateway", "Latency", "ApiName", "${local.name_prefix}-api"]
          ]
          view   = "timeSeries"
          region = local.region
        }
      },
      # Row 4 — Athena cost control
      {
        type   = "metric"
        x      = 0
        y      = 18
        width  = 12
        height = 6
        properties = {
          title  = "Athena Data Scanned (bytes)"
          period = 3600
          stat   = "Sum"
          metrics = [
            ["AWS/Athena", "DataScannedInBytes", "WorkGroup", "${local.name_prefix}-workgroup"]
          ]
          view   = "timeSeries"
          region = local.region
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 18
        width  = 12
        height = 6
        properties = {
          title  = "WAF Blocked Requests"
          period = 3600
          stat   = "Sum"
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", "${local.name_prefix}-waf", "Region", local.region, "Rule", "ALL"]
          ]
          view   = "timeSeries"
          region = local.region
        }
      }
    ]
  })
}

# ── CloudWatch Alarms ─────────────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "copilot_lambda_errors" {
  alarm_name          = "${local.name_prefix}-copilot-errors"
  alarm_description   = "Copilot Lambda error rate exceeds threshold"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = "${local.name_prefix}-copilot" }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.hunt_alerts.arn] : []
}

resource "aws_cloudwatch_metric_alarm" "copilot_lambda_throttles" {
  alarm_name          = "${local.name_prefix}-copilot-throttles"
  alarm_description   = "Copilot Lambda throttling detected"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  dimensions          = { FunctionName = "${local.name_prefix}-copilot" }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.hunt_alerts.arn] : []
}

resource "aws_cloudwatch_metric_alarm" "high_risk_threat" {
  alarm_name          = "${local.name_prefix}-high-risk-threat"
  alarm_description   = "Scheduled hunt detected a threat with risk score >= 75"
  namespace           = "ThreatHuntingCopilot"
  metric_name         = "RiskScore"
  statistic           = "Maximum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 75
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.hunt_alerts.arn] : []
}

resource "aws_cloudwatch_metric_alarm" "athena_data_scan" {
  alarm_name          = "${local.name_prefix}-athena-scan-cost"
  alarm_description   = "Athena data scanned exceeds 50 GB in an hour — cost alert"
  namespace           = "AWS/Athena"
  metric_name         = "DataScannedInBytes"
  dimensions          = { WorkGroup = "${local.name_prefix}-workgroup" }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 53687091200 # 50 GiB
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.hunt_alerts.arn] : []
}

# ── CloudWatch Metric Filters — extract structured fields from Lambda logs ────
resource "aws_cloudwatch_log_metric_filter" "threats_detected" {
  name           = "${local.name_prefix}-threats-detected"
  log_group_name = aws_cloudwatch_log_group.copilot_lambda.name
  pattern        = "{ $.event_type = \"copilot_query\" && $.threat_detected IS TRUE }"

  metric_transformation {
    name          = "ThreatDetectedByQuery"
    namespace     = "ThreatHuntingCopilot"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "critical_confidence" {
  name           = "${local.name_prefix}-critical-confidence"
  log_group_name = aws_cloudwatch_log_group.copilot_lambda.name
  pattern        = "{ $.event_type = \"copilot_query\" && $.confidence = \"CRITICAL\" }"

  metric_transformation {
    name          = "CriticalConfidenceQueries"
    namespace     = "ThreatHuntingCopilot"
    value         = "1"
    default_value = "0"
  }
}
