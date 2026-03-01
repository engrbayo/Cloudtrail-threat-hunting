# ─────────────────────────────────────────────────────────────────────────────
# WAF v2 WebACL — attached to the ALB fronting the Streamlit UI
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_wafv2_web_acl" "streamlit" {
  name        = "${local.name_prefix}-waf"
  description = "WAF protecting the Streamlit Threat Hunting Copilot UI"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # ── Rule 1: IP allowlist — restrict UI access to known CIDR ranges ─────────
  dynamic "rule" {
    for_each = length(var.allowed_ip_ranges) > 0 && !contains(var.allowed_ip_ranges, "0.0.0.0/0") ? [1] : []
    content {
      name     = "IPAllowList"
      priority = 1

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowed_ips[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-ip-allowlist"
        sampled_requests_enabled   = true
      }
    }
  }

  # ── Rule 2: AWS Managed — Common Rule Set (OWASP top 10) ─────────────────
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 3: AWS Managed — Known Bad Inputs ────────────────────────────────
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 4: Rate limiting — max 100 req/5-min per IP ─────────────────────
  rule {
    name     = "RateLimitPerIP"
    priority = 30

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 5: SQL injection protection (extra layer for the query endpoint) ──
  rule {
    name     = "SQLiProtection"
    priority = 40

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          body {
            oversize_handling = "CONTINUE"
          }
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-sqli"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-waf"
    sampled_requests_enabled   = true
  }

  tags = { Name = "${local.name_prefix}-waf" }
}

# IP set for the allowlist rule (only created when not open to 0.0.0.0/0)
resource "aws_wafv2_ip_set" "allowed_ips" {
  count              = length(var.allowed_ip_ranges) > 0 && !contains(var.allowed_ip_ranges, "0.0.0.0/0") ? 1 : 0
  name               = "${local.name_prefix}-allowed-ips"
  description        = "Allowed source CIDRs for the Streamlit UI"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.allowed_ip_ranges

  tags = { Name = "${local.name_prefix}-allowed-ips" }
}

# Attach the WAF WebACL to the ALB
resource "aws_wafv2_web_acl_association" "streamlit" {
  resource_arn = aws_lb.streamlit.arn
  web_acl_arn  = aws_wafv2_web_acl.streamlit.arn
}

# CloudWatch log group for WAF logs (name must start with aws-waf-logs)
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name_prefix}"
  retention_in_days = var.cloudwatch_log_retention_days
}

# Enable WAF logging to CloudWatch Logs
resource "aws_wafv2_web_acl_logging_configuration" "streamlit" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.streamlit.arn

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"
      condition {
        action_condition { action = "BLOCK" }
      }
      requirement = "MEETS_ANY"
    }
  }
}
