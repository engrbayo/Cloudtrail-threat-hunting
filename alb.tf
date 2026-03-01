# ─────────────────────────────────────────────────────────────────────────────
# Application Load Balancer — fronts the Streamlit ECS Fargate tasks
# WAF WebACL is attached here (see waf.tf)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_lb" "streamlit" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false # set true in production
  drop_invalid_header_fields = true

  access_logs {
    bucket  = aws_s3_bucket.audit.id
    prefix  = "alb-logs"
    enabled = true
  }

  tags = { Name = "${local.name_prefix}-alb" }
}

# Target group — points to the Streamlit container port 8501
resource "aws_lb_target_group" "streamlit" {
  name        = "${local.name_prefix}-tg"
  port        = 8501
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip" # required for Fargate

  health_check {
    enabled             = true
    path                = "/_stcore/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 10
    interval            = 30
    matcher             = "200"
  }

  tags = { Name = "${local.name_prefix}-tg" }
}

# HTTPS listener (port 443) — requires an ACM certificate
# If you don't have a cert yet, use the HTTP listener below and comment this out
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.streamlit.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.streamlit.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.streamlit.arn
  }
}

# HTTP listener — redirects to HTTPS
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.streamlit.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# ACM Certificate (DNS validation)
# Set var.streamlit_domain to your domain name, or comment this block out
# and replace certificate_arn above with a pre-existing cert ARN.
# ─────────────────────────────────────────────────────────────────────────────
variable "streamlit_domain" {
  description = "Domain name for the Streamlit UI (e.g. threat-hunt.internal.example.com)"
  type        = string
  default     = "threat-hunt.example.com" # Replace with your actual domain
}

resource "aws_acm_certificate" "streamlit" {
  domain_name       = var.streamlit_domain
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
  tags = { Name = "${local.name_prefix}-cert" }
}

resource "aws_acm_certificate_validation" "streamlit" {
  certificate_arn = aws_acm_certificate.streamlit.arn
  # Add the DNS validation CNAME record in your DNS provider using:
  # aws_acm_certificate.streamlit.domain_validation_options
}
