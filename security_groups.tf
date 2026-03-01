# ─────────────────────────────────────────────────────────────────────────────
# Security Group — VPC Interface Endpoints
# All private resources use this SG to reach AWS service endpoints
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.name_prefix}-vpce-sg"
  description = "Allow HTTPS from private subnets to VPC interface endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from private subnets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.private_subnet_cidrs
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-vpce-sg" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Security Group — Lambda functions
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg"
  description = "Outbound-only SG for Lambda functions"
  vpc_id      = aws_vpc.main.id

  # No ingress — Lambda is invoked via IAM, not network
  egress {
    description = "HTTPS to AWS service endpoints and VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Security Group — Application Load Balancer (public-facing)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb-sg"
  description = "Allow HTTPS inbound from the internet to the ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from anywhere (WAF enforces IP allowlist)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-alb-sg" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Security Group — ECS Fargate (Streamlit UI)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group" "ecs_streamlit" {
  name        = "${local.name_prefix}-ecs-sg"
  description = "Streamlit Fargate tasks - accept only from ALB"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "Outbound HTTPS for API Gateway and AWS endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-ecs-sg" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Cross-reference rules — defined separately to break the ALB ↔ ECS SG cycle
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group_rule" "alb_to_ecs_egress" {
  type                     = "egress"
  description              = "Forward to ECS Fargate Streamlit port"
  from_port                = 8501
  to_port                  = 8501
  protocol                 = "tcp"
  security_group_id        = aws_security_group.alb.id
  source_security_group_id = aws_security_group.ecs_streamlit.id
}

resource "aws_security_group_rule" "ecs_from_alb_ingress" {
  type                     = "ingress"
  description              = "Streamlit port from ALB only"
  from_port                = 8501
  to_port                  = 8501
  protocol                 = "tcp"
  security_group_id        = aws_security_group.ecs_streamlit.id
  source_security_group_id = aws_security_group.alb.id
}
