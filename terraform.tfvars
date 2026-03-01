# ─────────────────────────────────────────────────────────────────────────────
# terraform.tfvars — CloudTrail Threat Hunting Copilot
# Fill in the values marked with <CHANGE_ME> before running terraform apply
# ─────────────────────────────────────────────────────────────────────────────

# ── General ───────────────────────────────────────────────────────────────────
aws_region   = "us-east-1"
project_name = "ct-hunt-copilot"
environment  = "prod" # dev | staging | prod

# ── Networking ────────────────────────────────────────────────────────────────
vpc_cidr             = "10.10.0.0/16"
public_subnet_cidrs  = ["10.10.0.0/24", "10.10.1.0/24"]
private_subnet_cidrs = ["10.10.10.0/24", "10.10.11.0/24"]
availability_zones   = ["us-east-1a", "us-east-1b"]

# ── Amazon Bedrock ────────────────────────────────────────────────────────────
# Ensure Claude 3.5 Sonnet is enabled in your region before deploying:
# AWS Console → Amazon Bedrock → Model access → Enable
bedrock_model_id = "us.anthropic.claude-3-5-haiku-20241022-v1:0"

# ── Amazon Athena ─────────────────────────────────────────────────────────────
athena_query_limit    = 500
athena_results_prefix = "athena-results/"

# ── AWS CloudTrail ────────────────────────────────────────────────────────────
cloudtrail_log_prefix          = "cloudtrail/"
enable_cloudtrail_lake         = false # set true to enable CloudTrail Lake
cloudtrail_lake_retention_days = 90

# ── AWS Lambda ────────────────────────────────────────────────────────────────
lambda_timeout     = 300 # seconds (max 900)
lambda_memory_size = 512 # MB

# ── Scheduled Threat Hunts (EventBridge) ─────────────────────────────────────
scheduled_hunt_enabled = true
scheduled_hunt_cron    = "cron(0 2 * * ? *)" # 02:00 UTC every day

# ── ECS Fargate / Streamlit UI ────────────────────────────────────────────────
# Leave streamlit_container_image blank on first deploy.
# After `terraform apply`, build & push the image to ECR, then re-apply.
streamlit_container_image = "539247484955.dkr.ecr.us-east-1.amazonaws.com/ct-hunt-copilot-prod-streamlit:latest"
streamlit_domain          = "cloudtrailthreathuntingcopilot.com" # e.g. "copilot.yourdomain.com"

ecs_task_cpu      = 512  # 256 | 512 | 1024 | 2048 | 4096
ecs_task_memory   = 1024 # MiB
ecs_desired_count = 1

# ── AWS WAF v2 ────────────────────────────────────────────────────────────────
# IMPORTANT: Replace 0.0.0.0/0 with your office / VPN CIDR ranges in production
allowed_ip_ranges = ["0.0.0.0/0"]

# ── Notifications (Amazon SNS) ────────────────────────────────────────────────
# Email that receives HIGH / CRITICAL threat hunt alerts.
# Leave blank ("") to skip SNS email subscription.
alert_email = "bayodoyin4@gmail.com" # e.g. "soc-team@yourdomain.com"

# ── Observability ─────────────────────────────────────────────────────────────
cloudwatch_log_retention_days = 90
