variable "aws_region" {
  description = "AWS region to deploy all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used as prefix for all resource names"
  type        = string
  default     = "ct-hunt-copilot"
}

variable "environment" {
  description = "Deployment environment (dev / staging / prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod"
  }
}

# ── Networking ──────────────────────────────────────────────────────────────
variable "vpc_cidr" {
  description = "CIDR block for the project VPC"
  type        = string
  default     = "10.10.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ, used by ALB)"
  type        = list(string)
  default     = ["10.10.0.0/24", "10.10.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (Lambda, ECS Fargate)"
  type        = list(string)
  default     = ["10.10.10.0/24", "10.10.11.0/24"]
}

variable "availability_zones" {
  description = "Availability zones to deploy into (must match subnet count)"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

# ── Amazon Bedrock ───────────────────────────────────────────────────────────
variable "bedrock_model_id" {
  description = "Bedrock model ID used for NL→SQL conversion and threat analysis. Use the cross-region inference profile prefix (e.g. us.) for on-demand throughput."
  type        = string
  default     = "us.anthropic.claude-3-5-haiku-20241022-v1:0"
}

# ── Athena ───────────────────────────────────────────────────────────────────
variable "athena_query_limit" {
  description = "Default row limit applied to every generated Athena SQL query"
  type        = number
  default     = 500
}

variable "athena_results_prefix" {
  description = "S3 key prefix for Athena query result output"
  type        = string
  default     = "athena-results/"
}

# ── CloudTrail ───────────────────────────────────────────────────────────────
variable "enable_cloudtrail_lake" {
  description = "Enable CloudTrail Lake event data store (true) vs S3+Glue catalog (false)"
  type        = bool
  default     = false # set true if you want CloudTrail Lake
}

variable "cloudtrail_log_prefix" {
  description = "S3 key prefix for CloudTrail logs"
  type        = string
  default     = "cloudtrail/"
}

variable "cloudtrail_lake_retention_days" {
  description = "Retention in days for CloudTrail Lake event data store"
  type        = number
  default     = 90
}

# ── Lambda ───────────────────────────────────────────────────────────────────
variable "lambda_timeout" {
  description = "Lambda function timeout in seconds (max 900)"
  type        = number
  default     = 300
}

variable "lambda_memory_size" {
  description = "Lambda function memory allocation in MB"
  type        = number
  default     = 512
}

# ── Scheduled threat hunts ───────────────────────────────────────────────────
variable "scheduled_hunt_enabled" {
  description = "Enable nightly automated threat hunt via EventBridge"
  type        = bool
  default     = true
}

variable "scheduled_hunt_cron" {
  description = "EventBridge cron expression for scheduled hunts (UTC)"
  type        = string
  default     = "cron(0 2 * * ? *)" # 02:00 UTC every day
}

# ── ECS Fargate / Streamlit UI ───────────────────────────────────────────────
variable "streamlit_container_image" {
  description = "Full ECR image URI for the Streamlit chat app (set after docker push)"
  type        = string
  default     = "" # populated via CI/CD after first build
}

variable "ecs_task_cpu" {
  description = "ECS Fargate task CPU units (256 / 512 / 1024 / 2048 / 4096)"
  type        = number
  default     = 512
}

variable "ecs_task_memory" {
  description = "ECS Fargate task memory in MiB"
  type        = number
  default     = 1024
}

variable "ecs_desired_count" {
  description = "Desired number of Streamlit ECS tasks"
  type        = number
  default     = 1
}

# ── WAF ──────────────────────────────────────────────────────────────────────
variable "allowed_ip_ranges" {
  description = "IPv4 CIDR ranges permitted to reach the Streamlit UI via WAF"
  type        = list(string)
  default     = ["0.0.0.0/0"] # RESTRICT IN PRODUCTION
}

# ── Notifications ────────────────────────────────────────────────────────────
variable "alert_email" {
  description = "E-mail address that receives scheduled hunt alerts (leave blank to skip)"
  type        = string
  default     = ""
}

# ── Observability ────────────────────────────────────────────────────────────
variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log group retention in days"
  type        = number
  default     = 90
}
