# ─────────────────────────────────────────────────────────────────────────────
# ECS Cluster — hosts the Streamlit chat UI on Fargate
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_ecs_cluster" "streamlit" {
  name = "${local.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = "${local.name_prefix}-cluster" }
}

resource "aws_ecs_cluster_capacity_providers" "streamlit" {
  cluster_name       = aws_ecs_cluster.streamlit.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# ECS Task Definition — Streamlit container
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_ecs_task_definition" "streamlit" {
  family                   = "${local.name_prefix}-streamlit"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.ecs_task_cpu
  memory                   = var.ecs_task_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "streamlit"
      image = var.streamlit_container_image != "" ? var.streamlit_container_image : "${aws_ecr_repository.streamlit.repository_url}:latest"

      portMappings = [
        {
          containerPort = 8501
          hostPort      = 8501
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "API_GATEWAY_URL"
          value = "https://${aws_api_gateway_rest_api.copilot.id}.execute-api.${local.region}.amazonaws.com/${var.environment}"
        },
        {
          name  = "AWS_REGION"
          value = local.region
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_streamlit.name
          "awslogs-region"        = local.region
          "awslogs-stream-prefix" = "streamlit"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8501/_stcore/health || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 60
      }

      essential = true
    }
  ])

  tags = { Name = "${local.name_prefix}-streamlit-task" }
}

resource "aws_cloudwatch_log_group" "ecs_streamlit" {
  name              = "/ecs/${local.name_prefix}-streamlit"
  retention_in_days = var.cloudwatch_log_retention_days
}

# ─────────────────────────────────────────────────────────────────────────────
# ECS Service — runs the Streamlit task behind the ALB
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_ecs_service" "streamlit" {
  name            = "${local.name_prefix}-streamlit-svc"
  cluster         = aws_ecs_cluster.streamlit.id
  task_definition = aws_ecs_task_definition.streamlit.arn
  desired_count   = var.ecs_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_streamlit.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.streamlit.arn
    container_name   = "streamlit"
    container_port   = 8501
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  enable_execute_command = false # disable ECS Exec in production

  depends_on = [
    aws_lb_listener.https,
    aws_iam_role_policy_attachment.ecs_task_execution_managed,
  ]

  tags = { Name = "${local.name_prefix}-streamlit-svc" }

  lifecycle {
    ignore_changes = [task_definition, desired_count]
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# Auto-scaling — scale ECS service based on CPU and request count
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_appautoscaling_target" "streamlit" {
  max_capacity       = 4
  min_capacity       = var.ecs_desired_count
  resource_id        = "service/${aws_ecs_cluster.streamlit.name}/${aws_ecs_service.streamlit.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "streamlit_cpu" {
  name               = "${local.name_prefix}-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.streamlit.resource_id
  scalable_dimension = aws_appautoscaling_target.streamlit.scalable_dimension
  service_namespace  = aws_appautoscaling_target.streamlit.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
