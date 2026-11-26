# ECR, ECS Fargate (API + Celery worker), and the public ALB.
#
# The API and the worker run the SAME image with different commands:
# API    -> uvicorn app.main:app
# Worker -> celery -A app.tasks.celery_app worker
# Secrets are injected from Secrets Manager; nothing secret is baked
# into the image or the task definition environment.

# --- ECR ---

resource "aws_ecr_repository" "api" {
  name                 = "${local.name_prefix}-api"
  image_tag_mutability = "MUTABLE"
  force_delete         = true # staging only; lets the repo be destroyed with images in it

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = { Name = "${local.name_prefix}-api" }
}

resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# --- ECS cluster ---

resource "aws_ecs_cluster" "main" {
  name = "${local.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = "${local.name_prefix}-cluster" }
}

# --- Shared container environment (non-secret) ---

locals {
  redis_url           = "rediss://${aws_elasticache_replication_group.main.primary_endpoint_address}:6379/0"
  celery_broker_url   = "rediss://${aws_elasticache_replication_group.main.primary_endpoint_address}:6379/1"
  celery_backend_url  = "rediss://${aws_elasticache_replication_group.main.primary_endpoint_address}:6379/2"
  cognito_jwks_url    = "${local.cognito_issuer}/.well-known/jwks.json"
  api_image           = "${aws_ecr_repository.api.repository_url}:${var.api_image_tag}"

  common_container_env = [
    { name = "NULL_ENV", value = var.environment },
    { name = "NULL_API_PORT", value = tostring(var.container_port) },
    { name = "NULL_REDIS_URL", value = local.redis_url },
    { name = "NULL_CELERY_BROKER_URL", value = local.celery_broker_url },
    { name = "NULL_CELERY_RESULT_BACKEND", value = local.celery_backend_url },
    { name = "NULL_OIDC_ISSUER", value = local.cognito_issuer },
    { name = "NULL_OIDC_AUDIENCE", value = aws_cognito_user_pool_client.main.id },
    { name = "NULL_OIDC_JWKS_URL", value = local.cognito_jwks_url },
    { name = "NULL_COGNITO_USER_POOL_ID", value = aws_cognito_user_pool.main.id },
    { name = "NULL_S3_BUCKET", value = aws_s3_bucket.attachments.id },
    { name = "NULL_S3_REGION", value = var.aws_region },
  ]

  # Secrets injected from Secrets Manager (never in plaintext here).
  common_container_secrets = [
    {
      name      = "NULL_JWT_SECRET"
      valueFrom = aws_secretsmanager_secret.jwt.arn
    },
    {
      name      = "NULL_DATABASE_URL"
      valueFrom = "${aws_secretsmanager_secret.db_credentials.arn}:database_url::"
    },
    {
      name      = "NULL_DATABASE_OWNER_URL"
      valueFrom = "${aws_secretsmanager_secret.db_credentials.arn}:database_url::"
    },
  ]
}

# --- API task definition ---

resource "aws_ecs_task_definition" "api" {
  family                   = "${local.name_prefix}-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.api_cpu
  memory                   = var.api_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = local.api_image
      essential = true

      command = [
        "uvicorn", "app.main:app",
        "--host", "0.0.0.0",
        "--port", tostring(var.container_port),
      ]

      portMappings = [{
        containerPort = var.container_port
        protocol      = "tcp"
      }]

      environment = local.common_container_env
      secrets     = local.common_container_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.api.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "api"
        }
      }

      healthCheck = {
        command = [
          "CMD-SHELL",
          "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:${var.container_port}/health')\""
        ]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
    }
  ])

  tags = { Name = "${local.name_prefix}-api" }
}

# --- Celery worker task definition (same image, different command) ---

resource "aws_ecs_task_definition" "worker" {
  family                   = "${local.name_prefix}-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = local.api_image
      essential = true

      command = [
        "celery", "-A", "app.tasks.celery_app",
        "worker", "--loglevel=info",
      ]

      environment = local.common_container_env
      secrets     = local.common_container_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.worker.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "worker"
        }
      }
    }
  ])

  tags = { Name = "${local.name_prefix}-worker" }
}

# --- ALB ---

resource "aws_lb" "main" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = { Name = "${local.name_prefix}-alb" }
}

resource "aws_lb_target_group" "api" {
  name        = "${local.name_prefix}-api-tg"
  port        = var.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
    matcher             = "200"
  }

  tags = { Name = "${local.name_prefix}-api-tg" }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
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

# --- ECS services ---

resource "aws_ecs_service" "api" {
  name            = "${local.name_prefix}-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = var.container_port
  }

  depends_on = [aws_lb_listener.https]

  tags = { Name = "${local.name_prefix}-api" }
}

resource "aws_ecs_service" "worker" {
  name            = "${local.name_prefix}-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  tags = { Name = "${local.name_prefix}-worker" }
}
