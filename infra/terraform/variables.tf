# Variables for the NULL ITSM API staging environment.
# No real AWS values or secrets live here — everything sensitive is supplied
# at deploy time via tfvars / environment variables. See
# terraform.tfvars.example for placeholders.

variable "project" {
  description = "Project name used as a prefix for resource names and tags."
  type        = string
  default     = "null-itsm"
}

variable "environment" {
  description = "Environment name. This module is staging-only."
  type        = string
  default     = "staging"
}

variable "aws_region" {
  description = "AWS region for the staging environment."
  type        = string
  default     = "us-east-1"
}

# --- Networking ---

variable "vpc_cidr" {
  description = "CIDR block for the staging VPC."
  type        = string
  default     = "10.10.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones to use (staging uses 2)."
  type        = number
  default     = 2
}

# --- TLS / domain ---

variable "acm_certificate_arn" {
  description = "ARN of an ACM certificate (in this region) for the ALB HTTPS listener. The certificate must already exist and cover the staging domain."
  type        = string
  # No default: HTTPS cannot be configured without a real certificate.
}

variable "domain_name" {
  description = "Public domain name served by the ALB (used for documentation/outputs; DNS itself is managed outside Terraform)."
  type        = string
  default     = ""
}

# --- Cognito ---

variable "cognito_domain_prefix" {
  description = "Prefix for the Cognito hosted-UI domain (<prefix>.auth.<region>.amazoncognito.com). Must be globally unique."
  type        = string
  default     = "null-itsm-staging"
}

# --- Container image / sizing ---

variable "api_image_tag" {
  description = "Image tag in ECR to deploy for the API and worker."
  type        = string
  default     = "latest"
}

variable "container_port" {
  description = "Port the FastAPI container listens on."
  type        = number
  default     = 8000
}

variable "api_cpu" {
  description = "Fargate CPU units for the API task (256 = 0.25 vCPU)."
  type        = number
  default     = 512
}

variable "api_memory" {
  description = "Fargate memory (MiB) for the API task."
  type        = number
  default     = 1024
}

variable "api_desired_count" {
  description = "Desired number of API tasks."
  type        = number
  default     = 1
}

variable "worker_cpu" {
  description = "Fargate CPU units for the Celery worker task."
  type        = number
  default     = 256
}

variable "worker_memory" {
  description = "Fargate memory (MiB) for the Celery worker task."
  type        = number
  default     = 512
}

variable "worker_desired_count" {
  description = "Desired number of Celery worker tasks."
  type        = number
  default     = 1
}

# --- Database ---

variable "db_name" {
  description = "Initial PostgreSQL database name."
  type        = string
  default     = "null_itsm"
}

variable "db_username" {
  description = "Master username for RDS PostgreSQL."
  type        = string
  default     = "null_owner"
}

variable "db_password" {
  description = "Master password for RDS PostgreSQL. Supplied at deploy time (tfvars or TF_VAR_db_password). Never committed."
  type        = string
  sensitive   = true
  # No default: must be supplied at deploy time.
}

variable "db_instance_class" {
  description = "RDS instance class (staging size)."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "Allocated RDS storage in GiB."
  type        = number
  default     = 20
}

variable "db_engine_version" {
  description = "PostgreSQL major version."
  type        = string
  default     = "16"
}

variable "db_backup_retention_days" {
  description = "Automated backup retention in days."
  type        = number
  default     = 7
}

# --- Redis ---

variable "redis_node_type" {
  description = "ElastiCache node type (staging size)."
  type        = string
  default     = "cache.t4g.micro"
}

variable "redis_engine_version" {
  description = "Redis engine version."
  type        = string
  default     = "7.1"
}

# --- Secrets ---

variable "jwt_secret" {
  description = "Secret used to sign the app's JWTs. Supplied at deploy time (tfvars or TF_VAR_jwt_secret). Never committed."
  type        = string
  sensitive   = true
  # No default: must be supplied at deploy time.
}

# --- Observability / alarming ---

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 30
}

variable "alarm_notification_email" {
  description = "Email address subscribed to the CloudWatch alarms SNS topic. Empty means no email subscription is created."
  type        = string
  default     = ""
}

variable "alb_5xx_threshold" {
  description = "ALB target 5xx count in 5 minutes that triggers the alarm."
  type        = number
  default     = 10
}

variable "ecs_cpu_threshold" {
  description = "ECS service CPU utilization percent that triggers the alarm."
  type        = number
  default     = 80
}

variable "rds_free_storage_threshold_percent" {
  description = "RDS free-storage percent below which the alarm fires."
  type        = number
  default     = 20
}

variable "rds_max_connections" {
  description = "Approximate max_connections for the staging instance class; used to derive the connections alarm threshold at 80%."
  type        = number
  default     = 80
}
