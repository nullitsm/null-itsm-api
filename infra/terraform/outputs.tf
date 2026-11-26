# Outputs for the NULL ITSM API staging environment.

output "alb_dns_name" {
  description = "Public DNS name of the ALB (fronts the API)."
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "Route 53 zone ID of the ALB (for alias records)."
  value       = aws_lb.main.zone_id
}

output "ecr_repository_url" {
  description = "URL of the ECR repository for the API image."
  value       = aws_ecr_repository.api.repository_url
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster."
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_api_name" {
  description = "Name of the ECS API service."
  value       = aws_ecs_service.api.name
}

output "ecs_service_worker_name" {
  description = "Name of the ECS Celery worker service."
  value       = aws_ecs_service.worker.name
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint (host:port)."
  value       = aws_db_instance.main.endpoint
}

output "rds_address" {
  description = "RDS PostgreSQL hostname."
  value       = aws_db_instance.main.address
}

output "redis_primary_endpoint" {
  description = "ElastiCache Redis primary endpoint (host:port)."
  value       = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "cognito_user_pool_id" {
  description = "Cognito user pool ID."
  value       = aws_cognito_user_pool.main.id
}

output "cognito_user_pool_client_id" {
  description = "Cognito user pool client ID (OIDC audience)."
  value       = aws_cognito_user_pool_client.main.id
}

output "cognito_issuer" {
  description = "Cognito OIDC issuer URL."
  value       = local.cognito_issuer
}

output "cognito_domain" {
  description = "Cognito hosted-UI domain."
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.aws_region}.amazoncognito.com"
}

output "s3_attachments_bucket" {
  description = "Name of the S3 attachments bucket."
  value       = aws_s3_bucket.attachments.id
}

output "jwt_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the JWT secret."
  value       = aws_secretsmanager_secret.jwt.arn
}

output "db_credentials_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the DB credentials."
  value       = aws_secretsmanager_secret.db_credentials.arn
}

output "vpc_id" {
  description = "ID of the staging VPC."
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets."
  value       = aws_subnet.private[*].id
}
