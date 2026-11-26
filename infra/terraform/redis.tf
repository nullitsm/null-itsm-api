# ElastiCache Redis (staging) — broker + result backend for Celery.
# Private subnets only; reachable only from ECS tasks (see vpc.tf).
# Encrypted in transit (TLS) and at rest. Single node for staging
# (no automatic failover); production would use a multi-node cluster.

resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.name_prefix}-redis"
  subnet_ids = aws_subnet.private[*].id

  tags = { Name = "${local.name_prefix}-redis" }
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "NULL ITSM staging Redis (Celery broker + cache)"

  engine               = "redis"
  engine_version       = var.redis_engine_version
  node_type            = var.redis_node_type
  num_cache_clusters   = 1
  parameter_group_name = "default.redis7"

  automatic_failover_enabled = false # single node, staging only
  multi_az_enabled           = false

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.data.id]

  tags = { Name = "${local.name_prefix}-redis" }
}
