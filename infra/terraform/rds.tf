# RDS PostgreSQL 16 (staging).
# Private subnets only; reachable only from ECS tasks (see vpc.tf).
# Encrypted at rest, automated backups 7 days, SSL enforced.
# deletion_protection is false for staging so the environment can be
# torn down; production must set it to true.

resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db"
  subnet_ids = aws_subnet.private[*].id

  tags = { Name = "${local.name_prefix}-db" }
}

resource "aws_db_parameter_group" "postgres16" {
  name   = "${local.name_prefix}-postgres16"
  family = "postgres16"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  tags = { Name = "${local.name_prefix}-postgres16" }
}

resource "aws_db_instance" "main" {
  identifier     = "${local.name_prefix}-db"
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  db_subnet_group_name  = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.data.id]
  parameter_group_name  = aws_db_parameter_group.postgres16.name

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  backup_retention_period = var.db_backup_retention_days
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  multi_az            = false # staging only
  deletion_protection = false # staging only; production must be true
  skip_final_snapshot = true  # staging only
  copy_tags_to_snapshot = true

  tags = { Name = "${local.name_prefix}-db" }
}
