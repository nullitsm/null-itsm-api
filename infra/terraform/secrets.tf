# Secrets Manager secrets.
#
# Values are supplied at deploy time (variables) — nothing is hardcoded
# here and nothing secret is committed. The secret values live in the
# Terraform state file, so the state must be stored remotely and encrypted
# (see README.md). Rotate by changing the variable and re-applying.

resource "aws_secretsmanager_secret" "jwt" {
  name        = "${local.name_prefix}/jwt-secret"
  description = "JWT signing secret for the NULL ITSM API (staging)."

  tags = { Name = "${local.name_prefix}-jwt-secret" }
}

resource "aws_secretsmanager_secret_version" "jwt" {
  secret_id     = aws_secretsmanager_secret.jwt.id
  secret_string = var.jwt_secret
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name        = "${local.name_prefix}/db-credentials"
  description = "RDS PostgreSQL credentials and connection URL for the NULL ITSM API (staging)."

  tags = { Name = "${local.name_prefix}-db-credentials" }
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id

  secret_string = jsonencode({
    username     = var.db_username
    password     = var.db_password
    host         = aws_db_instance.main.address
    port         = aws_db_instance.main.port
    dbname       = var.db_name
    database_url = "postgresql+psycopg://${var.db_username}:${var.db_password}@${aws_db_instance.main.address}:${aws_db_instance.main.port}/${var.db_name}?sslmode=require"
  })
}
