# NULL ITSM API — Staging Infrastructure (Terraform)

AWS staging infrastructure **as code only**. This directory provisions
nothing by itself — it only describes what `terraform apply` would create.

> **Explicit infrastructure approval is required before any staging
> deployment.** Do not run `terraform apply` (and do not configure AWS
> credentials for it) until Miah approves the staging environment.
> Applying this module creates billable AWS resources (NAT gateway, RDS,
> ElastiCache, ALB, Fargate tasks).

## What it provisions (staging, `us-east-1` by default)

| Component | Detail |
|---|---|
| VPC | 2 AZs, public + private subnets, 1 NAT gateway (staging cost saving) |
| ECS Fargate | Cluster + API service (uvicorn) + Celery worker service (same ECR image, different command) |
| ALB | Public, HTTPS listener (ACM cert), HTTP → HTTPS redirect, `/health` target-group checks |
| RDS | PostgreSQL 16, `db.t4g.micro`, encrypted, 7-day backups, `rds.force_ssl=1`, private subnets |
| ElastiCache | Redis 7.1, `cache.t4g.micro`, encrypted in transit + at rest |
| S3 | Attachments bucket — versioned, SSE-S3, public access blocked, aborts incomplete multipart uploads |
| Cognito | User pool + client + hosted-UI domain; password policy, MFA optional |
| Secrets Manager | JWT secret + DB credentials (values supplied at deploy time, never hardcoded) |
| CloudWatch | Log groups (30-day retention) + alarms: ALB 5xx, ECS CPU, RDS free storage, RDS connections |
| IAM | ECS execution role (ECR pull, logs, secrets read) + task role (S3 on the attachments bucket only) |
| ECR | Repository for the API image, scan-on-push, keeps last 10 images |

## Layout

```
main.tf        provider, versions, locals
variables.tf   all inputs (no real values, no secrets)
outputs.tf     ALB DNS, ECR URL, endpoints, pool IDs, secret ARNs
vpc.tf         VPC, subnets, NAT, route tables, security groups
ecs.tf         ECR, ECS cluster/tasks/services, ALB + listeners
rds.tf         PostgreSQL
redis.tf       ElastiCache Redis
s3.tf          attachments bucket
cognito.tf     user pool, client, domain
secrets.tf     Secrets Manager secrets
cloudwatch.tf  log groups, SNS topic, alarms
iam.tf         ECS execution + task roles
```

## Deploy

```bash
cd infra/terraform

# 1. Copy the example vars and fill in real values (never commit the result).
cp terraform.tfvars.example terraform.tfvars
#    - acm_certificate_arn: ARN of a validated ACM cert in this region
#    - db_password: strong generated password
#    - jwt_secret: random 256-bit secret, e.g. openssl rand -hex 32
#    - alarm_notification_email: where alarm emails go

# 2. Initialise (downloads the AWS provider).
terraform init

# 3. Review exactly what will be created. Nothing is provisioned yet.
terraform plan

# 4. Apply — ONLY with explicit infrastructure approval.
terraform apply
```

## Notes / assumptions

- **No Dockerfile exists in this repo yet.** The ECS task definitions
  reference an ECR image (`<repo>:latest` by default); the CI workflow
  builds and pushes that image. Until a Dockerfile is added and an image
  is pushed, the services cannot start.
- **Remote state is not configured.** Before first use, add an S3 backend
  with encryption + DynamoDB locking. The state file contains secret
  values (DB password, JWT secret, connection URL) — never store it
  locally long-term and never commit it.
- **Secrets are supplied at deploy time** via `terraform.tfvars` (or
  `TF_VAR_db_password` / `TF_VAR_jwt_secret` env vars). They are stored in
  Secrets Manager and injected into containers; the app reads them as
  `NULL_JWT_SECRET` / `NULL_DATABASE_URL` (see `app/config.py`, `NULL_`
  prefix). Rotate by changing the variable and re-applying.
- **Single NAT gateway and single-node Redis** are staging cost choices;
  production would use one NAT per AZ, multi-AZ RDS, and a Redis cluster
  with failover.
- **Staging-only relaxations:** RDS `deletion_protection = false`,
  `skip_final_snapshot = true`, ECR/S3 `force_delete = true`. Production
  must flip all of these.
- **RDS `rds.force_ssl=1`** means the app connects with
  `?sslmode=require` (built into the Secrets Manager connection URL).
- **Redis uses TLS** (`rediss://` URLs) because transit encryption is on.
- The ALB target group and the ECS task health check both use `/health`
  (the app's existing health endpoint).
- No Route 53 records are managed here; point DNS at the ALB DNS name
  from `terraform output alb_dns_name` (or use the `domain_name` variable
  for reference).
- Terraform was not available in this environment, so the HCL was
  checked by careful review only — run `terraform validate` / `plan`
  before applying.
```

## Tear down

```bash
terraform destroy   # staging only; also requires approval
```
