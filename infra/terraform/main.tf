# NULL ITSM API — staging infrastructure (AWS, code only)
#
# This module provisions the STAGING environment only. It creates NO real
# resources until someone runs `terraform apply` with real AWS credentials,
# and doing so requires explicit infrastructure approval from Miah.
# See README.md in this directory.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # Remote state is intentionally NOT configured here. Before first use,
  # configure an S3 backend with DynamoDB locking (see README.md) so the
  # state file — which contains secret values — is never stored locally
  # or committed to git.
  # backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

# First N availability zones in the region (staging uses 2).
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name_prefix = "${var.project}-${var.environment}"

  common_tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    Service     = "null-itsm-api"
  }

  availability_zones = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Cognito OIDC issuer, used by the API to validate tokens.
  cognito_issuer = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
}
