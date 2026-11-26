# S3 bucket for file attachments.
# Versioned, SSE-S3 encrypted, public access fully blocked, and
# incomplete multipart uploads are aborted after 7 days.
# The bucket name gets a random suffix so it is globally unique.

resource "random_pet" "attachments_bucket" {
  length    = 2
  separator = "-"
}

resource "aws_s3_bucket" "attachments" {
  bucket        = "${local.name_prefix}-attachments-${random_pet.attachments_bucket.id}"
  force_destroy = true # staging only; lets the bucket be destroyed with objects in it

  tags = { Name = "${local.name_prefix}-attachments" }
}

resource "aws_s3_bucket_versioning" "attachments" {
  bucket = aws_s3_bucket.attachments.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "attachments" {
  bucket = aws_s3_bucket.attachments.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # SSE-S3
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "attachments" {
  bucket = aws_s3_bucket.attachments.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "attachments" {
  bucket = aws_s3_bucket.attachments.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
