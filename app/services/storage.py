"""S3 file storage interface.

Production: Amazon S3 via boto3, credentials from the environment / ECS
task role. Development: an S3-compatible endpoint (MinIO) via
``NULL_S3_ENDPOINT_URL``. When no bucket is configured the service reports
``configured == False`` and upload operations raise — callers must handle
that honestly instead of pretending a file was stored.
"""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.config import get_settings

logger = logging.getLogger("null.storage")


class StorageError(Exception):
    pass


class S3Storage:
    def __init__(self, bucket: str | None = None, client=None) -> None:
        settings = get_settings()
        self.bucket = bucket or settings.s3_bucket
        self._client = client
        if self._client is None and self.bucket:
            kwargs: dict = {"region_name": settings.s3_region}
            if settings.s3_endpoint_url:
                kwargs["endpoint_url"] = settings.s3_endpoint_url
            if settings.aws_access_key_id:
                kwargs["aws_access_key_id"] = settings.aws_access_key_id
                kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
            self._client = boto3.client("s3", **kwargs)

    @property
    def configured(self) -> bool:
        return bool(self.bucket and self._client is not None)

    def presigned_upload_url(self, key: str, content_type: str, expires_seconds: int = 900) -> str:
        """Return a presigned PUT URL for direct browser upload to S3."""
        if not self.configured:
            raise StorageError("S3 storage is not configured")
        try:
            return self._client.generate_presigned_url(
                "put_object",
                Params={"Bucket": self.bucket, "Key": key, "ContentType": content_type},
                ExpiresIn=expires_seconds,
            )
        except (BotoCoreError, ClientError) as exc:
            raise StorageError(f"presign failed: {exc}") from exc

    def presigned_download_url(self, key: str, expires_seconds: int = 900) -> str:
        if not self.configured:
            raise StorageError("S3 storage is not configured")
        try:
            return self._client.generate_presigned_url(
                "get_object", Params={"Bucket": self.bucket, "Key": key}, ExpiresIn=expires_seconds
            )
        except (BotoCoreError, ClientError) as exc:
            raise StorageError(f"presign failed: {exc}") from exc

    def delete(self, key: str) -> None:
        if not self.configured:
            raise StorageError("S3 storage is not configured")
        self._client.delete_object(Bucket=self.bucket, Key=key)


def get_storage() -> S3Storage:
    return S3Storage()
