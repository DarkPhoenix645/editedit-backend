from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from app.core.config import settings

logger = logging.getLogger(__name__)


def _missing_object_lock_configuration(exc: ClientError) -> bool:
    err = exc.response.get("Error", {})
    code = err.get("Code", "")
    msg = str(err.get("Message", ""))
    return code == "InvalidRequest" and "ObjectLockConfiguration" in msg


def get_worm_client() -> Any:
    """S3 client; typed as Any so boto service methods (get_object, put_object) resolve for type checkers."""
    return boto3.client(
        "s3",
        endpoint_url=settings.WORM_ENDPOINT,
        aws_access_key_id=settings.WORM_ACCESS_KEY,
        aws_secret_access_key=settings.WORM_SECRET_KEY,
        region_name=settings.WORM_REGION,
        config=Config(signature_version="s3v4"),
        verify=settings.WORM_VERIFY_SSL,
    )


def upload_to_worm(key: str, data: bytes, metadata: dict[str, str] | None = None) -> str:
    client = get_worm_client()
    extra: dict[str, Any] = {
        "Bucket": settings.WORM_BUCKET,
        "Key": key,
        "Body": data,
        "Metadata": metadata or {},
    }

    # MinIO requires the bucket to be created with object lock (--with-lock). If the bucket
    # predates that or was created without lock, PutObject with these keys fails.
    lock_extra: dict[str, Any] = {}
    if settings.WORM_PROVIDER.lower() == "minio":
        lock_extra["ObjectLockMode"] = "GOVERNANCE"
        lock_extra["ObjectLockRetainUntilDate"] = datetime.now(timezone.utc) + timedelta(
            days=settings.WORM_RETENTION_DAYS
        )
        extra.update(lock_extra)

    try:
        resp = client.put_object(**extra)
    except ClientError as exc:
        if lock_extra and _missing_object_lock_configuration(exc):
            for k in lock_extra:
                extra.pop(k, None)
            logger.warning(
                "WORM bucket missing Object Lock; uploading without retention headers. "
                "Recreate the bucket with object lock (see infrastructure/backend/docker-compose.yml, minio-init)."
            )
            try:
                resp = client.put_object(**extra)
            except ClientError as exc2:
                raise RuntimeError(f"WORM upload failed: {exc2}") from exc2
        else:
            raise RuntimeError(f"WORM upload failed: {exc}") from exc

    return str(resp.get("ETag", "")).strip('"')


def get_object_bytes(*, bucket: str, key: str, version_id: str | None = None) -> bytes:
    """Read a full object from the same S3/MinIO instance as WORM (any bucket, optional version)."""
    client = get_worm_client()
    kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key}
    if version_id:
        kwargs["VersionId"] = version_id
    resp = client.get_object(**kwargs)
    return resp["Body"].read()


def read_worm_object(key: str) -> bytes:
    """Full object read (used for block integrity verification)."""
    return get_object_bytes(bucket=settings.WORM_BUCKET, key=key)


def read_worm_line(key: str, offset: int) -> bytes:
    client = get_worm_client()
    resp = client.get_object(
        Bucket=settings.WORM_BUCKET,
        Key=key,
        Range=f"bytes={offset}-",
    )
    body = resp["Body"]
    line = b""
    for chunk in body.iter_chunks(chunk_size=1024):
        idx = chunk.find(b"\n")
        if idx == -1:
            line += chunk
            continue
        line += chunk[:idx]
        break
    return line
