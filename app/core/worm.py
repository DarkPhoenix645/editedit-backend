from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.client import BaseClient, Config
from botocore.exceptions import ClientError

from app.core.config import settings


def get_worm_client() -> BaseClient:
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

    # MinIO supports object lock APIs when bucket/versioning/object-lock are enabled.
    if settings.WORM_PROVIDER.lower() == "minio":
        extra["ObjectLockMode"] = "GOVERNANCE"
        extra["ObjectLockRetainUntilDate"] = datetime.now(timezone.utc) + timedelta(
            days=settings.WORM_RETENTION_DAYS
        )

    try:
        resp = client.put_object(**extra)
    except ClientError as exc:
        raise RuntimeError(f"WORM upload failed: {exc}") from exc

    return str(resp.get("ETag", "")).strip('"')


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
