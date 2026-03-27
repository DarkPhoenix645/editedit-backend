import hashlib
import io
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from minio import Minio
from minio.commonconfig import COMPLIANCE, GOVERNANCE, Tags
from minio.error import S3Error
from minio.retention import Retention

from app.core.canonical_json import canonical_json_bytes
from app.core.config import settings

@dataclass(frozen=True)
class ColdObjectReference:
    bucket: str
    object_key: str
    version_id: str | None
    etag: str
    sha256_hex: str
    size_bytes: int
    retention_mode: str
    retention_until: datetime
    legal_hold: bool
    storage_uri: str

_BUCKET_READY = False

@lru_cache(maxsize=1)
def _client() -> Minio:
    return Minio(
        endpoint=settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE,
    )

def _retention_mode() -> str:
    mode = settings.MINIO_RETENTION_MODE.strip().upper()
    if mode not in {GOVERNANCE, COMPLIANCE}:
        raise ValueError(
            "MINIO_RETENTION_MODE must be GOVERNANCE or COMPLIANCE"
        )
    return mode

def _retention_until() -> tuple[datetime, datetime]:
    retention_until = (
        datetime.now(timezone.utc).replace(microsecond=0)
        + timedelta(days=settings.MINIO_RETENTION_DAYS)
    )
    # MinIO examples use naive UTC datetimes for retention headers.
    minio_retention_until = retention_until.astimezone(timezone.utc).replace(
        tzinfo=None
    )
    return retention_until, minio_retention_until

def _storage_uri(bucket: str, object_key: str, version_id: str | None) -> str:
    base_uri = f"s3://{bucket}/{object_key}"
    if not version_id:
        return base_uri
    return f"{base_uri}?versionId={version_id}"

def _object_key(source_id: str, sequence_number: int, block_id: str) -> str:
    prefix = settings.MINIO_PREFIX.strip("/")
    object_name = f"{source_id}/{sequence_number:020d}-{block_id}.json"
    if not prefix:
        return object_name
    return f"{prefix}/{object_name}"

def _ensure_bucket() -> None:
    global _BUCKET_READY
    if _BUCKET_READY:
        return

    if not settings.MINIO_AUTO_CREATE_BUCKET:
        _BUCKET_READY = True
        return

    client = _client()
    bucket_name = settings.MINIO_BUCKET
    if client.bucket_exists(bucket_name):
        _BUCKET_READY = True
        return

    try:
        client.make_bucket(bucket_name, object_lock=True)
    except S3Error as exc:
        if exc.code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            raise
    _BUCKET_READY = True

def store_cold_block_payload(
    *,
    block_id: str,
    source_id: str,
    sequence_number: int,
    payload: dict[str, Any],
) -> ColdObjectReference:
    _ensure_bucket()

    payload_bytes = canonical_json_bytes(payload)
    payload_stream = io.BytesIO(payload_bytes)
    retention_until, minio_retention_until = _retention_until()
    retention_mode = _retention_mode()

    tags = Tags(for_object=True)
    tags["block_id"] = block_id
    tags["source_id"] = source_id

    bucket_name = settings.MINIO_BUCKET
    object_key = _object_key(source_id, sequence_number, block_id)
    result = _client().put_object(
        bucket_name=bucket_name,
        object_name=object_key,
        data=payload_stream,
        length=len(payload_bytes),
        content_type="application/json",
        tags=tags,
        retention=Retention(retention_mode, minio_retention_until),
    )

    return ColdObjectReference(
        bucket=bucket_name,
        object_key=object_key,
        version_id=result.version_id,
        etag=result.etag,
        sha256_hex=hashlib.sha256(payload_bytes).hexdigest(),
        size_bytes=len(payload_bytes),
        retention_mode=retention_mode,
        retention_until=retention_until,
        legal_hold=False,
        storage_uri=_storage_uri(bucket_name, object_key, result.version_id),
    )


def fetch_cold_block_payload(
    *,
    bucket: str,
    object_key: str,
    version_id: str | None,
    expected_sha256_hex: str | None = None,
) -> dict[str, Any]:
    """Download and parse the JSON payload stored for a cold block (same object as store_cold_block_payload)."""
    client = _client()
    response = client.get_object(
        bucket_name=bucket,
        object_name=object_key,
        version_id=version_id or None,
    )
    try:
        raw = response.read()
    finally:
        response.close()
        response.release_conn()

    if expected_sha256_hex is not None:
        got = hashlib.sha256(raw).hexdigest()
        if got != expected_sha256_hex:
            raise ValueError(
                f"object SHA-256 mismatch: expected {expected_sha256_hex}, got {got}"
            )

    return json.loads(raw.decode("utf-8"))
