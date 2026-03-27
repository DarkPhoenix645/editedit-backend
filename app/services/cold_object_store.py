import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from botocore.exceptions import ClientError

from app.core.canonical_json import canonical_json_bytes
from app.core.config import settings
from app.core.worm import _missing_object_lock_configuration, get_object_bytes, get_worm_client

logger = logging.getLogger(__name__)


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


def _retention_mode() -> str:
    mode = settings.MINIO_RETENTION_MODE.strip().upper()
    if mode not in {"GOVERNANCE", "COMPLIANCE"}:
        raise ValueError("MINIO_RETENTION_MODE must be GOVERNANCE or COMPLIANCE")
    return mode


def _retention_until() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
        days=settings.MINIO_RETENTION_DAYS
    )


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


def _create_cold_bucket(client: Any, bucket_name: str) -> None:
    base: dict[str, Any] = {"Bucket": bucket_name}
    if settings.WORM_REGION and settings.WORM_REGION != "us-east-1":
        base["CreateBucketConfiguration"] = {"LocationConstraint": settings.WORM_REGION}
    try:
        client.create_bucket(**base, ObjectLockEnabledForBucket=True)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            return
        try:
            client.create_bucket(**base)
        except ClientError as exc2:
            code2 = exc2.response.get("Error", {}).get("Code", "")
            if code2 in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                return
            raise RuntimeError(f"Could not create cold bucket {bucket_name}: {exc2}") from exc2


def _ensure_bucket() -> None:
    global _BUCKET_READY
    if _BUCKET_READY:
        return

    if not settings.MINIO_AUTO_CREATE_BUCKET:
        _BUCKET_READY = True
        return

    client = get_worm_client()
    bucket_name = settings.MINIO_BUCKET
    try:
        client.head_bucket(Bucket=bucket_name)
        _BUCKET_READY = True
        return
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise

    _create_cold_bucket(client, bucket_name)
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
    retention_until = _retention_until()
    retention_mode = _retention_mode()

    bucket_name = settings.MINIO_BUCKET
    object_key = _object_key(source_id, sequence_number, block_id)
    tagging = urlencode({"block_id": block_id, "source_id": source_id})

    client = get_worm_client()
    extra: dict[str, Any] = {
        "Bucket": bucket_name,
        "Key": object_key,
        "Body": payload_bytes,
        "ContentType": "application/json",
        "Tagging": tagging,
    }

    lock_extra: dict[str, Any] = {}
    if settings.WORM_PROVIDER.lower() == "minio":
        lock_extra["ObjectLockMode"] = retention_mode
        lock_extra["ObjectLockRetainUntilDate"] = retention_until
    extra.update(lock_extra)

    try:
        resp = client.put_object(**extra)
    except ClientError as exc:
        if lock_extra and _missing_object_lock_configuration(exc):
            for k in lock_extra:
                extra.pop(k, None)
            logger.warning(
                "Cold bucket missing Object Lock; uploading without retention headers. "
                "Recreate the bucket with object lock (see infrastructure/backend/docker-compose.minio.yml)."
            )
            try:
                resp = client.put_object(**extra)
            except ClientError as exc2:
                raise RuntimeError(f"Cold put_object failed: {exc2}") from exc2
        else:
            raise RuntimeError(f"Cold put_object failed: {exc}") from exc

    version_id = resp.get("VersionId")
    etag = str(resp.get("ETag", "")).strip('"')

    return ColdObjectReference(
        bucket=bucket_name,
        object_key=object_key,
        version_id=version_id,
        etag=etag,
        sha256_hex=hashlib.sha256(payload_bytes).hexdigest(),
        size_bytes=len(payload_bytes),
        retention_mode=retention_mode,
        retention_until=retention_until,
        legal_hold=False,
        storage_uri=_storage_uri(bucket_name, object_key, version_id),
    )


def fetch_cold_block_payload(
    *,
    bucket: str,
    object_key: str,
    version_id: str | None,
    expected_sha256_hex: str | None = None,
) -> dict[str, Any]:
    """Download and parse the JSON payload stored for a cold block (same object as store_cold_block_payload)."""
    raw = get_object_bytes(
        bucket=bucket,
        key=object_key,
        version_id=version_id or None,
    )

    if expected_sha256_hex is not None:
        got = hashlib.sha256(raw).hexdigest()
        if got != expected_sha256_hex:
            raise ValueError(
                f"object SHA-256 mismatch: expected {expected_sha256_hex}, got {got}"
            )

    return json.loads(raw.decode("utf-8"))
