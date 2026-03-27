from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.core.config import settings
from app.core.worm import get_object_bytes, read_worm_line


def parse_storage_uri(storage_uri: str) -> tuple[str, str, str | None]:
    """Parse s3://bucket/key?versionId=... into (bucket, key, version_id)."""
    if not storage_uri.startswith("s3://"):
        return settings.WORM_BUCKET, storage_uri, None
    parsed = urlparse(storage_uri)
    bucket = parsed.netloc or settings.WORM_BUCKET
    key = (parsed.path or "").lstrip("/")
    version_id = parse_qs(parsed.query).get("versionId", [None])[0]
    return bucket, key, version_id


def read_evidence_raw_event(
    *,
    storage_uri: str,
    cold_offset: int,
    event_fingerprint: str | None,
) -> tuple[str | None, dict[str, Any]]:
    """
    Return exact event line when possible and metadata for UI proof linkage.

    Supports:
    - WORM newline blocks (offset-based read).
    - cold stack JSON payload containing `events[]` (event-level selection).
    """
    bucket, key, version_id = parse_storage_uri(storage_uri)
    proof_meta = {
        "object_bucket": bucket,
        "object_key": key,
        "object_version": version_id,
        "leaf_index": None,
        "proof_available": False,
    }
    raw_line: str | None = None

    if cold_offset > 0:
        try:
            blob = read_worm_line(key=key, offset=cold_offset)
            raw_line = blob.decode("utf-8", errors="replace") if blob else None
            return raw_line, proof_meta
        except Exception:
            return None, proof_meta

    try:
        blob = get_object_bytes(bucket=bucket, key=key, version_id=version_id)
    except Exception:
        return None, proof_meta

    # JSONL fallback for offset=0 rows that still point to line-based payload.
    first_line = blob.split(b"\n", 1)[0] if blob else b""
    if first_line.startswith(b"{") and b'"events"' not in first_line:
        return first_line.decode("utf-8", errors="replace"), proof_meta

    try:
        payload = json.loads(blob.decode("utf-8"))
    except Exception:
        # Raw unstructured payload fallback
        return blob.decode("utf-8", errors="replace"), proof_meta

    events = payload.get("events")
    leaf_hashes = payload.get("leaf_hashes") or []
    if not isinstance(events, list) or not events:
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True), proof_meta

    selected_index = 0
    if event_fingerprint:
        for idx, ev in enumerate(events):
            if not isinstance(ev, dict):
                continue
            fid = (
                ev.get("forensiq", {}).get("event_fingerprint")
                or ev.get("event", {}).get("id")
                or ev.get("event_id")
            )
            if str(fid) == str(event_fingerprint):
                selected_index = idx
                break

    proof_meta["leaf_index"] = selected_index
    proof_meta["proof_available"] = bool(leaf_hashes)
    try:
        raw_line = json.dumps(events[selected_index], separators=(",", ":"), ensure_ascii=True)
    except Exception:
        raw_line = None
    return raw_line, proof_meta
