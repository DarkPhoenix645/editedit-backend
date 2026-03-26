from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.worm import upload_to_worm
from app.db.models import SealedBlock


def canonical_event_bytes(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _ls_str(value: Any) -> str:
    # Logstash fingerprint treats missing/nil values as empty strings.
    return "" if value is None else str(value)


def compute_fingerprint(event: dict[str, Any]) -> str:
    event_fields = event.get("event", {})
    host_name = event.get("host", {}).get("name") or ""
    dataset = event_fields.get("dataset") or ""
    event_id = event_fields.get("id") or ""
    # Match Logstash fingerprint filter behavior with:
    # source => ["@timestamp","message","[host][name]","[event][dataset]","[event][id]"]
    # concatenate_sources => true
    # The plugin concatenates field names and values in order.
    source = "".join(
        (
            "@timestamp",
            _ls_str(event.get("@timestamp", "")),
            "message",
            _ls_str(event.get("message", "")),
            "[host][name]",
            _ls_str(host_name),
            "[event][dataset]",
            _ls_str(dataset),
            "[event][id]",
            _ls_str(event_id),
        )
    )
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def compute_fingerprint_values_only(event: dict[str, Any]) -> str:
    event_fields = event.get("event", {})
    host_name = event.get("host", {}).get("name") or ""
    dataset = event_fields.get("dataset") or ""
    event_id = event_fields.get("id") or ""
    source = "".join(
        (
            _ls_str(event.get("@timestamp", "")),
            _ls_str(event.get("message", "")),
            _ls_str(host_name),
            _ls_str(dataset),
            _ls_str(event_id),
        )
    )
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def compute_merkle_root(entries: list[dict[str, Any]]) -> bytes:
    if not entries:
        return hashlib.sha256(b"").digest()

    level = [hashlib.sha256(canonical_event_bytes(entry)).digest() for entry in entries]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            next_level.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        level = next_level
    return level[0]


def _load_private_key() -> rsa.RSAPrivateKey:
    if settings.SEALING_PRIVATE_KEY_PEM:
        return serialization.load_pem_private_key(
            settings.SEALING_PRIVATE_KEY_PEM.encode("utf-8"), password=None
        )
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def sign_chain_hash(chain_hash: bytes) -> bytes:
    key = _load_private_key()
    return key.sign(
        chain_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


@dataclass
class SealedBlockResult:
    block: SealedBlock
    offsets: list[int]
    storage_key: str


def _next_sequence(db: Session, source_id: str) -> int:
    latest = (
        db.query(SealedBlock)
        .filter(SealedBlock.source_id == source_id)
        .order_by(SealedBlock.sequence_number.desc())
        .first()
    )
    return 1 if latest is None else int(latest.sequence_number) + 1


def _prev_chain_hash(db: Session, source_id: str) -> bytes:
    latest = (
        db.query(SealedBlock)
        .filter(SealedBlock.source_id == source_id)
        .order_by(SealedBlock.sequence_number.desc())
        .first()
    )
    if latest is None:
        return b"\x00" * 32
    return latest.chain_hash


def seal_event_batch(
    db: Session,
    source_id: str,
    events: list[dict[str, Any]],
) -> SealedBlockResult:
    canonical_lines = [canonical_event_bytes(ev) for ev in events]
    offsets: list[int] = []
    cursor = 0
    for line in canonical_lines:
        offsets.append(cursor)
        cursor += len(line) + 1

    payload = b"\n".join(canonical_lines)
    payload_hash = hashlib.sha256(payload).digest()
    merkle_root = compute_merkle_root(events)

    existing = db.query(SealedBlock).filter(SealedBlock.payload_hash == payload_hash).first()
    if existing:
        storage_key = existing.storage_uri.split("/", 1)[-1]
        return SealedBlockResult(block=existing, offsets=offsets, storage_key=storage_key)

    seq = _next_sequence(db, source_id)
    prev_hash = _prev_chain_hash(db, source_id)
    chain_hash = hashlib.sha256(prev_hash + merkle_root + payload_hash + str(seq).encode("utf-8")).digest()

    signed = sign_chain_hash(chain_hash)
    authoritative_time = datetime.now(timezone.utc)
    tsa_token = hashlib.sha256(
        chain_hash + authoritative_time.isoformat().encode("utf-8")
    ).digest()
    storage_key = f"blocks/{payload_hash.hex()}.raw"
    etag = upload_to_worm(
        storage_key,
        payload + b"\n",
        metadata={
            "payload_hash": payload_hash.hex(),
            "merkle_root": merkle_root.hex(),
            "chain_hash": chain_hash.hex(),
            "sequence_number": str(seq),
        },
    )

    timestamps = [
        datetime.fromisoformat(str(ev["@timestamp"]).replace("Z", "+00:00"))
        if ev.get("@timestamp")
        else authoritative_time
        for ev in events
    ]

    block = SealedBlock(
        source_id=source_id,
        sequence_number=seq,
        window_start=min(timestamps),
        window_end=max(timestamps),
        log_count=len(events),
        payload_hash=payload_hash,
        merkle_root=merkle_root,
        chain_hash=chain_hash,
        tsa_token=tsa_token,
        authoritative_time=authoritative_time,
        rsa_signature=signed,
        signing_key_id=settings.SEALING_SIGNING_KEY_ID,
        storage_uri=f"s3://{settings.WORM_BUCKET}/{storage_key}",
        logstash_config_version=settings.LOGSTASH_CONFIG_VERSION,
    )
    db.add(block)
    db.flush()

    # Persist etag in-memory for debugging flows without changing schema.
    _ = etag
    return SealedBlockResult(block=block, offsets=offsets, storage_key=storage_key)


def encode_block_hashes(block: SealedBlock) -> dict[str, str]:
    return {
        "payload_hash": base64.b16encode(block.payload_hash).decode("ascii").lower(),
        "merkle_root": base64.b16encode(block.merkle_root).decode("ascii").lower(),
        "chain_hash": base64.b16encode(block.chain_hash).decode("ascii").lower(),
    }
