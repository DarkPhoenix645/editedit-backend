import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import ColdStoredBlock, HotColdTrace, LogSource, SealedBlock


_PRIVATE_KEY = None

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value:
        return None

    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

def _get_nested(payload: dict[str, Any], path: str) -> Any:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current

def _first_present(payload: dict[str, Any], *paths: str, default: Any = None) -> Any:
    for path in paths:
        value = _get_nested(payload, path)
        if value not in (None, "", []):
            return value
    return default

def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

def _sha256_bytes(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()

def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _merkle_root(leaf_hashes: list[bytes]) -> bytes:
    if not leaf_hashes:
        return _sha256_bytes(b"")

    nodes = leaf_hashes[:]
    while len(nodes) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(nodes), 2):
            left = nodes[index]
            right = nodes[index + 1] if index + 1 < len(nodes) else left
            next_level.append(_sha256_bytes(left + right))
        nodes = next_level
    return nodes[0]

def _signing_key():
    global _PRIVATE_KEY
    if _PRIVATE_KEY is not None:
        return _PRIVATE_KEY

    if settings.COLDSTACK_SIGNING_PRIVATE_KEY_B64:
        key_bytes = base64.b64decode(settings.COLDSTACK_SIGNING_PRIVATE_KEY_B64)
        _PRIVATE_KEY = serialization.load_pem_private_key(key_bytes, password=None)
    else:
        # Dev fallback so the cold path still works without external key provisioning.
        _PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _PRIVATE_KEY

def _sign_chain_hash(chain_hash: bytes) -> bytes:
    return _signing_key().sign(
        chain_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def _resolve_source(db: Session, first_event: dict[str, Any], fallback_agent_id: str) -> LogSource:
    agent_id = _first_present(
        first_event,
        "agent.id",
        "elastic_agent.id",
        "agent.ephemeral_id",
        "host.id",
        "host.name",
        default=fallback_agent_id,
    )
    source = db.query(LogSource).filter(LogSource.agent_id == agent_id).first()
    if source:
        return source

    source = LogSource(
        agent_id=agent_id,
        source_name=_first_present(
            first_event,
            "data_stream.dataset",
            "log.file.path",
            "host.name",
            "service.name",
            default=agent_id,
        ),
        static_trust_level=str(
            _first_present(
                first_event,
                "forensiq.static_trust_level",
                "labels.static_trust_level",
                default="unknown",
            )
        ),
        dynamic_trust_score=float(
            _first_present(
                first_event,
                "forensiq.dynamic_trust_score",
                "labels.dynamic_trust_score",
                default=1.0,
            )
        ),
        provider_type=str(
            _first_present(
                first_event,
                "cloud.provider",
                "input.type",
                "service.type",
                default="unknown",
            )
        ),
        os_type=str(_first_present(first_event, "host.os.type", default="unknown")),
    )
    db.add(source)
    db.flush()
    return source

def _derive_event_id(event: dict[str, Any]) -> str:
    explicit_id = _first_present(event, "event.id", "metadata._id", default=None)
    if explicit_id:
        return str(explicit_id)
    return _sha256_hex(_canonical_json_bytes(event))

def process_cold_events(db: Session, events: list[dict[str, Any]]) -> SealedBlock:
    if not events:
        raise ValueError("cold event batch is empty")

    canonical_events = [_canonical_json_bytes(event) for event in events]
    leaf_hashes = [_sha256_bytes(event_bytes) for event_bytes in canonical_events]
    payload_hash = _merkle_root(leaf_hashes)

    fallback_agent_id = f"batch-{_sha256_hex(canonical_events[0])[:16]}"
    source = _resolve_source(db, events[0], fallback_agent_id)

    previous_block = (
        db.query(SealedBlock)
        .filter(SealedBlock.source_id == source.id)
        .order_by(desc(SealedBlock.sequence_number))
        .first()
    )
    sequence_number = 1 if previous_block is None else previous_block.sequence_number + 1

    authoritative_time = _utc_now()
    event_times = [
        parsed
        for parsed in (
            _parse_datetime(
                _first_present(
                    event,
                    "@timestamp",
                    "event.created",
                    "event.ingested",
                    "timestamp",
                    default=None,
                )
            )
            for event in events
        )
        if parsed is not None
    ]
    window_start = min(event_times) if event_times else authoritative_time
    window_end = max(event_times) if event_times else authoritative_time

    previous_chain_hash = previous_block.chain_hash if previous_block is not None else b""
    chain_material = b"|".join(
        [
            previous_chain_hash,
            payload_hash,
            str(sequence_number).encode("utf-8"),
            window_start.isoformat().encode("utf-8"),
            window_end.isoformat().encode("utf-8"),
            authoritative_time.isoformat().encode("utf-8"),
            str(len(events)).encode("utf-8"),
        ]
    )
    chain_hash = _sha256_bytes(chain_material)

    timestamp_proof = {
        "authority": settings.COLDSTACK_TIMESTAMP_AUTHORITY,
        "authoritative_time": authoritative_time.isoformat(),
        "payload_hash_hex": payload_hash.hex(),
        "chain_hash_hex": chain_hash.hex(),
    }
    rsa_signature = _sign_chain_hash(chain_hash)

    block = SealedBlock(
        source_id=source.id,
        sequence_number=sequence_number,
        window_start=window_start,
        window_end=window_end,
        log_count=len(events),
        payload_hash=payload_hash,
        chain_hash=chain_hash,
        tsa_token=json.dumps(timestamp_proof, sort_keys=True).encode("utf-8"),
        authoritative_time=authoritative_time,
        rsa_signature=rsa_signature,
        signing_key_id=settings.COLDSTACK_SIGNING_KEY_ID,
        storage_uri="",
    )
    db.add(block)
    db.flush()
    block.storage_uri = f"{settings.COLDSTACK_STORAGE_URI_PREFIX.rstrip('/')}/{block.id}"

    stored_block = ColdStoredBlock(
        block_id=block.id,
        source_id=source.id,
        events=events,
        leaf_hashes=[leaf_hash.hex() for leaf_hash in leaf_hashes],
        merkle_root_hex=payload_hash.hex(),
        chain_hash_hex=chain_hash.hex(),
        timestamp_proof=timestamp_proof,
    )
    db.add(stored_block)

    event_ids = [_derive_event_id(event) for event in events]
    existing_ids = {
        row[0]
        for row in db.query(HotColdTrace.elastic_event_id)
        .filter(HotColdTrace.elastic_event_id.in_(event_ids))
        .all()
    }
    for event_id in event_ids:
        if event_id in existing_ids:
            continue
        db.add(HotColdTrace(elastic_event_id=event_id, block_id=block.id))

    db.commit()
    db.refresh(block)
    return block
