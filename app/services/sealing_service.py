from __future__ import annotations

import base64
import hashlib
import json
import statistics
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.worm import upload_to_worm
from app.db.models import ColdStoredBlock, HotColdTrace, LogSource, SealedBlock


_SEALING_PRIVATE_KEY: rsa.RSAPrivateKey | None = None
_COLDSTACK_PRIVATE_KEY: rsa.RSAPrivateKey | None = None


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
    global _SEALING_PRIVATE_KEY
    if _SEALING_PRIVATE_KEY is not None:
        return _SEALING_PRIVATE_KEY

    if settings.SEALING_PRIVATE_KEY_PEM:
        _SEALING_PRIVATE_KEY = serialization.load_pem_private_key(
            settings.SEALING_PRIVATE_KEY_PEM.encode("utf-8"), password=None
        )
    else:
        _SEALING_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return _SEALING_PRIVATE_KEY


def sign_chain_hash(chain_hash: bytes) -> bytes:
    key = _load_private_key()
    return key.sign(
        chain_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def _load_coldstack_private_key() -> rsa.RSAPrivateKey:
    global _COLDSTACK_PRIVATE_KEY
    if _COLDSTACK_PRIVATE_KEY is not None:
        return _COLDSTACK_PRIVATE_KEY

    if settings.COLDSTACK_SIGNING_PRIVATE_KEY_B64:
        key_bytes = base64.b64decode(settings.COLDSTACK_SIGNING_PRIVATE_KEY_B64)
        _COLDSTACK_PRIVATE_KEY = serialization.load_pem_private_key(key_bytes, password=None)
    else:
        _COLDSTACK_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _COLDSTACK_PRIVATE_KEY


def _sign_coldstack_chain_hash(chain_hash: bytes) -> bytes:
    return _load_coldstack_private_key().sign(
        chain_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


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


def _event_source_kind(event: dict[str, Any]) -> str:
    dataset = str(_first_present(event, "data_stream.dataset", default="")).lower()
    category = _first_present(event, "event.category", default=[])
    if isinstance(category, str):
        categories = [category.lower()]
    else:
        categories = [str(item).lower() for item in category]
    service_type = str(_first_present(event, "service.type", default="")).lower()
    ocsf_class = str(_first_present(event, "ocsf.class", default="")).lower()

    auth_markers = ("auth", "login", "identity", "iam", "okta", "sso", "authentication")
    network_markers = ("network", "firewall", "dns", "proxy", "flow", "connection", "netflow")

    auth_hit = any(marker in dataset or marker in service_type or marker in ocsf_class for marker in auth_markers) or any(
        marker in value for value in categories for marker in auth_markers
    )
    if auth_hit:
        return "authentication"

    network_hit = any(
        marker in dataset or marker in service_type or marker in ocsf_class for marker in network_markers
    ) or any(marker in value for value in categories for marker in network_markers)
    if network_hit:
        return "network"

    return "other"


def _event_sequence(event: dict[str, Any]) -> int | None:
    raw = _first_present(
        event,
        "event.sequence",
        "log.offset",
        "forensiq.sequence_number",
        default=None,
    )
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _event_source_key(event: dict[str, Any], fallback_source_id: str) -> str:
    return str(
        _first_present(
            event,
            "agent.id",
            "elastic_agent.id",
            "host.id",
            "host.name",
            "source.ip",
            default=fallback_source_id,
        )
    )


def _derive_event_id(event: dict[str, Any]) -> str:
    explicit_id = _first_present(event, "event.id", "metadata._id", default=None)
    if explicit_id:
        return str(explicit_id)
    return _sha256_hex(_canonical_json_bytes(event))


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


def _build_anti_timestamp_report(
    events: list[dict[str, Any]],
    authoritative_time: datetime,
    previous_block: SealedBlock | None,
    fallback_source_id: str,
) -> dict[str, Any]:
    threshold_ms = settings.COLDSTACK_MAX_CLOCK_SKEW_MS
    event_reports: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] = []
    grouped_by_kind: dict[str, list[float]] = {"authentication": [], "network": [], "other": []}
    monotonic_state: dict[str, dict[str, Any]] = {}

    for event in events:
        event_id = _derive_event_id(event)
        event_time = _parse_datetime(
            _first_present(
                event,
                "@timestamp",
                "event.created",
                "event.ingested",
                "timestamp",
                default=None,
            )
        )
        source_kind = _event_source_kind(event)
        source_key = _event_source_key(event, fallback_source_id)
        sequence = _event_sequence(event)

        report = {
            "event_id": event_id,
            "source_kind": source_kind,
            "source_key": source_key,
            "timestamp": event_time.isoformat() if event_time else None,
            "sequence": sequence,
            "checks": [],
        }

        if event_time is not None:
            skew_ms = abs((authoritative_time - event_time).total_seconds() * 1000.0)
            grouped_by_kind[source_kind].append(skew_ms)
            report["clock_skew_ms"] = skew_ms
            if skew_ms > threshold_ms:
                finding = {
                    "type": "clock_skew_exceeded",
                    "event_id": event_id,
                    "source_kind": source_kind,
                    "skew_ms": round(skew_ms, 3),
                    "threshold_ms": threshold_ms,
                }
                report["checks"].append(finding)
                anomalies.append(finding)

            state = monotonic_state.setdefault(source_key, {"last_time": None, "last_sequence": None, "last_event_id": None})
            if state["last_time"] is not None and event_time < state["last_time"]:
                delta_ms = (state["last_time"] - event_time).total_seconds() * 1000.0
                finding = {
                    "type": "non_monotonic_timestamp",
                    "event_id": event_id,
                    "source_key": source_key,
                    "previous_event_id": state["last_event_id"],
                    "delta_ms": round(delta_ms, 3),
                    "threshold_ms": threshold_ms,
                }
                report["checks"].append(finding)
                anomalies.append(finding)
            state["last_time"] = event_time

            if previous_block is not None and event_time < previous_block.window_end:
                backward_ms = (previous_block.window_end - event_time).total_seconds() * 1000.0
                if backward_ms > threshold_ms:
                    finding = {
                        "type": "cross_block_backward_time",
                        "event_id": event_id,
                        "source_key": source_key,
                        "previous_block_sequence": previous_block.sequence_number,
                        "backward_ms": round(backward_ms, 3),
                        "threshold_ms": threshold_ms,
                    }
                    report["checks"].append(finding)
                    anomalies.append(finding)

        if sequence is not None:
            state = monotonic_state.setdefault(source_key, {"last_time": None, "last_sequence": None, "last_event_id": None})
            if state["last_sequence"] is not None and sequence <= state["last_sequence"]:
                finding = {
                    "type": "non_monotonic_sequence",
                    "event_id": event_id,
                    "source_key": source_key,
                    "previous_event_id": state["last_event_id"],
                    "sequence": sequence,
                    "previous_sequence": state["last_sequence"],
                }
                report["checks"].append(finding)
                anomalies.append(finding)
            state["last_sequence"] = sequence

        state = monotonic_state.setdefault(source_key, {"last_time": None, "last_sequence": None, "last_event_id": None})
        state["last_event_id"] = event_id
        event_reports.append(report)

    source_consistency: list[dict[str, Any]] = []
    auth_skews = grouped_by_kind["authentication"]
    network_skews = grouped_by_kind["network"]
    if auth_skews and network_skews:
        median_auth = statistics.median(auth_skews)
        median_network = statistics.median(network_skews)
        cross_source_skew_ms = abs(median_auth - median_network)
        source_consistency.append(
            {
                "pair": ["authentication", "network"],
                "median_clock_skew_ms": {
                    "authentication": round(median_auth, 3),
                    "network": round(median_network, 3),
                },
                "cross_source_skew_ms": round(cross_source_skew_ms, 3),
                "threshold_ms": threshold_ms,
            }
        )
        if cross_source_skew_ms > threshold_ms:
            anomalies.append(
                {
                    "type": "cross_source_clock_skew",
                    "sources": ["authentication", "network"],
                    "cross_source_skew_ms": round(cross_source_skew_ms, 3),
                    "threshold_ms": threshold_ms,
                }
            )

    return {
        "threshold_ms": threshold_ms,
        "authoritative_time": authoritative_time.isoformat(),
        "event_reports": event_reports,
        "source_consistency": source_consistency,
        "anomalies": anomalies,
        "anomaly_detected": bool(anomalies),
    }


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


def process_cold_events(db: Session, events: list[dict[str, Any]]) -> SealedBlock:
    if not events:
        raise ValueError("cold event batch is empty")

    canonical_events = [_canonical_json_bytes(event) for event in events]
    leaf_hashes = [_sha256_bytes(event_bytes) for event_bytes in canonical_events]
    merkle_root = compute_merkle_root(events)
    payload_hash = merkle_root

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
    anti_timestamp_report = _build_anti_timestamp_report(
        events,
        authoritative_time,
        previous_block,
        str(source.id),
    )

    timestamp_proof = {
        "authority": settings.COLDSTACK_TIMESTAMP_AUTHORITY,
        "authoritative_time": authoritative_time.isoformat(),
        "payload_hash_hex": payload_hash.hex(),
        "chain_hash_hex": chain_hash.hex(),
        "anti_time_stomping_check": anti_timestamp_report,
    }
    rsa_signature = _sign_coldstack_chain_hash(chain_hash)

    block = SealedBlock(
        source_id=source.id,
        sequence_number=sequence_number,
        window_start=window_start,
        window_end=window_end,
        log_count=len(events),
        payload_hash=payload_hash,
        merkle_root=merkle_root,
        chain_hash=chain_hash,
        tsa_token=json.dumps(timestamp_proof, sort_keys=True).encode("utf-8"),
        authoritative_time=authoritative_time,
        rsa_signature=rsa_signature,
        signing_key_id=settings.COLDSTACK_SIGNING_KEY_ID,
        storage_uri="",
        logstash_config_version=settings.LOGSTASH_CONFIG_VERSION,
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
        db.add(HotColdTrace(elastic_event_id=event_id, block_id=block.id, cold_offset=0, storage_uri=block.storage_uri, event_fingerprint=event_id))

    db.commit()
    db.refresh(block)
    return block


def verify_cold_stored_block(db: Session, block_id: UUID) -> dict[str, Any]:
    """
    Recompute Merkle root and chain hash for a cold-sealed block; verify RSA-PSS signature.
    Uses the same material as process_cold_events (not hot-path seal_event_batch).
    """
    block = db.query(SealedBlock).filter(SealedBlock.id == block_id).first()
    if block is None:
        return {"verified": False, "message": "Block not found", "block_id": str(block_id)}

    cold = db.query(ColdStoredBlock).filter(ColdStoredBlock.block_id == block_id).first()
    if cold is None:
        return {"verified": False, "message": "No cold_stored_blocks row for this block", "block_id": str(block_id)}

    events = cold.events
    if not isinstance(events, list) or not events:
        return {"verified": False, "message": "Cold block has no event list", "block_id": str(block_id)}

    merkle_recomputed = compute_merkle_root(events)
    if merkle_recomputed != block.merkle_root:
        return {
            "verified": False,
            "message": "Merkle root mismatch",
            "block_id": str(block_id),
            "expected_merkle_hex": block.merkle_root.hex(),
            "recomputed_merkle_hex": merkle_recomputed.hex(),
        }

    canonical_events = [_canonical_json_bytes(event) for event in events]
    leaf_expected = [_sha256_bytes(b).hex() for b in canonical_events]
    if cold.leaf_hashes != leaf_expected:
        return {"verified": False, "message": "Leaf hash list mismatch", "block_id": str(block_id)}

    if cold.merkle_root_hex != merkle_recomputed.hex():
        return {"verified": False, "message": "Stored merkle_root_hex mismatch", "block_id": str(block_id)}

    prev_block = (
        db.query(SealedBlock)
        .filter(
            SealedBlock.source_id == block.source_id,
            SealedBlock.sequence_number == block.sequence_number - 1,
        )
        .first()
    )
    previous_chain_hash = prev_block.chain_hash if prev_block is not None else b""

    payload_hash = merkle_recomputed
    chain_material = b"|".join(
        [
            previous_chain_hash,
            payload_hash,
            str(block.sequence_number).encode("utf-8"),
            block.window_start.isoformat().encode("utf-8"),
            block.window_end.isoformat().encode("utf-8"),
            block.authoritative_time.isoformat().encode("utf-8"),
            str(block.log_count).encode("utf-8"),
        ]
    )
    chain_hash = _sha256_bytes(chain_material)
    if chain_hash != block.chain_hash:
        return {
            "verified": False,
            "message": "Chain hash mismatch (possible tampering or wrong predecessor)",
            "block_id": str(block_id),
            "expected_chain_hex": block.chain_hash.hex(),
            "recomputed_chain_hex": chain_hash.hex(),
        }

    if cold.chain_hash_hex != chain_hash.hex():
        return {"verified": False, "message": "Cold chain_hash_hex mismatch", "block_id": str(block_id)}

    public_key = _load_coldstack_private_key().public_key()
    try:
        public_key.verify(
            block.rsa_signature,
            chain_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return {"verified": False, "message": "RSA signature verification failed", "block_id": str(block_id)}

    return {
        "verified": True,
        "message": "Merkle, chain, and signature OK",
        "block_id": str(block_id),
        "sequence_number": block.sequence_number,
        "log_count": block.log_count,
        "signature_valid": True,
        "clock_skew_flags": [],
    }


def _worm_key_from_s3_uri(storage_uri: str) -> str:
    if storage_uri.startswith("s3://"):
        rest = storage_uri[5:]
        slash = rest.find("/")
        if slash >= 0:
            return rest[slash + 1 :]
    return storage_uri


def verify_seal_event_batch_block(db: Session, block_id: UUID) -> dict[str, Any]:
    """
    Verify a block produced by seal_event_batch (WORM JSONL payload).
    Signature uses SEALING_PRIVATE_KEY (not coldstack).
    """
    block = db.query(SealedBlock).filter(SealedBlock.id == block_id).first()
    if block is None:
        return {
            "verified": False,
            "signature_valid": False,
            "message": "Block not found",
            "block_id": str(block_id),
            "clock_skew_flags": [],
        }

    if not block.storage_uri.startswith("s3://"):
        return {
            "verified": False,
            "signature_valid": False,
            "message": "Block has no S3 WORM storage_uri",
            "block_id": str(block_id),
            "clock_skew_flags": [],
        }

    from app.core.worm import read_worm_object

    key = _worm_key_from_s3_uri(block.storage_uri)
    raw = read_worm_object(key)
    lines = [ln for ln in raw.split(b"\n") if ln.strip()]
    try:
        events = [json.loads(ln.decode("utf-8")) for ln in lines]
    except json.JSONDecodeError as exc:
        return {
            "verified": False,
            "signature_valid": False,
            "message": f"Invalid JSON in WORM payload: {exc}",
            "block_id": str(block_id),
            "clock_skew_flags": [],
        }

    canonical_lines = [canonical_event_bytes(ev) for ev in events]
    payload = b"\n".join(canonical_lines)
    payload_hash = hashlib.sha256(payload).digest()
    merkle_root = compute_merkle_root(events)

    seq = int(block.sequence_number)
    prev = (
        db.query(SealedBlock)
        .filter(
            SealedBlock.source_id == block.source_id,
            SealedBlock.sequence_number == seq - 1,
        )
        .first()
    )
    prev_hash = b"\x00" * 32 if seq <= 1 or prev is None else prev.chain_hash
    chain_hash = hashlib.sha256(prev_hash + merkle_root + payload_hash + str(seq).encode("utf-8")).digest()

    hashes_ok = (
        payload_hash == block.payload_hash
        and merkle_root == block.merkle_root
        and chain_hash == block.chain_hash
    )

    public_key = _load_private_key().public_key()
    try:
        public_key.verify(
            block.rsa_signature,
            block.chain_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        sig_ok = True
    except InvalidSignature:
        sig_ok = False

    prev_for_time = prev
    time_report = _build_anti_timestamp_report(
        events,
        block.authoritative_time,
        prev_for_time,
        str(block.source_id),
    )
    clock_skew_flags = time_report.get("anomalies", [])

    ok = bool(hashes_ok and sig_ok)
    return {
        "verified": ok,
        "signature_valid": sig_ok,
        "hashes_match": hashes_ok,
        "message": "Merkle, chain, and RSA-PSS OK"
        if ok
        else ("hash mismatch" if not hashes_ok else "signature invalid"),
        "block_id": str(block_id),
        "sequence_number": block.sequence_number,
        "log_count": len(events),
        "clock_skew_flags": clock_skew_flags,
    }


def verify_sealed_block(db: Session, block_id: UUID) -> dict[str, Any]:
    """Route to cold-row verification or hot-path WORM verification."""
    cold = db.query(ColdStoredBlock).filter(ColdStoredBlock.block_id == block_id).first()
    if cold is not None:
        return verify_cold_stored_block(db, block_id)
    return verify_seal_event_batch_block(db, block_id)
