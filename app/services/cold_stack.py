import base64
import hashlib
import json
import statistics
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.canonical_json import canonical_json_bytes
from app.core.config import settings
from app.db.models import ColdStoredBlock, HotColdTrace, LogSource, SealedBlock
from app.services.cold_object_store import store_cold_block_payload


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
    return _sha256_hex(canonical_json_bytes(event))

def process_cold_events(db: Session, events: list[dict[str, Any]]) -> SealedBlock:
    if not events:
        raise ValueError("cold event batch is empty")

    canonical_events = [canonical_json_bytes(event) for event in events]
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

    leaf_hashes_hex = [leaf_hash.hex() for leaf_hash in leaf_hashes]
    object_reference = store_cold_block_payload(
        block_id=str(block.id),
        source_id=str(source.id),
        sequence_number=sequence_number,
        payload={
            "schema_version": 1,
            "block_id": str(block.id),
            "source_id": str(source.id),
            "sequence_number": sequence_number,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "authoritative_time": authoritative_time.isoformat(),
            "log_count": len(events),
            "payload_hash_hex": payload_hash.hex(),
            "chain_hash_hex": chain_hash.hex(),
            "signing_key_id": settings.COLDSTACK_SIGNING_KEY_ID,
            "rsa_signature_b64": base64.b64encode(rsa_signature).decode("ascii"),
            "leaf_hashes": leaf_hashes_hex,
            "timestamp_proof": timestamp_proof,
            "events": events,
        },
    )
    block.storage_uri = object_reference.storage_uri

    stored_block = ColdStoredBlock(
        block_id=block.id,
        source_id=source.id,
        object_bucket=object_reference.bucket,
        object_key=object_reference.object_key,
        object_version_id=object_reference.version_id,
        object_etag=object_reference.etag,
        object_sha256_hex=object_reference.sha256_hex,
        object_size_bytes=object_reference.size_bytes,
        object_retention_mode=object_reference.retention_mode,
        object_retention_until=object_reference.retention_until,
        object_legal_hold=object_reference.legal_hold,
        leaf_hashes=leaf_hashes_hex,
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
