from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid5, NAMESPACE_URL

from fastapi import APIRouter, Body, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import get_current_user
from app.core.rbac import UserRole, can_verify_sealed_block, user_role_from_db
from app.core.worm import read_worm_line
from app.db.models import HotColdTrace, LogSource, User
from app.db.session import get_db
from app.schemas.cold_ingest import ColdIngestResponse as ColdStackIngestResponse
from app.schemas.ingest import ColdIngestResponse
from app.services.ocsf_rederive_v1_0 import apply_ocsf_mapping_v1_0
from app.services.sealing_service import (
    compute_fingerprint,
    compute_fingerprint_values_only,
    process_cold_events,
    seal_event_batch,
    verify_sealed_block,
)

router = APIRouter()


def _role(user: User) -> UserRole:
    return user_role_from_db(getattr(user, "role", None)) or UserRole.INVESTIGATOR


def _coerce_stack_body(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        events = payload
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        events = payload["events"]
    elif isinstance(payload, dict):
        events = [payload]
    else:
        raise HTTPException(status_code=422, detail="body must be a JSON object or array")

    if not events:
        raise HTTPException(status_code=422, detail="at least one event required")
    for event in events:
        if not isinstance(event, dict):
            raise HTTPException(status_code=422, detail="each event must be a JSON object")
    return events


@router.post("/stack-ingest", response_model=ColdStackIngestResponse)
def ingest_cold_stack(
    body: Any = Body(...),
    db: Session = Depends(get_db),
    x_logstash_secret: str = Header(..., alias="X-Logstash-Secret"),
):
    """Cold-stack path: `process_cold_events` + `ColdStoredBlock` (same as legacy `cold_ingest` module)."""
    if x_logstash_secret != settings.LOGSTASH_SHARED_SECRET:
        raise HTTPException(status_code=403, detail="Invalid secret")
    events = _coerce_stack_body(body)
    try:
        block = process_cold_events(db, events)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ColdStackIngestResponse(
        source_id=block.source_id,
        block_id=block.id,
        sequence_number=block.sequence_number,
        sealed_event_count=block.log_count,
        authoritative_time=block.authoritative_time,
    )


@router.post("/ingest", response_model=ColdIngestResponse)
def ingest_cold_batch(
    events: list[dict],
    db: Session = Depends(get_db),
    x_logstash_secret: str = Header(..., alias="X-Logstash-Secret"),
):
    if x_logstash_secret != settings.LOGSTASH_SHARED_SECRET:
        raise HTTPException(status_code=403, detail="Invalid secret")

    if not events:
        return ColdIngestResponse(sealed=False, reason="empty_batch")

    source_agent = (
        events[0].get("agent", {}).get("id")
        or events[0].get("host", {}).get("name")
        or "unknown-source"
    )
    source = db.query(LogSource).filter(LogSource.agent_id == source_agent).first()
    if source is None:
        # Cold ingest log source defaults are only used as coarse trust metadata.
        # Trust tier values themselves are driven per-event by forensiq.trust_tier.
        dataset = events[0].get("event", {}).get("dataset") or events[0].get("dataset") or ""
        static_trust_level = "os"
        if dataset.startswith("application."):
            static_trust_level = "application"
        elif dataset.startswith("cloud."):
            static_trust_level = "cloud"
        elif dataset.startswith("iot."):
            static_trust_level = "iot"
        elif dataset.startswith("kernel.") or dataset.startswith("system.kernel"):
            static_trust_level = "kernel"
        elif dataset.startswith("iam.") or dataset.startswith("identity.") or dataset == "system.auth":
            static_trust_level = "iam"
        elif dataset.startswith("system.auth"):
            static_trust_level = "iam"

        source = LogSource(
            agent_id=source_agent,
            source_name=source_agent,
            static_trust_level=static_trust_level,
            dynamic_trust_score=1.0,
            provider_type="elastic-agent",
            os_type=str(events[0].get("host", {}).get("os", {}).get("name", "unknown")),
        )
        db.add(source)
        db.flush()

    for event in events:
        fq = event.setdefault("forensiq", {})
        expected_fingerprint = compute_fingerprint(event)
        legacy_expected_fingerprint = compute_fingerprint_values_only(event)
        incoming_fingerprint = fq.get("event_fingerprint")
        if incoming_fingerprint and incoming_fingerprint not in {
            expected_fingerprint,
            legacy_expected_fingerprint,
        }:
            fq["fingerprint_verification"] = "mismatch"
            fq["expected_fingerprint"] = expected_fingerprint
            fq["legacy_expected_fingerprint"] = legacy_expected_fingerprint
        else:
            fq["fingerprint_verification"] = "ok"
        fq["event_fingerprint"] = incoming_fingerprint or expected_fingerprint
        event.setdefault("event", {})
        if not event["event"].get("id"):
            event["event"]["id"] = event.get("event_id") or fq["event_fingerprint"]
        if not event.get("event_id"):
            event["event_id"] = event["event"]["id"]
        event["event"]["hash"] = fq["event_fingerprint"]

    sealed = seal_event_batch(db=db, source_id=str(source.id), events=events)

    for event, offset in zip(events, sealed.offsets):
        fingerprint = event["forensiq"]["event_fingerprint"]
        synthetic_elastic_id = str(uuid5(NAMESPACE_URL, fingerprint))
        existing = (
            db.query(HotColdTrace)
            .filter(HotColdTrace.event_fingerprint == fingerprint)
            .first()
        )
        if existing:
            continue
        db.add(
            HotColdTrace(
                event_fingerprint=fingerprint,
                elastic_event_id=synthetic_elastic_id,
                cold_offset=offset,
                storage_uri=sealed.block.storage_uri,
                block_id=sealed.block.id,
            )
        )

    db.commit()
    return ColdIngestResponse(sealed=True, block_id=str(sealed.block.id))


@router.get("/rederive/{event_fingerprint}")
def rederive_ocsf_by_fingerprint(
    event_fingerprint: str,
    db: Session = Depends(get_db),
):
    trace = (
        db.query(HotColdTrace)
        .filter(HotColdTrace.event_fingerprint == event_fingerprint)
        .first()
    )
    if trace is None:
        raise HTTPException(status_code=404, detail="Fingerprint not found")

    key = trace.storage_uri.split("/", 3)[-1]
    raw_line = read_worm_line(key=key, offset=trace.cold_offset)
    if not raw_line:
        raise HTTPException(status_code=404, detail="Raw event missing in WORM")

    raw_event = json.loads(raw_line)
    return apply_ocsf_mapping_v1_0(raw_event)


@router.post("/verify/{block_id}")
def verify_cold_block(
    block_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Recompute Merkle/chain and verify RSA (WORM `seal_event_batch` or `cold_stored_blocks` row)."""
    if not can_verify_sealed_block(_role(current_user)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
    return verify_sealed_block(db, block_id)
