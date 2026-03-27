from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.ml import MLEngine
from app.ml.normalize import logstash_event_to_log_event
from app.ml.orchestrator import infer_event
from app.ml.schemas import InferAckResponse, InferEventRequest
from app.services import case_service
from app.services.log_source_resolve import resolve_log_source_id_str

logger = logging.getLogger("forensiq.api.infer")

router = APIRouter()


def _coerce_infer_payload(body: Any) -> tuple[list[dict[str, Any]], UUID | None]:
    if isinstance(body, list):
        return body, None
    if isinstance(body, dict):
        cid = body.get("case_id")
        case_uuid: UUID | None = None
        if cid is not None:
            try:
                case_uuid = UUID(str(cid))
            except ValueError as e:
                raise HTTPException(status_code=400, detail="Invalid case_id") from e
        if "events" not in body:
            raise HTTPException(
                status_code=400,
                detail="JSON object must include an 'events' array (optional 'case_id')",
            )
        ev = body["events"]
        if not isinstance(ev, list):
            raise HTTPException(status_code=400, detail="'events' must be an array")
        return ev, case_uuid
    raise HTTPException(
        status_code=400,
        detail="Expected a JSON array of events or an object with 'events' and optional 'case_id'",
    )


@router.post("/infer", response_model=InferAckResponse)
def ml_infer(
    request: Request,
    body: Any = Body(...),
    db: Session = Depends(get_db),
    x_logstash_secret: str = Header(..., alias="X-Logstash-Secret"),
):
    if x_logstash_secret != settings.LOGSTASH_SHARED_SECRET:
        raise HTTPException(status_code=403, detail="Invalid secret")

    raw_events, case_id = _coerce_infer_payload(body)

    if case_id is not None:
        case_row = case_service.get_case(db, case_id)
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found")
        if raw_events:
            allowed = case_service.allowed_log_source_id_strs(db, case_id)
            if not allowed:
                raise HTTPException(
                    status_code=422,
                    detail="Attach at least one log source to this investigation before inference",
                )
            filtered: list[dict[str, Any]] = []
            for raw in raw_events:
                if not isinstance(raw, dict):
                    continue
                sid = resolve_log_source_id_str(raw, db)
                if sid and sid in allowed:
                    filtered.append(raw)
            if not filtered:
                raise HTTPException(
                    status_code=422,
                    detail="No events matched this investigation's log sources "
                    "(set top-level source_id or ensure agent/host matches a known log source)",
                )
            raw_events = filtered

    ml: MLEngine = request.app.state.ml

    events = []
    for raw in raw_events:
        if not isinstance(raw, dict):
            continue
        try:
            events.append(logstash_event_to_log_event(raw))
        except Exception as exc:
            logger.warning("normalize failed for one event: %s", exc)

    req = InferEventRequest(events=events, case_id=case_id)
    out = infer_event(
        req,
        db,
        detector=ml.anomaly,
        attack_graph=ml.graph,
        fusion=ml.fusion,
        rag=ml.rag,
    )

    return InferAckResponse(
        events_processed=out.events_processed,
        hypotheses_emitted=len(out.hypotheses),
        calibrating=out.calibrating,
        graph_nodes=out.graph_nodes,
        graph_edges=out.graph_edges,
        processing_time_ms=out.processing_time_ms,
    )
