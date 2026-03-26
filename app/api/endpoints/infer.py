from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.ml import MLEngine
from app.ml.normalize import logstash_event_to_log_event
from app.ml.orchestrator import infer_event
from app.ml.schemas import InferAckResponse, InferEventRequest

logger = logging.getLogger("forensiq.api.infer")

router = APIRouter()


def _coerce_event_batch(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and "events" in body and isinstance(body["events"], list):
        return body["events"]
    raise HTTPException(
        status_code=400,
        detail="Expected a JSON array of events or an object with an 'events' array",
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

    raw_events = _coerce_event_batch(body)
    ml: MLEngine = request.app.state.ml

    events = []
    for raw in raw_events:
        if not isinstance(raw, dict):
            continue
        try:
            events.append(logstash_event_to_log_event(raw))
        except Exception as exc:
            logger.warning("normalize failed for one event: %s", exc)

    req = InferEventRequest(events=events)
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
