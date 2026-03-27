from __future__ import annotations

import logging
from typing import Any
from uuid import UUID
from uuid import uuid4

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.ml import MLEngine
from app.ml.schemas import InferAckResponse, InferJobStatusResponse
from app.services import case_service
from app.services.infer_job_service import InferJobManager

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


@router.post("/infer", response_model=InferAckResponse, status_code=202)
def ml_infer(
    request: Request,
    body: Any = Body(...),
    db: Session = Depends(get_db),
    x_logstash_secret: str = Header(..., alias="X-Logstash-Secret"),
    x_idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
):
    if x_logstash_secret != settings.LOGSTASH_SHARED_SECRET:
        raise HTTPException(status_code=403, detail="Invalid secret")

    raw_events, case_id = _coerce_infer_payload(body)

    if case_id is not None:
        case_row = case_service.get_case(db, case_id)
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found")
    ml: MLEngine = request.app.state.ml
    manager: InferJobManager = request.app.state.infer_job_manager
    manager.start_worker(ml)
    idem_key = x_idempotency_key or f"{case_id or 'auto'}:{len(raw_events)}:{uuid4().hex}"
    job = manager.submit(
        job_id=f"job-{uuid4().hex[:16]}",
        idempotency_key=idem_key,
        raw_events=raw_events,
        case_id=case_id,
    )
    return InferAckResponse(
        job_id=job.job_id,
        status=job.status,
        case_id=job.case_id,
        case_auto_generated=job.case_auto_generated,
        events_received=job.events_received,
    )


@router.get("/infer/jobs/{job_id}", response_model=InferJobStatusResponse)
def ml_infer_job_status(
    request: Request,
    job_id: str,
):
    manager: InferJobManager = request.app.state.infer_job_manager
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return InferJobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        case_id=job.case_id,
        case_auto_generated=job.case_auto_generated,
        events_received=job.events_received,
        events_processed=job.events_processed,
        hypotheses_emitted=job.hypotheses_emitted,
        error=job.error,
        result=job.result,
    )
