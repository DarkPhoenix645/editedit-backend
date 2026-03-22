import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.cold_ingest import ColdIngestResponse
from app.services.cold_stack import process_cold_events

router = APIRouter()


def _coerce_events(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        events = payload
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        events = payload["events"]
    elif isinstance(payload, dict):
        events = [payload]
    else:
        raise HTTPException(status_code=422, detail="payload must be a JSON object or array")

    if not events:
        raise HTTPException(status_code=422, detail="payload must contain at least one event")

    for event in events:
        if not isinstance(event, dict):
            raise HTTPException(status_code=422, detail="each event must be a JSON object")
    return events


@router.post("/cold-ingest", response_model=ColdIngestResponse)
async def cold_ingest(request: Request, db: Session = Depends(get_db)):
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="request body must be valid JSON") from exc

    events = _coerce_events(payload)

    try:
        block = process_cold_events(db, events)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise

    return ColdIngestResponse(
        source_id=block.source_id,
        block_id=block.id,
        sequence_number=block.sequence_number,
        stored_events=block.log_count,
        authoritative_time=block.authoritative_time,
    )
