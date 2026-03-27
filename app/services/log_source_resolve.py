"""Resolve log_sources.id from Logstash-shaped payloads (aligns with cold ingest heuristics)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.models import LogSource


def resolve_log_source_id_str(raw: dict[str, Any], db: Session) -> str | None:
    sid = raw.get("source_id")
    if sid is not None and str(sid).strip():
        return str(sid)
    agent = (
        (raw.get("agent") or {}).get("id")
        or (raw.get("host") or {}).get("name")
        or "unknown-source"
    )
    src = db.query(LogSource).filter(LogSource.agent_id == agent).first()
    return str(src.id) if src else None
