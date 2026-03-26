from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import LogEvent as LogEventRow

logger = logging.getLogger("forensiq.ml.rag")


class RAGEngine:
    def __init__(self) -> None:
        self.event_store: dict[str, dict] = {}

    def _fingerprint(self, event: dict) -> str:
        return str(event.get("event_id") or event)

    def ingest_events(self, events: list[dict], db: Session | None = None) -> dict[str, Any]:
        stats: dict[str, Any] = {"persisted_db": 0, "failed_db": 0, "memory_writes": 0}
        for event in events:
            fingerprint = self._fingerprint(event)
            if db is not None:
                try:
                    ts_str = event.get("timestamp")
                    if ts_str:
                        ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                    else:
                        ts = datetime.now(timezone.utc)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)

                    src_raw = event.get("source_id")
                    source_uuid = None
                    if src_raw:
                        try:
                            source_uuid = UUID(str(src_raw))
                        except (ValueError, TypeError):
                            source_uuid = None

                    with db.begin_nested():
                        db_row = LogEventRow(
                            event_json=event,
                            event_time=ts,
                            source_id=source_uuid,
                        )
                        db.add(db_row)
                        db.flush()
                    self.event_store[fingerprint] = event
                    stats["persisted_db"] += 1
                    stats["memory_writes"] += 1
                except Exception as exc:
                    logger.error("RAG DB persist failed: %s", exc)
                    stats["failed_db"] += 1
                    continue
            else:
                self.event_store[fingerprint] = event
                stats["memory_writes"] += 1
        logger.info("RAG store now holds %d events", len(self.event_store))
        return stats

    def recover(self, db: Session) -> int:
        batch_size = settings.RAG_RECOVERY_BATCH_SIZE
        offset = 0
        recovered = 0
        start = time.monotonic()
        while True:
            rows = (
                db.execute(select(LogEventRow).order_by(LogEventRow.event_time).limit(batch_size).offset(offset))
                .scalars()
                .all()
            )
            if not rows:
                break
            for row in rows:
                fingerprint = self._fingerprint(row.event_json)
                self.event_store[fingerprint] = row.event_json
            recovered += len(rows)
            offset += batch_size
        elapsed = time.monotonic() - start
        if recovered == 0:
            logger.warning("RAG recovery: log_events table is empty")
        else:
            logger.info("RAG recovered %d events in %.2fs", recovered, elapsed)
        return recovered

    def query(self, query_text: str, context_event_ids: list[str] | None = None) -> dict[str, Any]:
        query_lower = query_text.lower()
        relevant = self._retrieve(query_lower, context_event_ids)
        if not relevant:
            return {"answer": "No matching evidence found for this query.", "cited_event_ids": [], "confidence": 0.0}
        answer = self._synthesize(query_lower, relevant)
        cited_ids = [e.get("event_id", "") for e in relevant]
        return {
            "answer": answer,
            "cited_event_ids": cited_ids,
            "confidence": min(0.9, 0.3 + 0.1 * len(relevant)),
        }

    def _retrieve(self, query: str, context_ids: list[str] | None) -> list[dict]:
        pool = self.event_store
        if context_ids:
            pool = {eid: e for eid, e in pool.items() if eid in context_ids}
        results: list[dict] = []
        keywords = query.split()
        for eid, event in pool.items():
            event_str = str(event).lower()
            hits = sum(1 for kw in keywords if kw in event_str)
            if hits > 0:
                results.append({**event, "_relevance": hits})
        results.sort(key=lambda x: x["_relevance"], reverse=True)
        return results[:10]

    def _synthesize(self, query: str, events: list[dict]) -> str:
        lines = [f"Based on {len(events)} matching events:"]
        for e in events[:5]:
            ts = e.get("timestamp", "unknown")
            user = e.get("user_id", "unknown")
            action = e.get("action", "unknown")
            resource = e.get("resource", "N/A")
            trust = e.get("trust_tier", "N/A")
            lines.append(
                f"  - [{ts}] User '{user}' performed '{action}' on '{resource}' (trust: {trust})"
            )
        if len(events) > 5:
            lines.append(f"  ... and {len(events) - 5} more events.")
        return "\n".join(lines)
