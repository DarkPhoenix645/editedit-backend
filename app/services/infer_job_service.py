from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from queue import Empty, Queue
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.ml import MLEngine
from app.ml.normalize import logstash_event_to_log_event
from app.ml.orchestrator import infer_event
from app.ml.schemas import InferEventRequest, InferEventResponse
from app.services import case_service
from app.services.log_source_resolve import resolve_log_source_id_str


@dataclass
class InferJob:
    job_id: str
    idempotency_key: str
    created_at: datetime
    status: str = "queued"
    case_id: UUID | None = None
    case_auto_generated: bool = False
    events_received: int = 0
    events_processed: int = 0
    hypotheses_emitted: int = 0
    error: str | None = None
    result: dict[str, Any] = field(default_factory=dict)


class InferJobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, InferJob] = {}
        self._idem_to_job_id: dict[str, str] = {}
        self._queue: Queue[tuple[str, list[dict[str, Any]], UUID | None]] = Queue()
        self._lock = threading.Lock()
        self._worker_started = False

    def start_worker(self, ml: MLEngine) -> None:
        with self._lock:
            if self._worker_started:
                return
            self._worker_started = True
        t = threading.Thread(target=self._worker_loop, args=(ml,), daemon=True, name="infer-job-worker")
        t.start()

    def submit(
        self,
        *,
        job_id: str,
        idempotency_key: str,
        raw_events: list[dict[str, Any]],
        case_id: UUID | None,
    ) -> InferJob:
        with self._lock:
            existing_job_id = self._idem_to_job_id.get(idempotency_key)
            if existing_job_id and existing_job_id in self._jobs:
                return self._jobs[existing_job_id]
            job = InferJob(
                job_id=job_id,
                idempotency_key=idempotency_key,
                created_at=datetime.now(timezone.utc),
                case_id=case_id,
                events_received=len(raw_events),
            )
            self._jobs[job_id] = job
            self._idem_to_job_id[idempotency_key] = job_id
            self._queue.put((job_id, raw_events, case_id))
            return job

    def get(self, job_id: str) -> InferJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _worker_loop(self, ml: MLEngine) -> None:
        while True:
            try:
                job_id, raw_events, case_id = self._queue.get(timeout=1.0)
            except Empty:
                continue
            try:
                self._run_job(job_id, raw_events, case_id, ml)
            finally:
                self._queue.task_done()

    def _run_job(
        self,
        job_id: str,
        raw_events: list[dict[str, Any]],
        case_id: UUID | None,
        ml: MLEngine,
    ) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.status = "processing"

        db: Session = SessionLocal()
        t0 = time.monotonic()
        try:
            resolved_case_id = case_id
            case_auto_generated = False
            if resolved_case_id is None:
                system_case = case_service.get_or_create_system_case(db, source_label="ml-infer")
                resolved_case_id = system_case.id
                case_auto_generated = True

            if resolved_case_id is not None and raw_events:
                allowed = case_service.allowed_log_source_id_strs(db, resolved_case_id)
                if allowed:
                    filtered: list[dict[str, Any]] = []
                    for raw in raw_events:
                        if not isinstance(raw, dict):
                            continue
                        sid = resolve_log_source_id_str(raw, db)
                        if sid and sid in allowed:
                            filtered.append(raw)
                    raw_events = filtered

            events = []
            for raw in raw_events:
                if not isinstance(raw, dict):
                    continue
                try:
                    events.append(logstash_event_to_log_event(raw))
                except Exception:
                    continue

            req = InferEventRequest(events=events, case_id=resolved_case_id)
            out: InferEventResponse = infer_event(
                req,
                db,
                detector=ml.anomaly,
                attack_graph=ml.graph,
                fusion=ml.fusion,
                rag=ml.rag,
                job_id=job_id,
            )
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            with self._lock:
                job = self._jobs[job_id]
                job.status = "done"
                job.case_id = resolved_case_id
                job.case_auto_generated = case_auto_generated
                job.events_processed = out.events_processed
                job.hypotheses_emitted = len(out.hypotheses)
                job.result = {
                    "graph_nodes": out.graph_nodes,
                    "graph_edges": out.graph_edges,
                    "calibrating": out.calibrating,
                    "processing_time_ms": elapsed_ms,
                }
        except Exception as exc:
            db.rollback()
            with self._lock:
                job = self._jobs[job_id]
                job.status = "failed"
                job.error = str(exc)
        finally:
            db.close()
