"""Phase 5 inference orchestration (no separate cold_engine sealing)."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.db.models import ForensicHypothesis, HypothesisEvidenceMap, LogSource
from app.ml.counterfactual import hypothesis_store
from app.ml.fusion import TRUST_TIERS, FusionEngine
from app.ml.rag import RAGEngine
from app.ml.schemas import Hypothesis, HypothesisStatus, InferEventRequest, InferEventResponse, LogEvent
from app.ml.anomaly import AnomalyDetector
from app.ml.graph import AttackGraph

logger = logging.getLogger("forensiq.ml.orchestrator")


def _uuid(sid: str) -> UUID:
    return UUID(str(sid))


def _compute_symbolic_risk(event: LogEvent) -> float:
    risk = 0.0
    meta = event.metadata or {}
    if meta.get("after_hours"):
        risk += 0.25
    if meta.get("restricted_asset"):
        risk += 0.3
    high_risk_actions = {
        "ESCALATION",
        "DATA_EXPORT",
        "SUDO",
        "SUDO_EXEC",
        "FILE_UPLOAD",
        "HTTP_POST",
        "CLEAR_LOGS",
        "DISABLE_AUDIT",
        "DELETE_HISTORY",
        "STOP_SERVICE",
    }
    medium_risk_actions = {
        "FILE_ACCESS",
        "FILE_WRITE",
        "SSH",
        "SSH_AUTH_FAIL",
        "RDP",
        "RDP_CONNECT",
        "SMB_CONNECT",
        "SMB_MOUNT",
        "REMOTE_EXEC",
        "TCP_CONNECT",
        "AUTH_FAIL",
        "AUTH_SUCCESS",
        "CLOUD_LOGIN",
        "API_CALL",
        "WINRM",
    }
    if event.action in high_risk_actions:
        risk += 0.3
    elif event.action in medium_risk_actions:
        risk += 0.15
    if event.dest_ip and not str(event.dest_ip).startswith(("10.", "172.", "192.168.")):
        risk += 0.2
    return min(risk, 1.0)


def _resolve_trust_weight(event: LogEvent, source_cache: dict[str, LogSource]) -> float:
    if event.source_id and event.source_id in source_cache:
        return float(source_cache[event.source_id].dynamic_trust_score)
    return TRUST_TIERS.get(event.trust_tier.value, TRUST_TIERS["unknown"])


def _compute_event_fingerprint(event_dict: dict) -> str:
    canonical = json.dumps(event_dict, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_reasoning_chain(
    event: LogEvent,
    neural_score: float,
    symbolic_boost: float,
    fusion_result: dict,
) -> list[str]:
    threshold = 0.3
    final_score = float(fusion_result.get("score", 0.0))
    decision = "HYPOTHESIS_EMITTED" if final_score > threshold else "NO_HYPOTHESIS"
    matched_rule = next(
        (x for x in fusion_result.get("rule_trace", []) if x.startswith("MATCH ")),
        "MATCH none",
    )
    return [
        f"Neural anomaly score: {neural_score:.4f}",
        f"Symbolic risk score: {symbolic_boost:.4f}",
        f"Trust tier '{event.trust_tier.value}' weight: {fusion_result.get('trust_weight', 0.0):.4f}",
        f"Policy fusion: {matched_rule}",
        f"Final confidence: {final_score:.4f} (threshold={threshold:.2f}) -> {decision}",
    ]


def _apply_p01_refinement(
    source_cache: dict[str, LogSource],
    anomalies: dict[str, list[float]],
    db: Session,
) -> None:
    alpha = 0.05
    for source_id_str, scores in anomalies.items():
        if not scores or source_id_str not in source_cache:
            continue
        source = source_cache[source_id_str]
        mean_anomaly = sum(scores) / len(scores)
        old_score = float(source.dynamic_trust_score)
        new_score = old_score * (1 - alpha * min(mean_anomaly, 1.0))
        source.dynamic_trust_score = round(max(0.1, min(1.0, new_score)), 6)


def infer_event(
    req: InferEventRequest,
    db: Session,
    detector: AnomalyDetector,
    attack_graph: AttackGraph,
    fusion: FusionEngine,
    rag: RAGEngine,
) -> InferEventResponse:
    t0 = time.monotonic()
    if not req.events:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return InferEventResponse(
            hypotheses=[],
            events_processed=0,
            graph_nodes=attack_graph.stats["nodes"],
            graph_edges=attack_graph.stats["edges"],
            calibrating=detector.is_calibrating,
            rag_ingest_ok=True,
            processing_time_ms=elapsed_ms,
        )

    rag_stats = rag.ingest_events([e.model_dump(mode="json") for e in req.events], db=db)
    rag_ingest_ok = rag_stats.get("failed_db", 0) == 0

    source_ids = {e.source_id for e in req.events if e.source_id}
    source_cache: dict[str, LogSource] = {}
    if source_ids:
        try:
            uuid_set = {_uuid(sid) for sid in source_ids if sid}
            sources = db.query(LogSource).filter(LogSource.id.in_(uuid_set)).all()
            source_cache = {str(s.id): s for s in sources}
        except (ValueError, TypeError):
            logger.warning("Invalid UUID in source_ids: %s", source_ids)

    hypotheses: list[Hypothesis] = []
    anomalies: defaultdict[str, list[float]] = defaultdict(list)

    for event in req.events:
        ev_payload = event.model_dump(mode="json")
        if isinstance(ev_payload.get("trust_tier"), str):
            pass
        else:
            ev_payload["trust_tier"] = event.trust_tier.value

        neural_score = detector.score_event(ev_payload)
        symbolic_boost = _compute_symbolic_risk(event)
        anomaly_score = min(1.0, (neural_score * 0.4) + (symbolic_boost * 0.6))

        if event.source_id:
            anomalies[event.source_id].append(anomaly_score)

        target = event.dest_ip or event.resource or "unknown"
        attack_graph.add_event(
            event_id=event.event_id,
            source=event.source_ip,
            target=str(target),
            action=event.action,
            timestamp=event.timestamp,
            metadata=event.metadata,
        )

        trust_weight = _resolve_trust_weight(event, source_cache)
        meta = event.metadata or {}
        symbolic_flags = {
            "after_hours": bool(meta.get("after_hours")),
            "restricted_asset": bool(meta.get("restricted_asset")),
            "symbolic_boost": symbolic_boost,
        }
        fusion_result = fusion.evaluate(
            anomaly_score=anomaly_score,
            trust_tier=event.trust_tier.value,
            action=event.action,
            metadata=event.metadata,
            trust_weight=trust_weight,
            event_for_mitre=ev_payload,
            symbolic_risk_flags=symbolic_flags,
        )

        elastic_event_id = event.fingerprint or _compute_event_fingerprint(ev_payload)

        if fusion_result["score"] > 0.3:
            hyp_id = f"HYP-{uuid4().hex[:8]}"
            hypothesis = Hypothesis(
                hypothesis_id=hyp_id,
                title=f"Anomalous {event.action} by {event.user_id}",
                description=(
                    f"User '{event.user_id}' performed '{event.action}' from {event.source_ip} "
                    f"targeting '{target}'. Fusion score: {fusion_result['score']:.4f}"
                ),
                score=fusion_result["score"],
                anomaly_score=fusion_result["anomaly_score"],
                trust_weight=fusion_result["trust_weight"],
                pattern_severity=fusion_result["pattern_severity"],
                rule_trace=fusion_result["rule_trace"],
                evidence_ids=[elastic_event_id],
                status=HypothesisStatus.ACTIVE,
                mitre_techniques=fusion_result.get("mitre_techniques", []),
                mitre_technique_id=fusion_result.get("mitre_technique_id"),
                mitre_technique_name=fusion_result.get("mitre_technique_name"),
                mitre_tactic=fusion_result.get("mitre_tactic"),
                cryptographic_evidence_snippet=f"fingerprint:{elastic_event_id}",
                neuro_symbolic_reasoning_chain=_build_reasoning_chain(
                    event=event,
                    neural_score=neural_score,
                    symbolic_boost=symbolic_boost,
                    fusion_result=fusion_result,
                ),
            )
            hypotheses.append(hypothesis)
            hypothesis_store[hyp_id] = {
                **hypothesis.model_dump(mode="json"),
                "trust_tier": event.trust_tier.value,
                "action": event.action,
                "metadata": event.metadata,
            }

            db_hyp = ForensicHypothesis(
                hypothesis_uid=hyp_id,
                generation_source="forensiq-v0.1.0",
                anomaly_score=fusion_result["anomaly_score"],
                confidence_score=fusion_result["score"],
                trust_weight=fusion_result["trust_weight"],
                pattern_severity=fusion_result["pattern_severity"],
                rule_trace=fusion_result["rule_trace"],
                fusion_policy_hash=fusion.policy_hash,
                title=hypothesis.title,
                description=hypothesis.description,
                evidence_ids=[elastic_event_id],
                hypotheses=hypothesis.description,
                status="active",
                event_trust_tier=event.trust_tier.value,
                event_action=event.action,
                event_metadata=dict(event.metadata or {}),
                mitre_technique_id=fusion_result.get("mitre_technique_id"),
                mitre_technique_name=fusion_result.get("mitre_technique_name"),
                mitre_tactic=fusion_result.get("mitre_tactic"),
            )
            db.add(db_hyp)
            db.flush()

            db.add(
                HypothesisEvidenceMap(
                    hypothesis_id=db_hyp.id,
                    elastic_event_id=elastic_event_id,
                    event_fingerprint=elastic_event_id,
                    evidence_weight=1.0,
                )
            )

    _apply_p01_refinement(source_cache, anomalies, db)
    db.commit()

    hypotheses.sort(key=lambda h: h.score, reverse=True)
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    return InferEventResponse(
        hypotheses=hypotheses,
        events_processed=len(req.events),
        graph_nodes=attack_graph.stats["nodes"],
        graph_edges=attack_graph.stats["edges"],
        block_id=None,
        calibrating=detector.is_calibrating,
        rag_ingest_ok=rag_ingest_ok,
        processing_time_ms=elapsed_ms,
    )
