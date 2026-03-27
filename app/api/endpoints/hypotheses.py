from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.rbac import (
    UserRole,
    can_mutate_hypothesis,
    can_use_ml_interactive,
    can_view_hypotheses,
    user_role_from_db,
)
from app.services import case_service
from app.core.worm import read_worm_line
from app.db.models import ForensicHypothesis, HotColdTrace, HypothesisEvidenceMap, User
from app.db.session import get_db
from app.ml.counterfactual import simulate_counterfactual_modifiers
from app.ml.schemas import (
    CounterfactualModifiersBody,
    CounterfactualModifiersResponse,
    EvidenceItem,
    HypothesisDetail,
    HypothesisOut,
)

logger = logging.getLogger("forensiq.api.hypotheses")

router = APIRouter()


def _role(user: User) -> UserRole:
    return user_role_from_db(getattr(user, "role", None)) or UserRole.INVESTIGATOR


def _require_hypothesis_read(user: User) -> None:
    r = _role(user)
    if not can_view_hypotheses(r):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


def _require_ml_interactive(user: User) -> None:
    r = _role(user)
    if not can_use_ml_interactive(r):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


def _require_hypothesis_mutate(user: User) -> None:
    r = _role(user)
    if not can_mutate_hypothesis(r):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


def _require_viewer_case_access(
    db: Session,
    current_user: User,
    case_id: UUID | None,
) -> None:
    """VIEWER may only see hypotheses tied to investigations they are assigned to."""
    if _role(current_user) != UserRole.VIEWER:
        return
    if case_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Hypothesis is not scoped to an investigation you can access",
        )
    if not case_service.viewer_has_access(db, case_id, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not assigned to this investigation",
        )


def _confidence_to_severity(conf: float | None) -> str:
    if conf is None:
        return "LOW"
    if conf >= 0.7:
        return "CRITICAL"
    if conf >= 0.5:
        return "HIGH"
    if conf >= 0.3:
        return "MEDIUM"
    return "LOW"


def _first_rule_id(rule_trace: Any) -> str | None:
    if not rule_trace or not isinstance(rule_trace, list):
        return None
    for line in rule_trace:
        s = str(line)
        if s.startswith("MATCH "):
            part = s[6:].strip()
            return part.split(":", 1)[0].strip() or None
    return None


def _mitre_list(row: ForensicHypothesis) -> list[str]:
    out: list[str] = []
    if row.mitre_technique_id:
        out.append(row.mitre_technique_id)
    return out


def _resolve_hypothesis(db: Session, hyp_id: str) -> ForensicHypothesis | None:
    try:
        uid = UUID(hyp_id)
        return db.query(ForensicHypothesis).filter(ForensicHypothesis.id == uid).first()
    except ValueError:
        return db.query(ForensicHypothesis).filter(ForensicHypothesis.hypothesis_uid == hyp_id).first()


class HypothesisPatch(BaseModel):
    status: Optional[str] = None
    case_id: Optional[UUID] = None


@router.get("", response_model=list[HypothesisOut])
def list_hypotheses(
    case_id: Optional[UUID] = None,
    min_score: Optional[float] = None,
    offset: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_hypothesis_read(current_user)
    r = _role(current_user)
    q = db.query(ForensicHypothesis).order_by(ForensicHypothesis.created_at.desc())
    if r == UserRole.VIEWER:
        allowed = case_service.viewer_case_ids(db, current_user.id)
        if case_id is not None:
            if case_id not in allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not assigned to this investigation",
                )
            q = q.filter(ForensicHypothesis.case_id == case_id)
        else:
            if not allowed:
                return []
            q = q.filter(ForensicHypothesis.case_id.in_(allowed))
    elif case_id is not None:
        q = q.filter(ForensicHypothesis.case_id == case_id)
    if min_score is not None:
        q = q.filter(ForensicHypothesis.confidence_score >= min_score)

    rows = q.offset(offset).limit(min(limit, 200)).all()
    if not rows:
        return []

    ids = [r.id for r in rows]
    cnt_rows = (
        db.query(HypothesisEvidenceMap.hypothesis_id, func.count(HypothesisEvidenceMap.id))
        .filter(HypothesisEvidenceMap.hypothesis_id.in_(ids))
        .group_by(HypothesisEvidenceMap.hypothesis_id)
        .all()
    )
    counts = {hid: int(c) for hid, c in cnt_rows}

    out: list[HypothesisOut] = []
    for r in rows:
        conf = r.confidence_score or 0.0
        ao = r.anomaly_score or 0.0
        created = r.created_at or datetime.now(timezone.utc)
        out.append(
            HypothesisOut(
                id=r.id,
                hypothesis_uid=r.hypothesis_uid,
                title=(r.title or r.hypotheses or "Untitled")[:512],
                anomaly_score=float(ao),
                confidence_score=float(conf),
                severity=_confidence_to_severity(conf),
                mitre_technique_id=r.mitre_technique_id,
                mitre_technique_name=r.mitre_technique_name,
                mitre_tactic=r.mitre_tactic,
                rule_id=_first_rule_id(r.rule_trace),
                status=r.status or "pending",
                created_at=created,
                evidence_count=counts.get(r.id, 0),
                case_id=r.case_id,
            )
        )
    return out


@router.post("/{hyp_id}/counterfactual", response_model=CounterfactualModifiersResponse)
def hypothesis_counterfactual(
    hyp_id: str,
    body: CounterfactualModifiersBody,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_ml_interactive(current_user)
    row = _resolve_hypothesis(db, hyp_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    uid = row.hypothesis_uid
    if not uid:
        raise HTTPException(
            status_code=400,
            detail="Hypothesis has no hypothesis_uid; re-run inference or rehydrate store",
        )
    ml = request.app.state.ml
    result = simulate_counterfactual_modifiers(uid, body.modifiers, ml.fusion)
    if "not found" in result.get("explanation", "").lower():
        raise HTTPException(status_code=404, detail=result["explanation"])
    return CounterfactualModifiersResponse(
        original_score=result["original_score"],
        modified_score=result["modified_score"],
        would_fire=result["would_fire"],
        explanation=result["explanation"],
    )


@router.get("/{hyp_id}", response_model=HypothesisDetail)
def get_hypothesis(
    hyp_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_hypothesis_read(current_user)
    row = _resolve_hypothesis(db, hyp_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    _require_viewer_case_access(db, current_user, row.case_id)

    links = db.query(HypothesisEvidenceMap).filter(HypothesisEvidenceMap.hypothesis_id == row.id).all()
    evidence: list[EvidenceItem] = []
    reasoning_chain: list[str] = []
    if row.rule_trace and isinstance(row.rule_trace, list):
        reasoning_chain = [str(x) for x in row.rule_trace]

    meta = dict(row.event_metadata or {})
    sym = float(meta.get("symbolic_boost", 0.0))
    neur = float(row.anomaly_score or 0.0)
    conf = float(row.confidence_score or 0.0)

    for link in links:
        fp = link.event_fingerprint or link.elastic_event_id
        trace = None
        if fp:
            trace = db.query(HotColdTrace).filter(HotColdTrace.event_fingerprint == fp).first()
        raw_line: str | None = None
        if trace and trace.storage_uri:
            try:
                key = trace.storage_uri.split("/", 3)[-1]
                blob = read_worm_line(key=key, offset=trace.cold_offset)
                if blob:
                    raw_line = blob.decode("utf-8", errors="replace")
            except Exception as exc:
                logger.debug("WORM read failed for %s: %s", fp, exc)

        evidence.append(
            EvidenceItem(
                elastic_event_id=link.elastic_event_id,
                event_fingerprint=fp,
                block_id=trace.block_id if trace else None,
                cold_offset=trace.cold_offset if trace else None,
                storage_uri=trace.storage_uri if trace else None,
                raw_log_line=raw_line,
            )
        )

    return HypothesisDetail(
        id=row.id,
        hypothesis_uid=row.hypothesis_uid,
        case_id=row.case_id,
        title=(row.title or row.hypotheses or "Untitled")[:512],
        description=row.description,
        hypotheses_legacy=row.hypotheses,
        anomaly_score=neur,
        confidence_score=conf,
        severity=_confidence_to_severity(conf),
        neural_anomaly_score=neur,
        symbolic_risk_score=sym,
        trust_weight=float(row.trust_weight or 0.0),
        pattern_severity=float(row.pattern_severity or 1.0),
        rule_trace=[str(x) for x in row.rule_trace] if row.rule_trace else [],
        reasoning_chain=reasoning_chain,
        fusion_policy_hash=row.fusion_policy_hash,
        evidence_ids=list(row.evidence_ids) if row.evidence_ids else None,
        mitre_technique_id=row.mitre_technique_id,
        mitre_technique_name=row.mitre_technique_name,
        mitre_tactic=row.mitre_tactic,
        mitre_techniques=_mitre_list(row),
        rule_id=_first_rule_id(row.rule_trace),
        status=row.status or "pending",
        event_trust_tier=row.event_trust_tier,
        event_action=row.event_action,
        event_metadata=meta,
        created_at=row.created_at or datetime.now(timezone.utc),
        evidence=evidence,
    )


@router.patch("/{hyp_id}", response_model=HypothesisOut)
def patch_hypothesis(
    hyp_id: str,
    body: HypothesisPatch,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_hypothesis_mutate(current_user)
    row = _resolve_hypothesis(db, hyp_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    if body.status is not None:
        row.status = body.status
    if body.case_id is not None:
        row.case_id = body.case_id
    db.commit()
    db.refresh(row)

    n_ev = (
        db.query(func.count(HypothesisEvidenceMap.id))
        .filter(HypothesisEvidenceMap.hypothesis_id == row.id)
        .scalar()
    )
    conf = row.confidence_score or 0.0
    ao = row.anomaly_score or 0.0
    return HypothesisOut(
        id=row.id,
        hypothesis_uid=row.hypothesis_uid,
        title=(row.title or row.hypotheses or "Untitled")[:512],
        anomaly_score=float(ao),
        confidence_score=float(conf),
        severity=_confidence_to_severity(conf),
        mitre_technique_id=row.mitre_technique_id,
        mitre_technique_name=row.mitre_technique_name,
        mitre_tactic=row.mitre_tactic,
        rule_id=_first_rule_id(row.rule_trace),
        status=row.status or "pending",
        created_at=row.created_at or datetime.now(timezone.utc),
        evidence_count=int(n_ev or 0),
        case_id=row.case_id,
    )
