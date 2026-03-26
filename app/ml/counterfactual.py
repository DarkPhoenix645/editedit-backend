from __future__ import annotations

import logging
from typing import Any

from app.ml.fusion import FusionEngine

logger = logging.getLogger("forensiq.ml.counterfactual")

hypothesis_store: dict[str, dict] = {}


def rehydrate_hypothesis_store_from_db(db: Any) -> int:
    from app.db.models import ForensicHypothesis

    count = 0
    rows = db.query(ForensicHypothesis).filter(ForensicHypothesis.hypothesis_uid.isnot(None)).all()
    for h in rows:
        uid = h.hypothesis_uid
        if not uid:
            continue
        hypothesis_store[uid] = {
            "hypothesis_id": uid,
            "case_id": str(h.case_id) if h.case_id else None,
            "title": h.title or "",
            "description": h.description or h.hypotheses or "",
            "score": h.confidence_score or 0.0,
            "anomaly_score": h.anomaly_score or 0.0,
            "trust_weight": h.trust_weight or 1.0,
            "pattern_severity": h.pattern_severity or 1.0,
            "rule_trace": h.rule_trace or [],
            "evidence_ids": h.evidence_ids or [],
            "status": h.status or "active",
            "trust_tier": h.event_trust_tier or "unknown",
            "action": h.event_action or "UNKNOWN",
            "metadata": dict(h.event_metadata or {}),
        }
        count += 1
    return count


def simulate_counterfactual(
    hypothesis_id: str,
    modify_attribute: str,
    modify_value: Any,
    fusion: FusionEngine,
) -> dict[str, Any]:
    hyp = hypothesis_store.get(hypothesis_id)
    if not hyp:
        return {
            "original_score": 0.0,
            "modified_score": 0.0,
            "delta": 0.0,
            "explanation": f"Hypothesis {hypothesis_id} not found in temporary store",
        }

    original_score = hyp.get("score", 0.0)
    current_anomaly = hyp.get("anomaly_score", 0.5)
    current_trust_tier = hyp.get("trust_tier", "unknown")
    current_action = hyp.get("action", "UNKNOWN")
    current_metadata = dict(hyp.get("metadata") or {})
    current_trust_weight = hyp.get("trust_weight", 0.5)

    if modify_attribute == "anomaly_score":
        current_anomaly = float(modify_value)
    elif modify_attribute == "trust_tier":
        current_trust_tier = str(modify_value)
        current_trust_weight = None
    elif modify_attribute == "trust_weight":
        current_trust_weight = float(modify_value)
    elif modify_attribute == "action":
        current_action = str(modify_value)
    elif modify_attribute.startswith("metadata."):
        meta_key = modify_attribute.split(".", 1)[1]
        current_metadata[meta_key] = modify_value

    result = fusion.evaluate(
        anomaly_score=current_anomaly,
        trust_tier=current_trust_tier,
        action=current_action,
        metadata=current_metadata,
        trust_weight=current_trust_weight,
    )

    modified_score = result["score"]
    delta = round(modified_score - original_score, 6)
    explanation = (
        f"Changing '{modify_attribute}' to '{modify_value}' moved score from {original_score:.4f} "
        f"to {modified_score:.4f} (delta: {delta:+.4f}). "
        f"Rules fired: {','.join(result.get('matched_rules', [])) or 'none'}."
    )
    logger.info("Counterfactual on %s: %s", hypothesis_id, explanation)
    return {
        "original_score": original_score,
        "modified_score": modified_score,
        "delta": delta,
        "explanation": explanation,
    }


def simulate_counterfactual_modifiers(
    hypothesis_id: str,
    modifiers: dict[str, Any],
    fusion: FusionEngine,
    *,
    fire_threshold: float = 0.3,
) -> dict[str, Any]:
    """Apply multiple attribute overrides then one fusion.evaluate (plan §5.5 style)."""
    hyp = hypothesis_store.get(hypothesis_id)
    if not hyp:
        return {
            "original_score": 0.0,
            "modified_score": 0.0,
            "would_fire": False,
            "explanation": f"Hypothesis {hypothesis_id} not found in temporary store",
        }

    original_score = float(hyp.get("score", 0.0))
    current_anomaly = float(hyp.get("anomaly_score", 0.5))
    current_trust_tier = str(hyp.get("trust_tier", "unknown"))
    current_action = str(hyp.get("action", "UNKNOWN"))
    current_metadata = dict(hyp.get("metadata") or {})
    current_trust_weight: float | None = hyp.get("trust_weight", 0.5)
    if isinstance(current_trust_weight, (int, float)):
        current_trust_weight = float(current_trust_weight)
    else:
        current_trust_weight = None

    for k, v in modifiers.items():
        if k == "anomaly_score":
            current_anomaly = float(v)
        elif k == "trust_tier":
            current_trust_tier = str(v)
            current_trust_weight = None
        elif k == "trust_weight":
            current_trust_weight = float(v)
        elif k == "action":
            current_action = str(v)
        elif k.startswith("metadata."):
            meta_key = k.split(".", 1)[1]
            current_metadata[meta_key] = v
        else:
            current_metadata[str(k)] = v

    result = fusion.evaluate(
        anomaly_score=current_anomaly,
        trust_tier=current_trust_tier,
        action=current_action,
        metadata=current_metadata,
        trust_weight=current_trust_weight,
    )
    modified_score = float(result["score"])
    would_fire = modified_score > fire_threshold
    explanation = (
        f"Modifiers {modifiers!r}: score {original_score:.4f} -> {modified_score:.4f}; "
        f"would_fire={would_fire} (threshold={fire_threshold}); "
        f"rules={','.join(result.get('matched_rules', [])) or 'none'}"
    )
    logger.info("Counterfactual multi on %s: %s", hypothesis_id, explanation)
    return {
        "original_score": original_score,
        "modified_score": modified_score,
        "would_fire": would_fire,
        "explanation": explanation,
    }
