"""Phase 6 — RAG, critic, counterfactual (uses in-process ML engines)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.deps import get_current_user
from app.ml.counterfactual import simulate_counterfactual
from app.ml.schemas import (
    CounterfactualRequest,
    CounterfactualResponse,
    RAGQueryRequest,
    RAGQueryResponse,
)

logger = logging.getLogger("forensiq.api.phase6")

router = APIRouter()


@router.post("/rag/query", response_model=RAGQueryResponse)
def query_rag(
    req: RAGQueryRequest,
    request: Request,
    _user=Depends(get_current_user),
):
    ml = request.app.state.ml
    result = ml.rag.query(req.query, req.context_event_ids)

    if req.strict_critic:
        event_ids = set(result.get("cited_event_ids", []))
        if req.context_event_ids:
            event_ids.update(req.context_event_ids)
        relevant_events = []
        for eid in event_ids:
            evt = ml.rag.event_store.get(eid)
            if evt:
                relevant_events.append(evt)

        critic_result = ml.critic.validate(result["answer"], relevant_events)
        if not critic_result["valid"]:
            logger.warning("RAG output rejected by critic: %s", critic_result["message"])
            result["answer"] += (
                f"\n\n[CRITIC WARNING: Potential hallucination detected. {critic_result['message']}]"
            )

    return RAGQueryResponse(**result)


@router.post("/counterfactual/simulate", response_model=CounterfactualResponse)
def run_counterfactual(
    req: CounterfactualRequest,
    request: Request,
    _user=Depends(get_current_user),
):
    ml = request.app.state.ml
    result = simulate_counterfactual(
        req.hypothesis_id,
        req.modify_attribute,
        req.modify_value,
        fusion=ml.fusion,
    )
    if "explanation" in result and "not found" in result["explanation"].lower():
        raise HTTPException(status_code=404, detail=result["explanation"])
    return CounterfactualResponse(**result)
