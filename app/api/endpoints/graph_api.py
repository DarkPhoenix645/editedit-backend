from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from app.core.deps import get_current_user

router = APIRouter()


@router.get("/subgraph/{node}")
def get_subgraph(
    node: str,
    request: Request,
    k: int = 2,
    _user=Depends(get_current_user),
) -> dict[str, Any]:
    ml = request.app.state.ml
    g = ml.graph.k_hop_subgraph(node, k=k)
    edges_out: list[dict[str, Any]] = []
    for u, v, key, data in g.edges(keys=True, data=True):  # MultiDiGraph subgraph
        edges_out.append(
            {
                "source": u,
                "target": v,
                "key": key,
                "action": data.get("action"),
                "timestamp": data.get("timestamp"),
            }
        )
    nodes_out = [{"id": n, **g.nodes[n]} for n in g.nodes()]
    return {"center": node, "k": k, "nodes": nodes_out, "edges": edges_out}


@router.get("/bridges", response_model=list[str])
def get_bridges(
    request: Request,
    _user=Depends(get_current_user),
) -> list[str]:
    ml = request.app.state.ml
    return ml.graph.get_bridge_nodes()
