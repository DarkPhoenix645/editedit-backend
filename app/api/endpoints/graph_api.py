from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.deps import get_current_user
from app.core.rbac import UserRole, can_view_graph, user_role_from_db
from app.db.models import User

router = APIRouter()


def _role(user: User) -> UserRole:
    return user_role_from_db(getattr(user, "role", None)) or UserRole.INVESTIGATOR


def _require_graph_read(user: User) -> None:
    if not can_view_graph(_role(user)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


@router.get("/subgraph/{node}")
def get_subgraph(
    node: str,
    request: Request,
    k: int = 2,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _require_graph_read(current_user)
    ml = request.app.state.ml
    g = ml.graph.k_hop_subgraph(node, k=k)
    edges_out: list[dict[str, Any]] = []
    try:
        # Multi(Graph|DiGraph) path.
        for u, v, key, data in g.edges(keys=True, data=True):
            edges_out.append(
                {
                    "source": u,
                    "target": v,
                    "key": key,
                    "action": data.get("action"),
                    "timestamp": data.get("timestamp"),
                }
            )
    except TypeError:
        # DiGraph/Graph path (no edge key support).
        for u, v, data in g.edges(data=True):
            edges_out.append(
                {
                    "source": u,
                    "target": v,
                    "key": None,
                    "action": data.get("action"),
                    "timestamp": data.get("timestamp"),
                }
            )
    nodes_out = [{"id": n, **g.nodes[n]} for n in g.nodes()]
    return {"center": node, "k": k, "nodes": nodes_out, "edges": edges_out}


@router.get("/bridges", response_model=list[str])
def get_bridges(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> list[str]:
    _require_graph_read(current_user)
    ml = request.app.state.ml
    return ml.graph.get_bridge_nodes()
