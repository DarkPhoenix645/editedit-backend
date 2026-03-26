"""ML engine bundle — construct once per process (use workers=1 for shared state)."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from app.ml.anomaly import AnomalyDetector
from app.ml.critic import CriticEngine
from app.ml.fusion import FusionEngine, default_fusion_rules_path
from app.ml.graph import AttackGraph
from app.ml.mitre import MitreMapper
from app.ml.rag import RAGEngine


@dataclass
class MLEngine:
    anomaly: AnomalyDetector
    graph: AttackGraph
    fusion: FusionEngine
    mitre: MitreMapper
    rag: RAGEngine
    critic: CriticEngine


def build_ml_engine() -> MLEngine:
    mitre = MitreMapper()
    return MLEngine(
        anomaly=AnomalyDetector(),
        graph=AttackGraph(max_nodes=10_000),
        fusion=FusionEngine(default_fusion_rules_path(), mitre=mitre),
        mitre=mitre,
        rag=RAGEngine(),
        critic=CriticEngine(),
    )


def get_ml(request: Request) -> MLEngine:
    return request.app.state.ml
