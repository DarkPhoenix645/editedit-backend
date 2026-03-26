from __future__ import annotations

import logging
import statistics
from collections import deque
from datetime import datetime, timezone

import networkx as nx

logger = logging.getLogger("forensiq.ml.graph")


class AttackGraph:
    """Directed graph for lateral movement and bridge detection."""

    def __init__(self, max_nodes: int = 10_000) -> None:
        self.G = nx.MultiDiGraph()
        self._centrality_history: dict[str, deque] = {}
        self._max_nodes = max_nodes

    def add_event(
        self,
        event_id: str,
        source: str | None,
        target: str | None,
        action: str,
        timestamp: datetime,
        metadata: dict | None = None,
    ) -> None:
        if not source or not target:
            return
        if source == target:
            return

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        ts_iso = timestamp.isoformat()

        if not self.G.has_node(source):
            self.G.add_node(source, first_seen=ts_iso, last_seen=ts_iso)
        else:
            self.G.nodes[source]["last_seen"] = ts_iso

        if not self.G.has_node(target):
            self.G.add_node(target, first_seen=ts_iso, last_seen=ts_iso)
        else:
            self.G.nodes[target]["last_seen"] = ts_iso

        self.G.add_edge(
            source,
            target,
            key=event_id,
            action=action,
            timestamp=ts_iso,
            **(metadata or {}),
        )

        self.trim(self._max_nodes)

    def k_hop_subgraph(self, node: str, k: int = 2) -> nx.DiGraph:
        if node not in self.G:
            return nx.DiGraph()

        nodes = {node}
        for _ in range(k):
            new_nodes: set[str] = set()
            for n in nodes:
                new_nodes.update(self.G.successors(n))
                new_nodes.update(self.G.predecessors(n))
            nodes.update(new_nodes)

        return self.G.subgraph(nodes).copy()

    def betweenness_centrality(self) -> dict[str, float]:
        if self.G.number_of_nodes() == 0:
            return {}
        simple_G = nx.DiGraph(self.G)
        return nx.betweenness_centrality(simple_G)

    def _update_centrality_baseline(self, node: str, score: float) -> None:
        if node not in self._centrality_history:
            self._centrality_history[node] = deque(maxlen=100)
        self._centrality_history[node].append(score)

    def _is_bridge_spike(self, node: str, current_score: float) -> bool:
        history = self._centrality_history.get(node, deque())
        if len(history) < 10:
            return False
        mean = statistics.mean(history)
        stdev = statistics.stdev(history) if len(history) > 1 else 0.001
        if stdev == 0:
            stdev = 0.001
        return current_score > mean + (3 * stdev)

    def get_bridge_nodes(self) -> list[str]:
        centrality = self.betweenness_centrality()
        bridges: list[str] = []
        for node, score in centrality.items():
            self._update_centrality_baseline(node, score)
            if self._is_bridge_spike(node, score):
                bridges.append(node)
        return bridges

    def clone(self) -> AttackGraph:
        cloned = AttackGraph(max_nodes=self._max_nodes)
        cloned.G = self.G.copy()
        cloned._centrality_history = {k: deque(v, maxlen=100) for k, v in self._centrality_history.items()}
        return cloned

    def trim(self, max_nodes: int) -> None:
        if self.G.number_of_nodes() <= max_nodes:
            return
        nodes_by_time = sorted(self.G.nodes(data=True), key=lambda x: x[1].get("last_seen", ""))
        to_remove = len(nodes_by_time) - max_nodes
        for i in range(to_remove):
            self.G.remove_node(nodes_by_time[i][0])

    @property
    def stats(self) -> dict[str, int]:
        return {"nodes": self.G.number_of_nodes(), "edges": self.G.number_of_edges()}
