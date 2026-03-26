from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import yaml

from app.ml.mitre import MitreMapper

logger = logging.getLogger("forensiq.ml.fusion")

TRUST_TIERS = {
    "kernel": 1.0,
    "iam": 0.95,
    "os": 0.85,
    "application": 0.6,
    "cloud": 0.65,
    "iot": 0.3,
    "unknown": 0.1,
}


def default_fusion_rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "policies" / "fusion_rules.yaml"


class FusionEngine:
    """Policy-driven fusion of anomaly signals and symbolic rules."""

    def __init__(self, rules_path: Path | None = None, mitre: MitreMapper | None = None) -> None:
        self._mitre = mitre or MitreMapper()
        self.rules: list[dict[str, Any]] = []
        self.policy_hash: str = ""
        self._load_rules(rules_path or default_fusion_rules_path())

    def _load_rules(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Fusion rules not found at {path}")
        with open(path, "rb") as f:
            content = f.read()
            self.policy_hash = hashlib.sha256(content).hexdigest()
            data = yaml.safe_load(content.decode("utf-8"))
        self.rules = data.get("rules", [])
        logger.info(
            "Loaded %d fusion rules from %s (hash: %s)",
            len(self.rules),
            path,
            self.policy_hash[:8],
        )

    def evaluate(
        self,
        anomaly_score: float,
        trust_tier: str,
        action: str,
        metadata: dict | None = None,
        trust_weight: float | None = None,
        event_for_mitre: dict[str, Any] | None = None,
        symbolic_risk_flags: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if trust_weight is None:
            trust_weight = TRUST_TIERS.get(trust_tier, TRUST_TIERS["unknown"])

        matched_rules: list[str] = []
        matched_rule_mitre_ids: list[str] = []
        mitre_techniques: list[str] = []
        pattern_severity = 1.0
        metadata = metadata or {}
        rule_trace_entries: list[str] = []
        first_match_found = False

        for rule in self.rules:
            if self._rule_matches(rule, anomaly_score, trust_tier, action, metadata):
                matched_rules.append(rule["id"])
                rule_desc = rule.get("description", "no desc")
                rule_trace_entries.append(f"MATCH {rule['id']}: {rule_desc}")
                mt_one = rule.get("mitre_technique")
                if mt_one and mt_one not in matched_rule_mitre_ids:
                    matched_rule_mitre_ids.append(mt_one)
                for t in rule.get("mitre_techniques", []):
                    if t not in mitre_techniques:
                        mitre_techniques.append(t)
                if not first_match_found:
                    pattern_severity = rule.get("severity_multiplier", 1.0)
                    first_match_found = True

        if not first_match_found:
            rule_trace_entries.append("DEFAULT: No rule matched")
            pattern_severity = 1.0

        final_score = min(anomaly_score * trust_weight * pattern_severity, 1.0)

        result: dict[str, Any] = {
            "score": final_score,
            "anomaly_score": anomaly_score,
            "trust_weight": trust_weight,
            "pattern_severity": pattern_severity,
            "matched_rules": matched_rules,
            "rule_trace": rule_trace_entries,
            "mitre_techniques": mitre_techniques,
            "matched_rule_mitre_ids": matched_rule_mitre_ids,
        }

        ev = event_for_mitre if event_for_mitre is not None else {
            "action": action,
            "trust_tier": trust_tier,
            "metadata": dict(metadata),
            "outcome": metadata.get("outcome"),
            "dest_ip": metadata.get("dest_ip"),
            "source_ip": metadata.get("source_ip"),
        }
        if ev.get("metadata") is None:
            ev["metadata"] = {}
        mt_id, mt_name, mt_tactic = self._mitre.map_event(ev, result, symbolic_risk_flags or {})
        result["mitre_technique_id"] = mt_id
        result["mitre_technique_name"] = mt_name
        result["mitre_tactic"] = mt_tactic

        return result

    def _rule_matches(
        self,
        rule: dict[str, Any],
        anomaly_score: float,
        trust_tier: str,
        action: str,
        metadata: dict[str, Any],
    ) -> bool:
        conditions = rule.get("conditions", {})
        if "min_anomaly" in conditions and anomaly_score < conditions["min_anomaly"]:
            return False
        if "trust_tiers" in conditions and trust_tier not in conditions["trust_tiers"]:
            return False
        if "actions" in conditions and action not in conditions["actions"]:
            return False
        for key, expected in conditions.get("metadata", {}).items():
            if metadata.get(key) != expected:
                return False
        return True

    def reload(self, path: Path | None = None) -> None:
        self._load_rules(path or default_fusion_rules_path())
