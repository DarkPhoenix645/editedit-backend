from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CsvToUiField:
    csv_column: str
    db_field: str
    api_field: str
    required: bool = True


CSV_TO_UI_CONTRACT: list[CsvToUiField] = [
    CsvToUiField("scenario_id", "forensic_hypotheses.scenario_id", "scenario_id"),
    CsvToUiField("scenario_title", "forensic_hypotheses.scenario_title", "scenario_title", required=False),
    CsvToUiField("hypothesis_uid", "forensic_hypotheses.hypothesis_uid", "hypothesis_uid"),
    CsvToUiField("title", "forensic_hypotheses.title", "title"),
    CsvToUiField("description", "forensic_hypotheses.description", "description", required=False),
    CsvToUiField("confidence_score", "forensic_hypotheses.confidence_score", "confidence_score"),
    CsvToUiField("anomaly_score", "forensic_hypotheses.anomaly_score", "anomaly_score"),
    CsvToUiField("trust_weight", "forensic_hypotheses.trust_weight", "trust_weight"),
    CsvToUiField("mitre_technique_id", "forensic_hypotheses.mitre_technique_id", "mitre_technique_id", required=False),
    CsvToUiField("mitre_technique_name", "forensic_hypotheses.mitre_technique_name", "mitre_technique_name", required=False),
    CsvToUiField("mitre_tactic", "forensic_hypotheses.mitre_tactic", "mitre_tactic", required=False),
    CsvToUiField(
        "cryptographic_evidence_snippet",
        "forensic_hypotheses.cryptographic_evidence_snippet",
        "cryptographic_evidence_snippet",
        required=False,
    ),
    CsvToUiField(
        "neuro_symbolic_reasoning_chain",
        "forensic_hypotheses.neuro_symbolic_reasoning_chain",
        "neuro_symbolic_reasoning_chain",
        required=False,
    ),
]


def validate_csv_record(record: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for f in CSV_TO_UI_CONTRACT:
        if not f.required:
            continue
        if record.get(f.csv_column) in (None, ""):
            missing.append(f.csv_column)
    return missing
