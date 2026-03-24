from __future__ import annotations

from typing import Any


def apply_ocsf_mapping_v1_0(raw_event: dict[str, Any]) -> dict[str, Any]:
    event = raw_event.get("event", {})
    dataset = event.get("dataset", "")
    trust_tier = "T3"
    if dataset.startswith("system."):
        trust_tier = "T1"
    elif dataset.startswith("application."):
        trust_tier = "T2"

    mapped: dict[str, Any] = {
        "@timestamp": raw_event.get("@timestamp"),
        "message": raw_event.get("message"),
        "forensiq": {
            "event_fingerprint": raw_event.get("forensiq", {}).get("event_fingerprint"),
            "trust_tier": trust_tier,
        },
        "ocsf": {
            "version": "1.0.0",
            "category": "security",
            "class": "authentication",
            "severity": "medium",
            "time": raw_event.get("@timestamp"),
            "host": {"hostname": raw_event.get("host", {}).get("name")},
            "src_endpoint": {"ip": raw_event.get("source", {}).get("ip")},
            "user": {"name": raw_event.get("user", {}).get("name")},
        },
    }
    return mapped
