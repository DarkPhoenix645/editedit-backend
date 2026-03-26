from __future__ import annotations

from typing import Any


def apply_ocsf_mapping_v1_0(raw_event: dict[str, Any]) -> dict[str, Any]:
    event = raw_event.get("event", {})
    dataset = event.get("dataset", "")
    outcome = str(event.get("outcome", "unknown")).lower()
    # ML trust tiers are 6 canonical classes:
    # application, cloud, iam, iot, kernel, os
    trust_tier = "os"
    if dataset.startswith("application."):
        trust_tier = "application"
    elif dataset.startswith("cloud."):
        trust_tier = "cloud"
    elif dataset.startswith("iot."):
        trust_tier = "iot"
    elif dataset.startswith("kernel.") or dataset.startswith("system.kernel"):
        trust_tier = "kernel"
    elif dataset.startswith("iam.") or dataset.startswith("identity.") or dataset == "system.auth":
        trust_tier = "iam"
    elif dataset.startswith("system.auth"):
        trust_tier = "iam"

    status = "Unknown"
    status_id = 0
    if outcome == "success":
        status = "Success"
        status_id = 1
    elif outcome == "failure":
        status = "Failure"
        status_id = 2

    mapped: dict[str, Any] = {
        "@timestamp": raw_event.get("@timestamp"),
        "message": raw_event.get("message"),
        "event_id": event.get("id") or raw_event.get("event_id"),
        "forensiq": {
            "event_fingerprint": raw_event.get("forensiq", {}).get("event_fingerprint"),
            "trust_tier": trust_tier,
        },
        "event": {
            "id": event.get("id") or raw_event.get("event_id"),
            "hash": event.get("hash") or raw_event.get("forensiq", {}).get("event_fingerprint"),
            "dataset": dataset,
            "outcome": outcome,
        },
        "ocsf": {
            "activity_id": 0,
            "activity_name": "Unknown",
            "category_uid": 3,
            "category_name": "Identity & Access Management",
            "class_uid": 3002,
            "class_name": "Authentication",
            "severity_id": 3,
            "severity": "Medium",
            "type_uid": 300200,
            "type_name": "Authentication: Unknown",
            "status": status,
            "status_id": status_id,
            "message": raw_event.get("message"),
            "time": raw_event.get("@timestamp"),
            "metadata": {
                "version": "1.0.0",
                "product": {"name": "ForensIQ"},
                "uid": event.get("id") or raw_event.get("event_id"),
            },
            "src_endpoint": {"ip": raw_event.get("source", {}).get("ip")},
            "dst_endpoint": {"ip": raw_event.get("destination", {}).get("ip")},
            "user": {"name": raw_event.get("user", {}).get("name")},
        },
    }
    return mapped
