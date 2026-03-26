"""Map Logstash / ECS-shaped dicts to LogEvent for ML."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.ml.schemas import LogEvent, TrustTier


def _get_nested(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur if cur is not None else default


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        s = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _after_hours(ts: datetime | None) -> bool:
    if ts is None:
        return False
    h = ts.hour
    start = settings.AFTER_HOURS_START_HOUR
    end = settings.AFTER_HOURS_END_HOUR
    if start > end:
        return h >= start or h < end
    return h >= start or h < end


_RESTRICTED_PATTERNS = (
    re.compile(r"/etc/shadow", re.I),
    re.compile(r"/data/financial", re.I),
    re.compile(r"/var/log/audit", re.I),
    re.compile(r"admin|privileged|secret", re.I),
)


def _restricted_asset(resource: str | None) -> bool:
    if not resource:
        return False
    return any(p.search(resource) for p in _RESTRICTED_PATTERNS)


def canonicalize_action(raw_action: str, outcome: str | None) -> str:
    """Map coarse [ml][action] + outcome to fusion-rule action strings."""
    a = (raw_action or "").strip().upper()
    o = (outcome or "").lower()

    if a == "AUTH":
        if o == "failure":
            return "AUTH_FAIL"
        if o == "success":
            return "AUTH_SUCCESS"
        return "AUTH_SUCCESS"
    if a == "SYSLOG":
        return "API_CALL"
    if a == "APP":
        return "API_CALL"
    if a == "CLOUD_EVENT":
        return "CLOUD_LOGIN"
    if a == "IOT_EVENT":
        return "TCP_CONNECT"
    if a == "KERNEL_EVENT":
        return "PROC_ACCESS"
    if a == "UNKNOWN":
        return "HTTP_GET"
    return a if a else "HTTP_GET"


def _trust_tier_from_forensiq(raw: str | None) -> TrustTier:
    if not raw:
        return TrustTier.APPLICATION
    key = str(raw).lower().strip()
    mapping = {
        "kernel": TrustTier.KERNEL,
        "iam": TrustTier.IAM,
        "os": TrustTier.OS,
        "application": TrustTier.APPLICATION,
        "cloud": TrustTier.CLOUD,
        "iot": TrustTier.IOT,
        "unknown": TrustTier.UNKNOWN,
    }
    return mapping.get(key, TrustTier.APPLICATION)


def logstash_event_to_log_event(raw: dict[str, Any]) -> LogEvent:
    """Normalize a Logstash document (nested ECS + forensiq + ml) to LogEvent."""
    ml = raw.get("ml") or {}
    forensiq = raw.get("forensiq") or {}
    event = raw.get("event") or {}
    host = raw.get("host") or {}
    source = raw.get("source") or {}
    destination = raw.get("destination") or {}
    user = raw.get("user") or {}
    winlog = raw.get("winlog") or {}
    logon = winlog.get("logon") or {} if isinstance(winlog, dict) else {}
    network = raw.get("network") or {}

    ts = _parse_ts(raw.get("@timestamp")) or datetime.now(timezone.utc)

    event_id = str(
        event.get("id")
        or raw.get("event_id")
        or forensiq.get("event_fingerprint")
        or "unknown",
    )

    source_ip = str(ml.get("source_ip") or source.get("ip") or "0.0.0.0")
    dest_ip = ml.get("dest_ip") or destination.get("ip")
    user_id = str(ml.get("user_id") or user.get("name") or "unknown")

    raw_action = str(ml.get("action") or "UNKNOWN")
    outcome = ml.get("outcome") or event.get("outcome") or raw.get("outcome")
    if isinstance(outcome, str):
        outcome = outcome.lower()
    action = canonicalize_action(raw_action, outcome if isinstance(outcome, str) else None)

    resource = ml.get("resource") or _get_nested(raw, "file", "path") or _get_nested(raw, "url", "original")

    meta: dict[str, Any] = {
        "logon_type": int(logon.get("type", 2)) if str(logon.get("type", "")).isdigit() else 2,
        "bytes_sent": float(network.get("bytes_sent") or network.get("bytes") or ml.get("bytes_sent") or 0),
        "after_hours": _after_hours(ts),
        "restricted_asset": _restricted_asset(str(resource) if resource else None),
    }
    if isinstance(forensiq.get("event_fingerprint"), str):
        meta["forensiq_fingerprint"] = forensiq["event_fingerprint"]

    trust_tier = _trust_tier_from_forensiq(forensiq.get("trust_tier") or ml.get("log_type"))

    fingerprint = forensiq.get("event_fingerprint") or forensiq.get("incoming_fingerprint")

    return LogEvent(
        event_id=event_id,
        timestamp=ts,
        source_ip=source_ip,
        dest_ip=str(dest_ip) if dest_ip else None,
        user_id=user_id,
        action=action,
        resource=str(resource) if resource else None,
        outcome=outcome if isinstance(outcome, str) else None,
        source_id=str(raw.get("source_id")) if raw.get("source_id") else None,
        message=raw.get("message"),
        fingerprint=str(fingerprint) if fingerprint else None,
        trust_tier=trust_tier,
        metadata=meta,
    )
