#!/usr/bin/env bash
set -euo pipefail

# -------- config --------
PG_CONTAINER="${PG_CONTAINER:-postgres-db}"
PG_USER="${PG_USER:-postgres}"
PG_DB="${PG_DB:-editedit-db}"
BACKEND_URL="${BACKEND_URL:-https://localhost:8000}"
LOGSTASH_SECRET="${LOGSTASH_SHARED_SECRET:-}"
# ------------------------

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }
need docker
need logger
need curl

count_hyp() {
  docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc \
    "select count(*) from forensic_hypotheses;"
}

severity_breakdown_recent() {
  docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "
    with recent as (
      select confidence_score
      from forensic_hypotheses
      where created_at >= now() - interval '15 minutes'
    )
    select
      sum(case when confidence_score >= 0.7 then 1 else 0 end) as critical,
      sum(case when confidence_score >= 0.5 and confidence_score < 0.7 then 1 else 0 end) as high,
      sum(case when confidence_score >= 0.3 and confidence_score < 0.5 then 1 else 0 end) as medium,
      sum(case when confidence_score < 0.3 then 1 else 0 end) as low
    from recent;
  "
}

before="$(count_hyp)"
echo "Hypotheses before: $before"\

if [ -z "$LOGSTASH_SECRET" ]; then
  echo "Set LOGSTASH_SHARED_SECRET env var to run fallback direct infer injection."
  exit 2
fi

echo "Performing Log Burst..."
ack_json="$(curl -sk -X POST "$BACKEND_URL/api/ml/infer" \
  -H "X-Logstash-Secret: $LOGSTASH_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "@timestamp": "2026-03-27T00:14:05Z",
        "message": "CLEAR_LOGS by breakglass-admin",
        "event": {"dataset": "cloud.audit", "outcome": "success", "id": "force-hyp-1"},
        "host": {"name": "10.95.165.5"},
        "source": {"ip": "10.95.165.5"},
        "destination": {"ip": "203.0.113.227"},
        "user": {"name": "breakglass-admin"},
        "forensiq": {"trust_tier": "cloud"},
        "ml": {
          "action": "CLEAR_LOGS",
          "outcome": "success",
          "resource": "/var/log/audit",
          "source_ip": "10.95.165.5",
          "dest_ip": "203.0.113.227",
          "user_id": "breakglass-admin"
        }
      },
      {
        "@timestamp": "2026-03-27T00:15:20Z",
        "message": "DISABLE_AUDIT by breakglass-admin",
        "event": {"dataset": "cloud.audit", "outcome": "success", "id": "force-hyp-2"},
        "host": {"name": "10.95.165.5"},
        "source": {"ip": "10.95.165.5"},
        "destination": {"ip": "203.0.113.227"},
        "user": {"name": "breakglass-admin"},
        "forensiq": {"trust_tier": "cloud"},
        "ml": {
          "action": "DISABLE_AUDIT",
          "outcome": "success",
          "resource": "/var/log/audit",
          "source_ip": "10.95.165.5",
          "dest_ip": "203.0.113.227",
          "user_id": "breakglass-admin"
        }
      },
      {
        "@timestamp": "2026-03-27T00:16:01Z",
        "message": "REMOTE_EXEC from breakglass-admin to prod-db-primary",
        "event": {"dataset": "cloud.audit", "outcome": "success", "id": "force-hyp-3"},
        "host": {"name": "10.95.165.5"},
        "source": {"ip": "10.95.165.5"},
        "destination": {"ip": "203.0.113.227"},
        "user": {"name": "breakglass-admin"},
        "forensiq": {"trust_tier": "cloud"},
        "ml": {
          "action": "REMOTE_EXEC",
          "outcome": "success",
          "resource": "/admin/secret-shell",
          "source_ip": "10.95.165.5",
          "dest_ip": "203.0.113.227",
          "user_id": "breakglass-admin"
        }
      },
      {
        "@timestamp": "2026-03-27T00:16:42Z",
        "message": "DATA_EXPORT by breakglass-admin",
        "event": {"dataset": "cloud.audit", "outcome": "success", "id": "force-hyp-4"},
        "host": {"name": "10.95.165.5"},
        "source": {"ip": "10.95.165.5"},
        "destination": {"ip": "203.0.113.227"},
        "user": {"name": "breakglass-admin"},
        "forensiq": {"trust_tier": "cloud"},
        "ml": {
          "action": "DATA_EXPORT",
          "outcome": "success",
          "resource": "/admin/secret-dump",
          "source_ip": "10.95.165.5",
          "dest_ip": "203.0.113.227",
          "user_id": "breakglass-admin"
        }
      },
      {
        "@timestamp": "2026-03-27T11:03:15Z",
        "message": "LOW severity baseline API call by analytics-bot",
        "event": {"dataset": "application.audit", "outcome": "success", "id": "force-hyp-low-1"},
        "host": {"name": "10.95.165.9"},
        "source": {"ip": "10.95.165.9"},
        "destination": {"ip": "10.95.165.11"},
        "user": {"name": "analytics-bot"},
        "forensiq": {"trust_tier": "application"},
        "ml": {
          "action": "API_CALL",
          "outcome": "success",
          "resource": "/api/v1/health",
          "source_ip": "10.95.165.9",
          "dest_ip": "10.95.165.11",
          "user_id": "analytics-bot",
          "bytes_sent": 1245
        },
        "network": {"bytes_sent": 1245}
      },
      {
        "@timestamp": "2026-03-27T20:24:11Z",
        "message": "MEDIUM severity remote admin attempt by ops-user",
        "event": {"dataset": "system.auth", "outcome": "success", "id": "force-hyp-med-1"},
        "host": {"name": "10.95.166.20"},
        "source": {"ip": "10.95.166.20"},
        "destination": {"ip": "10.95.166.33"},
        "user": {"name": "ops-user"},
        "forensiq": {"trust_tier": "os"},
        "ml": {
          "action": "SSH",
          "outcome": "success",
          "resource": "/etc/passwd",
          "source_ip": "10.95.166.20",
          "dest_ip": "10.95.166.33",
          "user_id": "ops-user",
          "bytes_sent": 22056
        },
        "network": {"bytes_sent": 22056}
      },
      {
        "@timestamp": "2026-03-27T23:41:09Z",
        "message": "HIGH severity suspicious export by backup-admin",
        "event": {"dataset": "cloud.audit", "outcome": "success", "id": "force-hyp-high-1"},
        "host": {"name": "10.95.166.51"},
        "source": {"ip": "10.95.166.51"},
        "destination": {"ip": "203.0.113.88"},
        "user": {"name": "backup-admin"},
        "forensiq": {"trust_tier": "cloud"},
        "ml": {
          "action": "DATA_EXPORT",
          "outcome": "success",
          "resource": "/data/financial/quarterly.csv",
          "source_ip": "10.95.166.51",
          "dest_ip": "203.0.113.88",
          "user_id": "backup-admin",
          "bytes_sent": 887331
        },
        "network": {"bytes_sent": 887331}
      }
    ]
  }')"

job_id="$(python - <<'PY'
import json,sys
try:
    d=json.loads(sys.stdin.read())
    print(d.get("job_id",""))
except Exception:
    print("")
PY
<<<"$ack_json")"

if [ -n "$job_id" ]; then
  echo "Queued infer job: $job_id"
  for _ in $(seq 1 20); do
    status_json="$(curl -sk "$BACKEND_URL/api/ml/infer/jobs/$job_id")"
    status="$(python - <<'PY'
import json,sys
try:
    print(json.loads(sys.stdin.read()).get("status",""))
except Exception:
    print("")
PY
<<<"$status_json")"
    [ "$status" = "done" ] && break
    [ "$status" = "failed" ] && break
    sleep 1
  done
else
  sleep 3
fi

final="$(count_hyp)"
echo "Hypotheses after logger burst: $final"
echo "Recent severity breakdown (critical high medium low):"
severity_breakdown_recent

if [ "$final" -gt "$before" ]; then
  echo "OK: hypothesis guaranteed via fallback infer call."
  exit 0
fi

echo "Still no new hypothesis; check backend/logstash logs + model calibration state."
exit 3