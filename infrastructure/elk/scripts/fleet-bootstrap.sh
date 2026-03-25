#!/usr/bin/env bash
# Idempotent Fleet outputs: Elasticsearch (default) + Logstash with server-auth TLS only
# (CA verify; no client cert / mTLS). Paths are agent-container paths (see host-agent:enroll).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ELK_DIR}"

if [ ! -f .env ]; then
  echo "Missing infrastructure/elk/.env"
  exit 1
fi
set -a
# shellcheck source=/dev/null
source .env
set +a

CA="volumes/certs/ca/ca.crt"
if [ ! -f "${CA}" ]; then
  echo "Missing ${CA} — run: task infra:certs:generate"
  exit 1
fi

KIBANA_PORT="${KIBANA_PORT:-5601}"
KIBANA_URL="${KIBANA_URL:-https://localhost:${KIBANA_PORT}}"
AUTH=(-u "elastic:${ELASTIC_PASSWORD}")
HDR=(-H "kbn-xsrf: true" -H "Content-Type: application/json")
CURL=(curl -sS --cacert "${CA}" "${AUTH[@]}" "${HDR[@]}")
# Fail on 4xx/5xx for mutating requests and single-item GETs
CURLF=(curl -sS -f --cacert "${CA}" "${AUTH[@]}" "${HDR[@]}")

fleet_setup() {
  "${CURL[@]}" -X POST "${KIBANA_URL}/api/fleet/setup" -d '{}' >/dev/null 2>&1 || true
}

wait_kibana() {
  local i code
  for i in $(seq 1 60); do
    code=$(curl -sS --cacert "${CA}" "${AUTH[@]}" "${HDR[@]}" -o /dev/null -w "%{http_code}" "${KIBANA_URL}/api/fleet/outputs" || true)
    if [ "${code}" = "200" ]; then
      return 0
    fi
    echo "Waiting for Kibana Fleet API (${i}/60)..."
    sleep 5
  done
  echo "Kibana Fleet API did not become ready."
  exit 1
}

get_outputs_json() {
  "${CURL[@]}" "${KIBANA_URL}/api/fleet/outputs"
}

output_id_by_name() {
  local name="$1"
  get_outputs_json | jq -r --arg n "$name" '.items[]? | select(.name == $n) | .id' | head -1
}

get_output_item() {
  local id="$1"
  "${CURLF[@]}" "${KIBANA_URL}/api/fleet/outputs/${id}"
}

put_output() {
  local id="$1"
  local body="$2"
  "${CURLF[@]}" -X PUT "${KIBANA_URL}/api/fleet/outputs/${id}" -d "${body}"
}

# Merge patch onto existing saved output (PUT expects full document shape from Fleet).
put_output_merged() {
  local id="$1"
  local patch="$2"
  local merged
  merged=$(get_output_item "${id}" | jq --argjson patch "${patch}" '.item * $patch')
  put_output "${id}" "${merged}"
}

post_output() {
  local body="$1"
  "${CURLF[@]}" -X POST "${KIBANA_URL}/api/fleet/outputs" -d "${body}"
}

demote_other_es_defaults() {
  local keep_name="$1"
  local ids
  ids=$(get_outputs_json | jq -r --arg k "$keep_name" '
    .items[]?
    | select(.type == "elasticsearch" and .is_default == true and .name != $k)
    | .id
  ')
  local oid
  for oid in ${ids}; do
    [ -z "${oid}" ] && continue
    local body
    body=$(get_output_item "${oid}" | jq '.item | .is_default = false | .is_default_monitoring = false')
    echo "Demoting default on output id=${oid} (so ${keep_name} can be default)"
    put_output "${oid}" "${body}"
  done
}

CONFIG_ES="$(cat <<'EOF'
ssl.verification_mode: certificate
ssl.certificate_authorities:
  - /usr/share/elastic-agent/config/certs/ca/ca.crt
EOF
)"

CONFIG_LS="$(cat <<'EOF'
ssl.verification_mode: full
ssl.certificate_authorities:
  - /usr/share/elastic-agent/config/certs/ca/ca.crt
EOF
)"

payload_es() {
  local id="${1:-}"
  jq -n \
    --arg id "${id}" \
    --arg name "Elasticsearch Direct" \
    --arg cfg "${CONFIG_ES}" \
    '{
      name: $name,
      type: "elasticsearch",
      hosts: ["https://es01:9200"],
      is_default: true,
      is_default_monitoring: true,
      config_yaml: $cfg
    }
    + (if ($id | length) > 0 then {id: $id} else {} end)'
}

payload_ls() {
  local id="${1:-}"
  jq -n \
    --arg id "${id}" \
    --arg name "Logstash Ingest Pipeline" \
    --arg cfg "${CONFIG_LS}" \
    '{
      name: $name,
      type: "logstash",
      hosts: ["logstash:5044"],
      is_default: false,
      is_default_monitoring: false,
      config_yaml: $cfg
    }
    + (if ($id | length) > 0 then {id: $id} else {} end)'
}

upsert_es() {
  local eid
  eid="$(output_id_by_name "Elasticsearch Direct")"
  if [ -n "${eid}" ]; then
    echo "Updating Fleet output: Elasticsearch Direct (${eid})"
    put_output_merged "${eid}" "$(payload_es "${eid}")"
  else
    demote_other_es_defaults "Elasticsearch Direct"
    echo "Creating Fleet output: Elasticsearch Direct"
    post_output "$(payload_es "")"
  fi
}

upsert_ls() {
  local eid
  eid="$(output_id_by_name "Logstash Ingest Pipeline")"
  if [ -n "${eid}" ]; then
    echo "Updating Fleet output: Logstash Ingest Pipeline (${eid})"
    put_output_merged "${eid}" "$(payload_ls "${eid}")"
  else
    echo "Creating Fleet output: Logstash Ingest Pipeline"
    post_output "$(payload_ls "")"
  fi
}

fleet_setup
wait_kibana
upsert_es
upsert_ls
echo "Fleet outputs OK. Assign policies to Logstash in Kibana if needed."
