#!/usr/bin/env bash
# Idempotent Fleet outputs: Elasticsearch (default) + Logstash with TLS (Fleet UI model):
# agents verify Logstash with CA + present a shared client cert (mTLS). PEMs come from
# volumes/certs/ after task infra:certs:generate (elastic_agent client cert + CA).
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
  # Prefer demoting only non–preconfigured outputs; Fleet may omit flags on list, so each PUT can still fail.
  local ids
  ids=$(get_outputs_json | jq -r --arg k "$keep_name" '
    .items[]?
    | select(.type == "elasticsearch" and .is_default == true and .name != $k)
    | select((.is_preconfigured // false) | not)
    | .id
  ')
  local oid
  for oid in ${ids}; do
    [ -z "${oid}" ] && continue
    echo "Demoting default on output id=${oid} (so ${keep_name} can be default)"
    if ! put_output_merged "${oid}" "$(jq -n '{is_default: false, is_default_monitoring: false}')"; then
      echo "WARN: could not demote output id=${oid} (read-only or Fleet-managed). Continuing."
    fi
  done
}

CONFIG_ES="$(cat <<'EOF'
ssl.verification_mode: certificate
ssl.certificate_authorities:
  - /usr/share/elastic-agent/config/certs/ca/ca.crt
EOF
)"

# Used only if client cert files are missing (legacy); prefer ssl{} in payload_ls with inline PEMs.
CONFIG_LS_FALLBACK="$(cat <<'EOF'
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
  local ca_path crt_path key_path
  ca_path="${ELK_DIR}/volumes/certs/ca/ca.crt"
  crt_path="${ELK_DIR}/volumes/certs/elastic_agent/elastic_agent.crt"
  key_path="${ELK_DIR}/volumes/certs/elastic_agent/elastic_agent.pkcs8.key"
  if [ ! -f "${key_path}" ] && [ -f "${ELK_DIR}/volumes/certs/elastic_agent/elastic_agent.key" ]; then
    key_path="${ELK_DIR}/volumes/certs/elastic_agent/elastic_agent.key"
  fi
  if [ -f "${ca_path}" ] && [ -f "${crt_path}" ] && [ -f "${key_path}" ]; then
    jq -n \
      --arg id "${id}" \
      --arg name "Logstash Ingest Pipeline" \
      --rawfile ca "${ca_path}" \
      --rawfile cert "${crt_path}" \
      --rawfile clientkey "${key_path}" \
      '{
        name: $name,
        type: "logstash",
        hosts: ["https://logstash:5044"],
        is_default: false,
        is_default_monitoring: false,
        config_yaml: "",
        ssl: {
          certificate_authorities: [$ca],
          certificate: $cert,
          key: $clientkey,
          verification_mode: "full"
        }
      }
      + (if ($id | length) > 0 then {id: $id} else {} end)'
  else
    echo "WARN: Missing ${crt_path} or client key (or ${ca_path}). Using path-based config_yaml only — generate certs (task infra:certs:generate) and re-run, or paste PEMs in Fleet UI." >&2
    jq -n \
      --arg id "${id}" \
      --arg name "Logstash Ingest Pipeline" \
      --arg cfg "${CONFIG_LS_FALLBACK}" \
      '{
        name: $name,
        type: "logstash",
        hosts: ["https://logstash:5044"],
        is_default: false,
        is_default_monitoring: false,
        config_yaml: $cfg
      }
      + (if ($id | length) > 0 then {id: $id} else {} end)'
  fi
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
    if post_output "$(payload_es "")"; then
      :
    else
      echo "WARN: Could not create output as default (another preconfigured default may exist). Creating non-default — set default in Fleet → Settings → Outputs."
      post_output "$(payload_es "" | jq '.is_default = false | .is_default_monitoring = false')"
    fi
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
echo "Set LOGSTASH_FLEET_API_KEY in .env (Fleet → Outputs → Logstash → Generate API key) and restart logstash — see ELK_AGENT_SETUP.md."
