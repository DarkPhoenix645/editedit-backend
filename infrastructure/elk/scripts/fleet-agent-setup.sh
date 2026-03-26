#!/usr/bin/env bash
# Bootstrap/verify Fleet policy for ForensIQ ingest path.
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
KIBANA_SPACE_ID="${KIBANA_SPACE_ID:-default}"
POLICY_NAME="${FORENSIQ_POLICY_NAME:-ForensIQ Host Log Collection}"
TOKEN_NAME="${FORENSIQ_TOKEN_NAME:-ForensIQ Host Agent Token}"
USE_LOGSTASH_OUTPUT="${FORENSIQ_USE_LOGSTASH_OUTPUT:-true}"

AUTH=(-u "elastic:${ELASTIC_PASSWORD}")
HDR=(-H "kbn-xsrf: true" -H "Content-Type: application/json")
CURL=(curl -sS --cacert "${CA}" "${AUTH[@]}" "${HDR[@]}")
CURLF=(curl -sS -f --cacert "${CA}" "${AUTH[@]}" "${HDR[@]}")

root_api() {
  echo "${KIBANA_URL}/api/fleet"
}

space_api() {
  echo "${KIBANA_URL}/s/${KIBANA_SPACE_ID}/api/fleet"
}

post_try() {
  # Args: <path> <json_payload>
  # Tries /api/fleet and /s/<space>/api/fleet, returns response body on success.
  local path="$1"
  local payload="$2"
  local urls=(
    "$(root_api)/${path}"
    "$(space_api)/${path}"
  )
  local last_status=""
  local last_body=""
  for url in "${urls[@]}"; do
    local tmp
    tmp="$(mktemp)"
    # -o tmp + -w status lets us handle 404 without curl exiting early (-f).
    local status
    status="$(
      curl -sS --cacert "${CA}" -u "elastic:${ELASTIC_PASSWORD}" \
        -H "kbn-xsrf: true" -H "Content-Type: application/json" \
        -X POST "${url}" -d "${payload}" \
        -o "${tmp}" -w "%{http_code}" || true
    )"
    if [ "${status}" = "200" ]; then
      cat "${tmp}"
      rm -f "${tmp}" >/dev/null 2>&1 || true
      return 0
    fi
    last_status="${status}"
    last_body="$(cat "${tmp}")"
    rm -f "${tmp}" >/dev/null 2>&1 || true
  done
  echo "Fleet API POST failed (tried both space/no-space). Last status=${last_status}" >&2
  echo "${last_body}" >&2
  return 1
}

get_try() {
  # Args: <path>
  # Tries /api/fleet and /s/<space>/api/fleet, returns response body on success.
  local path="$1"
  local urls=(
    "$(root_api)/${path}"
    "$(space_api)/${path}"
  )
  local last_status=""
  local last_body=""
  for url in "${urls[@]}"; do
    local tmp
    tmp="$(mktemp)"
    local status
    status="$(
      curl -sS --cacert "${CA}" -u "elastic:${ELASTIC_PASSWORD}" \
        -X GET "${url}" \
        -o "${tmp}" -w "%{http_code}" || true
    )"
    if [ "${status}" = "200" ]; then
      cat "${tmp}"
      rm -f "${tmp}" >/dev/null 2>&1 || true
      return 0
    fi
    last_status="${status}"
    last_body="$(cat "${tmp}")"
    rm -f "${tmp}" >/dev/null 2>&1 || true
  done
  echo "Fleet API GET failed (tried both space/no-space). Last status=${last_status}" >&2
  echo "${last_body}" >&2
  return 1
}

output_id_by_name() {
  local name="$1"
  "${CURL[@]}" "${KIBANA_URL}/api/fleet/outputs" | jq -r --arg n "${name}" '.items[]? | select(.name == $n) | .id' | head -1
}

policy_id_by_name() {
  local name="$1"
  local q="agent_policies?page=1&perPage=100"
  get_try "${q}" | jq -r --arg n "${name}" '.items[]? | select(.name == $n) | .id' | head -1
}

create_policy() {
  local output_id="${1:-}"
  local payload
  if [ -n "${output_id}" ]; then
    payload=$(jq -n --arg n "${POLICY_NAME}" --arg oid "${output_id}" '{
      name: $n,
      namespace: "default",
      description: "ForensIQ host policy for hot/cold + OCSF pipeline",
      monitoring_enabled: ["logs", "metrics"],
      is_default: false,
      is_default_fleet_server: false,
      has_fleet_server: false,
      supports_agentless: false,
      inactivity_timeout: 1209600,
      data_output_id: $oid,
      monitoring_output_id: $oid
    }')
  else
    payload=$(jq -n --arg n "${POLICY_NAME}" '{
      name: $n,
      namespace: "default",
      description: "ForensIQ host policy for hot/cold + OCSF pipeline",
      monitoring_enabled: ["logs", "metrics"],
      is_default: false,
      is_default_fleet_server: false,
      has_fleet_server: false,
      supports_agentless: false,
      inactivity_timeout: 1209600
    }')
  fi
  post_try "agent_policies" "${payload}" >/dev/null
}

ensure_policy() {
  local output_id="${1:-}"
  local pid
  pid="$(policy_id_by_name "${POLICY_NAME}")"
  if [ -n "${pid}" ]; then
    echo "Fleet policy exists: ${POLICY_NAME} (${pid})" >&2
  else
    echo "Creating Fleet policy: ${POLICY_NAME}" >&2
    create_policy "${output_id}"
    pid="$(policy_id_by_name "${POLICY_NAME}")"
    if [ -z "${pid}" ]; then
      echo "Failed to create or resolve policy id for ${POLICY_NAME}" >&2
      exit 1
    fi
  fi
  # stdout must be ID-only (consumed via command substitution).
  echo "${pid}"
}

create_enrollment_token() {
  local policy_id="$1"
  local payload
  payload=$(jq -n --arg n "${TOKEN_NAME}" --arg pid "${policy_id}" '{
    name: $n,
    policy_id: $pid
  }')
  post_try "enrollment_api_keys" "${payload}" | jq -r '.item.api_key'
}

LOGSTASH_OUTPUT_ID=""
if [ "${USE_LOGSTASH_OUTPUT}" = "true" ]; then
  LOGSTASH_OUTPUT_ID="$(output_id_by_name "Logstash Ingest Pipeline")"
  if [ -z "${LOGSTASH_OUTPUT_ID}" ]; then
    echo "Missing Fleet output 'Logstash Ingest Pipeline'. Run: task elk:fleet:bootstrap"
    exit 1
  fi
  echo "Using output: Logstash Ingest Pipeline (${LOGSTASH_OUTPUT_ID})"
else
  echo "Using policy default output (ForensIQ_USE_LOGSTASH_OUTPUT=false)"
fi

POLICY_ID="$(ensure_policy "${LOGSTASH_OUTPUT_ID}")"
ENROLLMENT_TOKEN="$(create_enrollment_token "${POLICY_ID}")"

echo
echo "Fleet agent setup complete"
echo "Policy: ${POLICY_NAME} (${POLICY_ID})"
echo "Enrollment token:"
echo "${ENROLLMENT_TOKEN}"
echo
echo "Next:"
echo "  Setup the policy as required in the Kibana UI, make sure to add any needed integrations for log collection"
echo "  task host-agent:enroll -- ${ENROLLMENT_TOKEN}"
echo