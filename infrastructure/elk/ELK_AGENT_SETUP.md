# ELK Stack 9.3.1 – Add Agent (UI + Docker/Taskfile)

End-to-end steps to configure Fleet in the Kibana UI and enroll a Dockerized
Elastic Agent for log collection using the Taskfile command.

**Assumptions:**

1. ELK stack is running
2. Fleet Server healthy
3. Kibana reachable at `https://localhost:5601` (or your host/port).
4. Stack started from `infrastructure/elk` so the Docker network is
   `elk_default`.
5. `jq` installed
6. `infrastructure/elk/.env` configured

**ForensIQ backend / MinIO:** The API stack (`task backend:up`) uses the
external Docker network **`forensiq_shared`**, shared with **MinIO**
(S3-compatible storage for WORM and cold paths). The Taskfile creates that
network if missing. It is separate from `elk_default`; the backend container
also joins `elk_default` when present. See the [README](../../README.md) FastAPI
section.

---

## Part 0: Bootstrap Fleet outputs (recommended)

```bash
task elk:fleet:bootstrap
```

This creates or updates **Elasticsearch Direct** and **Logstash Ingest
Pipeline** outputs with full TLS. For Logstash output it configures **mTLS**
using the same CA path the enrolled agent uses
(`/usr/share/elastic-agent/config/certs/ca/ca.crt`) plus shared client
certificate/key from `volumes/certs/elastic_agent/*`.

**Re-run this after changing CA/certs or hosts.**

### Logstash → Elasticsearch API key (required for Fleet integrations)

Fleet’s UI shows **Additional Logstash configuration required** until Logstash
actually ships Agent events to Elasticsearch with **`data_stream`** and the
**API key** from the output wizard. The `ingest` pipeline does that via
`LOGSTASH_FLEET_API_KEY`.

1. Edit **Kibana > Fleet > Settings > Outputs > Your Logstash Output**.
2. Copy API key generated from **Additional Logstash configuration required >
   Generate API key** into `infrastructure/elk/.env` as
   `LOGSTASH_FLEET_API_KEY=<key>`
3. Recreate Logstash so container env is refreshed:
   `task infra:logstash:recreate` (from repo root).

Without this, integration data cannot index correctly; routing only to ForensIQ
hot/cold pipelines also **breaks** Fleet (Elastic requires not mutating Agent
document shape before ES — see
[Logstash output](https://www.elastic.co/docs/reference/fleet/logstash-output)).

**Greyed-out Logstash/output controls in policy config?** In many fresh dev
setups, click **Start free trial** in Kibana first. If still greyed out, check
policy type: Fleet Server/APM policies cannot use Logstash as the default output
for integrations or monitoring; use Elasticsearch for those policy types.

### Fleet “Enable SSL” on the Logstash output — what the fields mean

When **Enable SSL** is on, Kibana’s form matches Elastic’s **mTLS** tutorial
([Configure SSL/TLS for the Logstash output](https://www.elastic.co/docs/reference/fleet/secure-logstash-connections)):
the in-product snippet uses `ssl_client_authentication => "required"`, so
**client** cert + key are **required** in the UI (there is an open request to
make them optional:
[kibana#145266](https://github.com/elastic/kibana/issues/145266)).

| UI field                               | What to paste (this repo after `task infra:certs:generate`)                                                                                  |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Server SSL certificate authorities** | Full PEM of **`volumes/certs/ca/ca.crt`** — agents use this CA to **verify** the Logstash **server** cert.                                   |
| **Client SSL certificate**             | Full PEM of **`volumes/certs/elastic_agent/elastic_agent.crt`** — shared client identity agents **present** to Logstash.                     |
| **Client SSL certificate key**         | PEM of **`elastic_agent.pkcs8.key`** if present, else **`elastic_agent.key`** — private key for the client cert (PKCS#8 preferred by Fleet). |

`task elk:fleet:bootstrap` can push the same PEMs via the Fleet API so you do
not have to paste them by hand, **after** the `elastic_agent` cert exists on
disk.

**ForensIQ mirror (duplicate stream):** The `ingest` pipeline **clones** each
Fleet/integration event (`data_stream` or `[@metadata][_id]`): the **original**
is indexed unchanged to Elasticsearch (Fleet contract); the **clone** is sent to
the hot + cold pipelines for OCSF/cold HTTP. That doubles Logstash work and
stores a second copy in `ocsf-logs-*` (and cold backend traffic) alongside the
managed data streams — plan capacity accordingly.

---

## Part 1: Kibana UI – One-time setup

### 1.1 Confirm Fleet Server and output

1. Open **Kibana > Fleet**.
2. Open the **Agents** tab. Confirm **Fleet Server is Healthy** and at least one
   Fleet Server agent is **Healthy**.
3. Open **Kibana > Fleet > Settings**.
4. Under **Fleet Server host**, confirm the default host has URL
   **`https://fleet:8220`** (used by agents in the same Docker network). Do not
   change this for Docker agents on `elk_default`.
5. Under **Outputs**, confirm **Elasticsearch Direct** exists with:
   - **Hosts:** `https://es01:9200`
   - **Certificate authority:**
     `/usr/share/elastic-agent/config/certs/ca/ca.crt`  
     If you see a different CA path (e.g. Kibana path), edit the output and set
     the path above so the Fleet container can reach Elasticsearch.

### 1.2 Create an agent policy for host/log collection

1. Go to **Kibana > Fleet > Agent policies**.
2. Click **Create agent policy**.
3. Set:
   - **Name:** `Host Log Collection` (or e.g. `ForensIQ Host Agent`).
   - **Description:** optional (e.g. "Docker agent for host logs and metrics").
   - **Data collection:** leave **Collect system logs and metrics** enabled
     (adds the System integration).
4. Click **Create agent policy**. Note the **Agent policy ID** (e.g.
   `host-log-policy` or a generated ID) for reference.
5. (Optional) In **Kibana > Fleet > Agent policies > Host Log Collection > Add
   integration**, add **System** if not already there; configure log streams
   (e.g. paths like `/var/log/*.log`) and metrics as needed. Save.

### 1.3 Create an enrollment token for the policy

1. Go to **Kibana > Fleet > Enrollment tokens**.
2. Click **Create enrollment token**.
3. Set:
   - **Name:** e.g. `Host Agent Docker`.
   - **Policy:** select the policy you created (e.g. **Host Log Collection**).
4. Click **Create enrollment token**.
5. **Copy the token** (long string). You will pass it to the Taskfile command.
   You can also create the token later from **Add agent** (step 2.2).

---

## Part 2: Add agent (UI flow + run Docker agent)

### 2.1 Open the Add agent flow

1. Go to **Kibana > Fleet > Agents**.
2. Click **Add agent**.

### 2.2 Enroll in Fleet and get the token

1. In the **Add agent** flyout, ensure **Enroll in Fleet** is selected (not
   standalone).
2. **Select an agent policy:** choose the policy you created (e.g. **Host Log
   Collection**).  
   If you already created an enrollment token for this policy, you can use that
   token and skip to 2.4.
3. If you create the token from this flyout: after selecting the policy, click
   **Continue** (or equivalent). Copy the **Enrollment token** shown in the
   **Run the agent** step.

### 2.3 Choose Docker and note the settings

1. In the same **Add agent** flow, select **Docker** as the platform.
2. The UI shows a `docker run` command. For our setup you will use the
   **Taskfile** instead, which uses the same token and correct network/CA paths.
   Ensure:
   - **Fleet URL** is `https://fleet:8220` (for agents on the same Docker
     network as Fleet).
   - **Enrollment token** is the one from step 2.2.

### 2.4 Run the agent with the Taskfile (from repo root)

From the **repository root** (so that `infrastructure/elk/volumes/certs` exists
and the ELK stack was started from `infrastructure/elk`):

```bash
task host-agent:enroll -- <ENROLLMENT_TOKEN>
```

- **Network:** The task uses `elk_default` (see Taskfile vars: `NETWORK`,
  `CERTS_PATH`). If you started the stack from the repo root with
  `docker compose -f infrastructure/elk/docker-compose.yml up -d`, the network
  name may be different (e.g. `editedit-backend_default`). In that case either:
  - Run the stack from `infrastructure/elk` so the network is `elk_default`, or
  - Override in Taskfile: set `NETWORK` to the actual network (e.g.
    `editedit-backend_default`).
- **Certs:** The task mounts `infrastructure/elk/volumes/certs` as `/certs` in
  the container and sets `FLEET_CA` and `ELASTICSEARCH_CA` to `/certs/ca/ca.crt`
  so the agent trusts Fleet and Elasticsearch.

### 2.5 Verify in Fleet

1. In **Kibana > Fleet > Agents**, wait up to about a minute.
2. You should see a new agent with status **Healthy**, policy **Host Log
   Collection** (or your policy name), and **Last activity** updating.
3. If the agent stays **Unhealthy**, check:
   - Agent and Fleet Server are on the same Docker network
     (`docker network inspect elk_default` and confirm both `elk-fleet-1` and
     `elastic-agent-host`).
   - Certs exist: `ls infrastructure/elk/volumes/certs/ca`.
   - Agent logs: `docker logs elastic-agent-host --tail 100`.

---

## Policy and settings summary (for Taskfile Docker agent)

| Item                 | Value                                                                                                                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Agent policy**     | One policy for host log collection (e.g. "Host Log Collection") with **Collect system logs and metrics** enabled (System integration).                                                           |
| **Fleet Server URL** | `https://fleet:8220` (agents must be on same Docker network as Fleet).                                                                                                                           |
| **Enrollment**       | Use an enrollment token tied to that policy.                                                                                                                                                     |
| **Output**           | Default **Elasticsearch Direct** (CA path `/usr/share/elastic-agent/config/certs/ca/ca.crt`) plus optional **Logstash Ingest Pipeline** output configured for mTLS (CA + agent client cert/key). |
| **Agent container**  | Image `docker.elastic.co/elastic-agent/elastic-agent:9.3.1`, root, network `elk_default`, certs at `/certs/ca/ca.crt` via `FLEET_CA` and `ELASTICSEARCH_CA`.                                     |

---

## Optional: Logstash output (ForensIQ pipeline)

If you want this agent to send data via Logstash (e.g. for OCSF/trust
classification) instead of directly to Elasticsearch:

1. In **Kibana > Fleet > Settings > Outputs**, ensure an output of type
   **Logstash** exists (e.g. **Logstash Ingest Pipeline**) with host
   `logstash:5044`.
2. In **Kibana > Fleet > Agent policies > Host Log Collection > Settings (or
   Output)**, select the policy output section.
3. Set the policy’s **Output** to that Logstash output (instead of Elasticsearch
   Direct). Save.
4. Redeploy or wait for the agent to pick up the new output.

The same Taskfile command and enrollment token remain valid; only the policy’s
output changes.

---

## Field provenance for ForensIQ pipeline

This is how the fields referenced in `hot.conf` are set today:

| Field                        | Source                                                                                                                            |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `@timestamp`                 | Set by Elastic Agent / integration ingest path (event occurrence time).                                                           |
| `message`                    | Original incoming payload; when payload is JSON-stringified, Logstash parses it and replaces `message` with the inner `.message`. |
| `event.dataset`              | Set by integration/data stream (`module.dataset` shape like `system.auth`, `application.app`, `tcp.generic`, etc.).               |
| `host.name`                  | Set by Elastic Agent host metadata and/or promoted from parsed message (`host.name` key in JSON payload).                         |
| `source.ip`                  | Present for network/listener integrations (for example custom TCP/UDP logs); optional for many host logs.                         |
| `destination.ip`             | Optional; present only when source integration provides destination endpoint context.                                             |
| `user.name`                  | Optional; present when source parser/integration extracts identity fields.                                                        |
| `event.outcome`              | Optional in ECS (`success` / `failure` / `unknown`); absent for many log types.                                                   |
| `event.id` / `event_id`      | Generated in Logstash (`uuid` filter) as unique per-event reference.                                                              |
| `forensiq.event_fingerprint` | Generated in Logstash from canonical immutable source fields; server-side verified on cold ingest.                                |

### forensiq.trust_tier values

`forensiq.trust_tier` is one of the 6 canonical ML bootstrap classes:

- `application`
- `cloud`
- `iam`
- `iot`
- `kernel`
- `os`

Logstash sets it from a coarse heuristic based on `event.dataset` (and a bit of
`event.category` evidence for IAM/auth). ML is expected to re-classify and can
override these values downstream.

### Why some OCSF fields are defaulted

OCSF requires enum IDs (`category_uid`, `class_uid`, `type_uid`, etc.). Not all
incoming datasets provide enough semantics to pick an exact class. Current
behavior:

- default to OCSF Base Event (`category_uid=0`, `class_uid=0`, `type_uid=0`)
- upgrade to IAM/Auth only when dataset/category clearly indicates
  authentication semantics

This avoids mislabeling non-auth logs while staying schema-valid.

---

## Fleet agent setup helper script

Use this to create/verify a Fleet policy aligned with ForensIQ and generate an
enrollment token:

```bash
task elk:fleet:agent:setup
```

Optional env vars:

- `FORENSIQ_POLICY_NAME` (default: `ForensIQ Host Log Collection`)
- `FORENSIQ_TOKEN_NAME` (default: `ForensIQ Host Agent Token`)
- `FORENSIQ_USE_LOGSTASH_OUTPUT` (default: `true`)

Then enroll:

```bash
task host-agent:enroll -- <TOKEN_FROM_OUTPUT>
```

---

## Useful commands

| Action                     | Command                                 |
| -------------------------- | --------------------------------------- |
| Enroll agent (ELK)         | `task host-agent:enroll -- <TOKEN>`     |
| Stop/remove agent          | `task host-agent:stop`                  |
| Agent logs                 | `docker logs elastic-agent-host -f`     |
| List agents (same network) | `docker ps --filter name=elastic-agent` |

---

## References (Elastic 9.3)

- [Install Fleet-managed Elastic Agents](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html)
- [Run Elastic Agent in a container](https://www.elastic.co/docs/reference/fleet/elastic-agent-container)
- [Elastic Agent environment variables](https://www.elastic.co/docs/reference/fleet/agent-environment-variables)
- [Elastic Agent policies](https://www.elastic.co/docs/reference/fleet/agent-policy)
