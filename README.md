# editedit-backend

## Submission Artifacts

Deployed Frontend Link: https://forensiq-frontend-deployed.vercel.app/ Backend +
ML Services Source Code: https://github.com/DarkPhoenix645/editedit-backend
Frontend Service Source Code:
https://github.com/DarkPhoenix645/forensiq-frontend

## Infra Setup & Run Instructions

## TLS Strategy (Dev + AWS)

This repo uses two TLS layers:

1. **Public edge TLS** (browser/API clients): certificate trusted by public CAs.
2. **Internal service TLS** (Elasticsearch/Kibana/Fleet/Logstash/backend
   container traffic): private CA chain trusted by stack services.

### Exact split (recommended)

- **Dev (local Docker)**
  - Internal container TLS CA: **private CA** (`setup` certutil).
  - Backend HTTPS cert (`backend.crt/.key`): same internal CA chain from
    `infrastructure/elk/volumes/certs/backend/*`.
- **AWS deploy (frontend on Vercel)**
  - Public TLS (`api.yourdomain.com`, optional `kibana.yourdomain.com`): **AWS
    ACM public cert** on **ALB**.
  - Internal container TLS (ES/Kibana/Fleet/Logstash/backend): **private
    CA-issued certs** (self-managed CA, Step CA, or AWS Private CA), mounted to
    the same cert paths expected by this stack.

Important: internal service names like `es01`, `kib01`, `fleet`, `logstash`,
`backend` are not public DNS names, so they should use a **private CA**, not
public internet CAs.

### ELK Stack (Fleet, Elasticsearch, Kibana, Logstash)

1. Create `.env` in `infrastructure/elk/`: copy
   `infrastructure/elk/.env.example` to `infrastructure/elk/.env` and set
   `ELASTIC_PASSWORD`, `KIBANA_PASSWORD`, and `ENCRYPTION_KEY` (and adjust other
   values if needed).

2. From project root, create volumes: `task infra:mkdir`

3. Generate TLS certs (one-time, if missing): `task infra:certs:generate`

4. Start the stack: `task infra:up`

5. **Fleet outputs (git-stable, UI-editable):** After Kibana is up, create the
   default Elasticsearch output and the Logstash ingest output with full TLS,
   including Logstash mTLS (agents verify server cert and present client cert):

   ```bash
   task elk:fleet:bootstrap
   ```

   Uses `elastic` + `ELASTIC_PASSWORD` from `infrastructure/elk/.env`, talks to
   `https://localhost:${KIBANA_PORT:-5601}`, sets `ssl.verification_mode` to
   `certificate` for Elasticsearch and configures Logstash output SSL with: CA +
   client certificate + client key (from
   `infrastructure/elk/volumes/certs/elastic_agent/*`) and verification mode
   `full`. Override `KIBANA_URL` if Kibana is not on localhost.

6. **Fleet and Elastic Agent:** For step-by-step Kibana UI configuration (Fleet
   Server, agent policies, enrollment tokens) and enrolling a Docker agent with
   the Taskfile, see
   **[ELK Agent Setup — Fleet & Add Agent](infrastructure/elk/ELK_AGENT_SETUP.md)**.
   For one-command Fleet policy + token bootstrap aligned to ForensIQ pipelines:
   `task elk:fleet:agent:setup`

7. Enroll a host agent (after getting an enrollment token from Kibana Fleet):
   install [Task](https://taskfile.dev/docs/installation), then from project
   root run:
   ```bash
   task host-agent:enroll -- <ENROLLMENT_TOKEN>
   ```

## FastAPI Backend Setup

1. **Shared Docker network:** `task backend:up` creates `forensiq_shared` if it
   does not exist (used by MinIO and the backend container).

2. **Environment file** — values map to `app.core.config.Settings` (see
   `app/core/config.py`). Copy `infrastructure/backend/.env.example` →
   `infrastructure/backend/.env` and set secrets (`SECRET_KEY`,
   `LOGSTASH_SHARED_SECRET`, DB passwords, `WORM_*`, cold `MINIO_*`, optional
   `SMTP_*` for password-reset email, etc.). This path is used both by Docker
   and by local / IDE runs. For Postgres on the host instead of the `db`
   service, set `DATABASE_URL` with host `localhost`.

   Use `postgresql+psycopg://...` in `DATABASE_URL` for psycopg v3.

3. **TLS:** The backend compose command expects certs at
   `infrastructure/elk/volumes/certs/...` (see
   `infrastructure/backend/docker-compose.yml`). Generate certs with
   `task infra:certs:generate` after `task infra:mkdir`, or adjust the compose
   command for HTTP-only dev.

4. **Run the stack** (Postgres + MinIO + init buckets + API):

   ```bash
   task backend:up
   ```

   Apply DB schema: `task backend:db:upgrade`.

## MacOS Note Regarding Setup

1. MacOS log collection is problematic, therefore we use synthetic logs for dev
   purposes.

2. Follow the same steps as usual and then utilise the
   `task host-agent:synthetic:inject` to inject logs in the container, the logs
   are stored at `/var/log/dev/synthetic.log`, this needs to be added to the
   Agent Policy under the System Integration

3. This can then be queried in **Kibana > Dev Tools**:

   ```json
   GET logs-*/_search
   {
   "size": 20,
   "sort": [{ "@timestamp": "desc" }],
   "query": {
      "bool": {
         "should": [
         { "match_phrase": { "message": "synthetic event" } },
         { "match_phrase": { "message": "dev.synthetic" } },
         { "match_phrase": { "host.name": "macos-dev" } }
         ],
         "minimum_should_match": 1
      }
   }
   }
   ```

4. The logs should be saved under the dataset `event.dataset: system.syslog`

## ForensIQ v2.1 Hot/Cold Setup

1. Bootstrap ILM for hot OCSF indices

   From repo root:

   ```bash
   task elk:ilm:bootstrap
   ```

   This creates:
   - ILM policy: `ocsf-logs-7d`
   - index template: `ocsf-logs-template` for `ocsf-logs-*`

2. MinIO (local S3 / WORM + cold JSON buckets)

   MinIO is part of `infrastructure/backend/docker-compose.yml` (`minio` +
   `minio-init`). It starts automatically with `task backend:up`, or run
   `task minio:up` if you only need object storage.

   Console: [http://localhost:9001](http://localhost:9001) (default `minioadmin`
   / `minioadmin`; align with `WORM_ACCESS_KEY` / `WORM_SECRET_KEY` in `.env`).

   To force-recreate the WORM bucket with object lock, set
   `MINIO_WORM_RECREATE_BUCKET=true` once in `infrastructure/backend/.env`, then
   recreate the `minio-init` container (see comments in the compose file).

3. Kibana UI verification
   - **Kibana > Stack Management > Index Management**: confirm `ocsf-logs-*`
     exists and doc count grows.
   - **Kibana > Stack Management > Index Lifecycle Policies**: confirm
     `ocsf-logs-7d`.
   - **Kibana > Discover**: use/create data view `ocsf-logs-*`, verify
     `forensiq.event_fingerprint`, `forensiq.trust_tier`.
   - **Kibana > Dev Tools**:

   ```http
   GET _ilm/explain/ocsf-logs-*
   ```

4. E2E smoke commands

   Publish a test log on the enrolled agent host:

   ```bash
   logger -t forensiq-smoke '{"dataset":"system.auth","message":"forensiq smoke test","host.name":"smoke-host"}'
   ```

   Check hot path in Elasticsearch:

   ```bash
   curl -s -u elastic:$ELASTIC_PASSWORD --cacert infrastructure/elk/volumes/certs/ca/ca.crt \
     'https://localhost:9200/ocsf-logs-*/_search?q=forensiq-smoke&sort=@timestamp:desc&size=5'
   ```

   Check cold path backend ingestion:

   ```bash
   docker logs fastapi-backend --since 2m | rg '/api/cold/ingest|sealed|block_id'
   ```

   Check DB persistence:

   ```bash
   docker exec -it postgres-db psql -U ${POSTGRES_USER:-postgres} -d ${POSTGRES_DB:-editedit-db} \
     -c "select id, sequence_number, created_at from sealed_blocks order by authoritative_time desc limit 5;"

   docker exec -it postgres-db psql -U ${POSTGRES_USER:-postgres} -d ${POSTGRES_DB:-editedit-db} \
     -c "select event_fingerprint, block_id from hot_cold_traces order by created_at desc limit 5;"
   ```

   Check MinIO object:

   ```bash
   docker exec -it minio sh -lc 'mc alias set local http://minio:9000 minioadmin minioadmin >/dev/null 2>&1; mc ls local/forensiq-cold-dev/blocks/'
   ```

5. Acceptance criteria:
   - Event appears in **Kibana > Discover** (`ocsf-logs-*`).
   - Same fingerprint is present in `hot_cold_traces`.
   - A corresponding sealed block exists in `sealed_blocks`.
   - Object exists in WORM bucket.
   - No `raw-logs-*` writes from Logstash cold path.

## AWS Deployment TLS Process (exact)

Use this process when frontend is on Vercel and backend/ELK are on AWS:

1. **Public API domain + ACM cert**
   - Create Route53 record for `api.yourdomain.com`.
   - Request ACM public cert for `api.yourdomain.com` (and any additional public
     hostnames).
   - Attach ACM cert to ALB listener `:443`.
   - Configure ALB `:80` -> redirect to `:443`.

2. **Run app containers behind ALB**
   - ALB -> backend target group (HTTP or HTTPS; if HTTPS internally, mount
     backend cert/key).
   - Security groups: ALB public inbound 443; backend inbound only from ALB SG.

3. **Internal stack certs (identical behavior to local cert bootstrap)**
   - Keep cert file layout:
     - `certs/ca/ca.crt`
     - `certs/es01/es01.crt|key`
     - `certs/kib01/kib01.crt|key`
     - `certs/fleet/fleet.crt|key`
     - `certs/logstash/logstash.crt|key`
     - `certs/backend/backend.crt|key`
     - `certs/elastic_agent/elastic_agent.crt|key|elastic_agent.pkcs8.key`
   - Populate these certs via one-shot certutil bootstrap task/job.
   - Mount certs read-only into each container at the same paths as compose
     config.

4. **Vercel frontend integration**
   - Set frontend env to public API:
     - `VITE_API_URL=https://api.yourdomain.com`
   - Set backend CORS to Vercel domains:
     - `CORS_ORIGINS=https://<your-project>.vercel.app,https://app.yourdomain.com`

5. **Forgot-password link correctness**
   - Set:
     - `FRONTEND_RESET_PASSWORD_URL=https://app.yourdomain.com/reset-password`
   - Ensure SMTP is configured (`SMTP_*`) and reachable from backend runtime.

6. **Validation checks**
   - Public edge cert:
     - `curl -I https://api.yourdomain.com/api/health/`
   - Internal CA trust in stack:
     - `curl --cacert /path/to/ca.crt https://es01:9200` from trusted container
       context
   - Fleet/Logstash mTLS still healthy (per
     `infrastructure/elk/ELK_AGENT_SETUP.md`).
