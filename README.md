# editedit-backend

## Infra Setup & Run Instructions

### ELK Stack (Fleet, Elasticsearch, Kibana, Logstash)

1. Create `.env` in `infrastructure/elk/`: copy
   `infrastructure/elk/.env.example` to `infrastructure/elk/.env` and set
   `ELASTIC_PASSWORD`, `KIBANA_PASSWORD`, and `ENCRYPTION_KEY` (and adjust other
   values if needed).

2. From project root, create volumes: `task infra:mkdir`

3. Generate TLS certs (one-time, if missing): `task infra:certs:generate`

4. Start the stack: `task infra:up`

5. **Fleet outputs (git-stable, UI-editable):** After Kibana is up, create the
   default Elasticsearch output and the Logstash ingest output with **server-auth
   TLS only** (agents verify Logstash’s server cert using the stack CA; no mTLS):

   ```bash
   task elk:fleet:bootstrap
   ```

   Uses `elastic` + `ELASTIC_PASSWORD` from `infrastructure/elk/.env`, talks to
   `https://localhost:${KIBANA_PORT:-5601}`, and sets `ssl.verification_mode` to
   `certificate` for Elasticsearch and `full` for Logstash (SAN includes `logstash`
   in the generated PKI). Override `KIBANA_URL` if Kibana is not on localhost.

6. **Fleet and Elastic Agent:** For step-by-step Kibana UI configuration (Fleet
   Server, agent policies, enrollment tokens) and enrolling a Docker agent with
   the Taskfile, see
   **[ELK Agent Setup — Fleet & Add Agent](infrastructure/elk/ELK_AGENT_SETUP.md)**.

7. Enroll a host agent (after getting an enrollment token from Kibana Fleet):
   install [Task](https://taskfile.dev/docs/installation), then from project
   root run:
   ```bash
   task host-agent:enroll -- <ENROLLMENT_TOKEN>
   ```

## FastAPI Backend Setup

1. Create .env in `app/`:

   ```bash
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=postgres
   POSTGRES_DB=editedit-db
   POSTGRES_HOST=db
   POSTGRES_PORT=5432

   # IMP: use +psycopg in the URL for enabling the use of psycopgv3
   DATABASE_URL=postgresql+psycopg://postgres:postgres@db:5432/editedit-db

   HOST=0.0.0.0
   PORT=8000

   SECRET_KEY=lalalala123
   ```

2. Create .env in `infrastructure/backend`:

   ```bash
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=postgres
   POSTGRES_DB=editedit-db
   POSTGRES_HOST=db
   POSTGRES_PORT=5432
   ```

3. Run with:
   ```bash
   docker compose up --build
   ```

## MacOS Note Regarding Setup
1. MacOS log collection is problematic, therefore we use synthetic logs for dev purposes.

2. Follow the same steps as usual and then utilise the `task host-agent:synthetic:inject` to inject logs in the container, the logs are stored at `/var/log/dev/synthetic.log`, this needs to be added to the Agent Policy under the System Integration

3. This can then be queried with the following in the Kibana Dev Tools
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

2. Start MinIO (local WORM)

   ```bash
   docker compose -f infrastructure/backend/docker-compose.minio.yml up -d
   ```

   Console: [http://localhost:9001](http://localhost:9001) (`minioadmin` /
   `minioadmin`)

3. Kibana UI verification
   - `Stack Management -> Index Management`: confirm `ocsf-logs-*` exists and
     doc count grows.
   - `Stack Management -> Index Lifecycle Policies`: confirm `ocsf-logs-7d`.
   - `Discover`: use/create data view `ocsf-logs-*`, verify
     `forensiq.event_fingerprint`, `forensiq.trust_tier`.
   - `Dev Tools`:

   ```http
   GET _ilm/explain/ocsf-logs-*
   ```

4. End-to-end smoke commands

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
   - Event appears in Kibana Discover (`ocsf-logs-*`).
   - Same fingerprint is present in `hot_cold_traces`.
   - A corresponding sealed block exists in `sealed_blocks`.
   - Object exists in WORM bucket.
   - No `raw-logs-*` writes from Logstash cold path.
