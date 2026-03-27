# MVP Data Lineage (Elastic Agent -> Hypotheses -> UI)

## Ingestion
- Elastic agents send logs into Logstash.
- Logstash forwards ML payloads to `/api/ml/infer`.
- Cold paths persist payloads through `/api/cold/ingest` and `/api/cold/stack-ingest`.

## Inference
- `/api/ml/infer` is asynchronous and returns `job_id`.
- Worker normalizes events and runs `infer_event`.
- If no `case_id` is provided, worker creates/reuses a `SYSTEM_GENERATED` case.

## Persistence
- Hypotheses saved in `forensic_hypotheses`.
- Evidence linkage saved in `hypothesis_evidence_map`.
- Cold traceability saved in `hot_cold_traces`.

## Scenario Grouping
- Each emitted hypothesis stores `scenario_id` and `scenario_title`.
- Timeline API groups by `scenario_id`.

## Proof + Raw Evidence
- Block verification uses `/api/cold/verify/{block_id}`.
- Merkle visualization data uses:
  - `/api/cold/blocks/{block_id}/proof-graph`
  - `/api/cold/blocks/{block_id}/proof-path/{event_fingerprint}`
- Exact raw lines are returned via `GET /api/hypotheses/{hyp_id}` evidence items.

## Dossier
- Case dossier APIs:
  - `POST /api/cases/{case_id}/dossier`
  - `GET /api/cases/{case_id}/dossier/{job_id}`
  - `GET /api/cases/{case_id}/dossier/{job_id}/download`
