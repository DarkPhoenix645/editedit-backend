# ELK Stack 9.3.1 – Add Agent (UI + Docker/Taskfile)

End-to-end steps to configure Fleet in the Kibana UI and enroll a Dockerized
Elastic Agent for log collection using the Taskfile command.

**Assumptions:** ELK stack is running (Fleet Server healthy), Kibana reachable
at `https://localhost:5601` (or your host/port). Stack started from
`infrastructure/elk` so the Docker network is `elk_default`.

---

## Part 0: Bootstrap Fleet outputs (recommended)

From the **repository root** (with `jq` installed and `infrastructure/elk/.env`
configured):

```bash
task elk:fleet:bootstrap
```

This creates or updates **Elasticsearch Direct** and **Logstash Ingest
Pipeline** outputs with TLS **server verification** using the same CA path the
enrolled agent uses (`/usr/share/elastic-agent/config/certs/ca/ca.crt`). It does
**not** configure client certificates (no mTLS). **Re-run this after changing CA
or hosts.**

---

## Part 1: Kibana UI – One-time setup

### 1.1 Confirm Fleet Server and output

1. Open **Kibana** → **Management** (gear) → **Fleet** (or **Fleet** from the
   main menu).
2. Open the **Agents** tab. Confirm **Fleet Server is Healthy** and at least one
   Fleet Server agent is **Healthy**.
3. Open the **Settings** tab (or **Fleet** → **Settings**).
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

1. Go to **Fleet** → **Agent policies**.
2. Click **Create agent policy**.
3. Set:
   - **Name:** `Host Log Collection` (or e.g. `ForensIQ Host Agent`).
   - **Description:** optional (e.g. "Docker agent for host logs and metrics").
   - **Data collection:** leave **Collect system logs and metrics** enabled
     (adds the System integration).
4. Click **Create agent policy**. Note the **Agent policy ID** (e.g.
   `host-log-policy` or a generated ID) for reference.
5. (Optional) Click the new policy → **Add integration**. Add **System** if not
   already there; configure log streams (e.g. paths like `/var/log/*.log`) and
   metrics as needed. Save.

### 1.3 Create an enrollment token for the policy

1. Go to **Fleet** → **Enrollment tokens**.
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

1. Go to **Fleet** → **Agents**.
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

Example:

```bash
task host-agent:enroll -- eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
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

1. In **Fleet** → **Agents**, wait up to about a minute.
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

| Item                 | Value                                                                                                                                                                       |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Agent policy**     | One policy for host log collection (e.g. "Host Log Collection") with **Collect system logs and metrics** enabled (System integration).                                      |
| **Fleet Server URL** | `https://fleet:8220` (agents must be on same Docker network as Fleet).                                                                                                      |
| **Enrollment**       | Use an enrollment token tied to that policy.                                                                                                                                |
| **Output**           | Default **Elasticsearch Direct** with CA path `/usr/share/elastic-agent/config/certs/ca/ca.crt` (for the Fleet container; your Docker agent gets output config from Fleet). |
| **Agent container**  | Image `docker.elastic.co/elastic-agent/elastic-agent:9.3.1`, root, network `elk_default`, certs at `/certs/ca/ca.crt` via `FLEET_CA` and `ELASTICSEARCH_CA`.                |

---

## Optional: Logstash output (ForensIQ pipeline)

If you want this agent to send data via Logstash (e.g. for OCSF/trust
classification) instead of directly to Elasticsearch:

1. **Fleet** → **Settings** → **Outputs**. Ensure an output of type **Logstash**
   exists (e.g. **Logstash Ingest Pipeline**) with host `logstash:5044`.
2. **Fleet** → **Agent policies** → your policy (e.g. **Host Log Collection**) →
   **Settings** or **Output**.
3. Set the policy’s **Output** to that Logstash output (instead of Elasticsearch
   Direct). Save.
4. Redeploy or wait for the agent to pick up the new output.

The same Taskfile command and enrollment token remain valid; only the policy’s
output changes.

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
