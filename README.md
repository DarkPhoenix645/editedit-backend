# editedit-backend

## Infra Setup & Run Instructions

1. Create .env in the `infrastructure/` directory:

   ```
   # Password for the 'elastic' user (at least 6 characters)
   ELASTIC_PASSWORD=something

   # Password for the 'kibana_system' user (at least 6 characters)
   KIBANA_PASSWORD=something

   # Version of Elastic Stack to use
   STACK_VERSION=8.12.0

   # License to use (basic, trial, or platinum)
   LICENSE=basic

   # Ports to expose to the host
   ES_PORT=9200
   KIBANA_PORT=5601
   LOGSTASH_PORT=5044
   LOGSTASH_MONITORING_PORT=9600

   ENCRYPTION_KEY=<random 32-character string for Kibana encryption>
   ```

2. Create volumes, from project root run: `mkdir -p volumes/certs volumes/esdata volumes/lsdata`
3. Run `docker compose up` from the `infrastructure/` directory.
4. Configure Fleet Server:
   1. In the Kibana UI, go to Management > Fleet > Agent Policies
   2. Create a new policy with the "Collect system logs and metrics" checkbox checked
   3. Create a new agent with "Add Agent" in Management > Fleet > Agents
   4. Copy the enrollment token
5. Configure Elastic Agent:
   1. Install [Task](https://taskfile.dev/docs/installation)
   2. From the root of the project, run `task host-agent:enroll <enrollment-token>`

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
