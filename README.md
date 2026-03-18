# editedit-backend

## Infra Setup & Run Instructions

### ELK Stack (Fleet, Elasticsearch, Kibana, Logstash)

1. Create `.env` in `infrastructure/elk/`: copy `infrastructure/elk/.env.example` to `infrastructure/elk/.env` and set `ELASTIC_PASSWORD`, `KIBANA_PASSWORD`, and `ENCRYPTION_KEY` (and adjust other values if needed).

2. From project root, create volumes: `task infra:mkdir`

3. Start the stack from `infrastructure/elk/`: `cd infrastructure/elk && docker compose up -d`

4. **Fleet and Elastic Agent:** For step-by-step Kibana UI configuration (Fleet Server, agent policies, enrollment tokens) and enrolling a Docker agent with the Taskfile, see **[ELK Agent Setup — Fleet & Add Agent](infrastructure/elk/ELK_AGENT_SETUP.md)**.

5. Enroll a host agent (after getting an enrollment token from Kibana Fleet): install [Task](https://taskfile.dev/docs/installation), then from project root run:
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
