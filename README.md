# editedit-backend

Fastapi backend setup

## Configure .env file

```bash
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=editedit-db
POSTGRES_HOST=db
POSTGRES_PORT=5432

DATABASE_URL=postgresql://postgres:postgres@db:5432/editedit-db

HOST=0.0.0.0
PORT=8000

SECRET_KEY=lalalala123
```

## Steps to run

```bash
docker compose up --build
```