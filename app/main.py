from fastapi import FastAPI
from app.api.router import api_router
import app.db.models  # noqa: F401 - registers SQLAlchemy tables on Base.metadata

# Schema is owned by Alembic only — run `task backend:db:upgrade` after deploy.

app = FastAPI(title="EditEdit Backend")
app.include_router(api_router, prefix="/api")