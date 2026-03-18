from contextlib import asynccontextmanager

from fastapi import FastAPI
from app.db.base import Base
from app.db.session import engine
from app.api.router import api_router
import app.db.models  # noqa: F401 - registers SQLAlchemy tables on Base.metadata

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure DB tables exist even if Alembic isn't run (useful in local/dev containers).
    # Uses SQLAlchemy metadata from `app.db.models`.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="EditEdit Backend", lifespan=lifespan)
app.include_router(api_router, prefix="/api")