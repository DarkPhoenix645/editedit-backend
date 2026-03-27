from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.db.models  # noqa: F401 - registers SQLAlchemy tables on Base.metadata
from app.api.router import api_router
from app.core.config import settings
from app.db.session import SessionLocal
from app.ml import MLEngine, build_ml_engine
from app.ml.counterfactual import rehydrate_hypothesis_store_from_db
from app.services.infer_job_service import InferJobManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    ml: MLEngine = build_ml_engine()
    app.state.ml = ml
    app.state.infer_job_manager = InferJobManager()
    db = SessionLocal()
    try:
        ml.rag.recover(db)
        rehydrate_hypothesis_store_from_db(db)
    finally:
        db.close()
    yield
    ml.anomaly.save()


app = FastAPI(title="EditEdit Backend", lifespan=lifespan)

_cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(api_router, prefix="/api")