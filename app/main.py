from contextlib import asynccontextmanager

from fastapi import FastAPI

import app.db.models  # noqa: F401 - registers SQLAlchemy tables on Base.metadata
from app.api.router import api_router
from app.db.session import SessionLocal
from app.ml import MLEngine, build_ml_engine
from app.ml.counterfactual import rehydrate_hypothesis_store_from_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    ml: MLEngine = build_ml_engine()
    app.state.ml = ml
    db = SessionLocal()
    try:
        ml.rag.recover(db)
        rehydrate_hypothesis_store_from_db(db)
    finally:
        db.close()
    yield
    ml.anomaly.save()


app = FastAPI(title="EditEdit Backend", lifespan=lifespan)
app.include_router(api_router, prefix="/api")
