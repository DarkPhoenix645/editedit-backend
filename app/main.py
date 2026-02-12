from fastapi import FastAPI
from app.api.router import api_router
from app.db.session import engine
from app.db.models import Base

app = FastAPI(title="EditEdit Backend")

Base.metadata.create_all(bind=engine) 

app.include_router(api_router, prefix="/api")