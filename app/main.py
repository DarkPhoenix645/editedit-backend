from fastapi import FastAPI
from app.api.router import api_router
import app.db.models  

app = FastAPI(title="EditEdit Backend")
app.include_router(api_router, prefix="/api")
