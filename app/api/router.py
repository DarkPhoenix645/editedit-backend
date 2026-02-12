from fastapi import APIRouter
from app.api.endpoints import health, auth

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["Health"])