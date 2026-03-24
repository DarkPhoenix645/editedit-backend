from fastapi import APIRouter
from app.api.endpoints import health, auth, users, cold

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(cold.router, prefix="/cold", tags=["Cold Ingest"])