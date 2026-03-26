from fastapi import APIRouter
from app.api.endpoints import auth, audit_logs, cold_ingest, health, organizations, users

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])
api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(audit_logs.router, prefix="/audit-logs", tags=["Audit Logs"])
api_router.include_router(cold_ingest.router, tags=["Cold Stack"])