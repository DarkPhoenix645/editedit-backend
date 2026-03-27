from fastapi import APIRouter

from app.api.endpoints import auth, audit_logs, cases, cold, graph_api, health, log_sources, organizations, hypotheses, infer, phase6, users

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(cases.router, prefix="/cases", tags=["Cases"])
api_router.include_router(log_sources.router, prefix="/log-sources", tags=["Log Sources"])
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])
api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(audit_logs.router, prefix="/audit-logs", tags=["Audit Logs"])
api_router.include_router(cold.router, prefix="/cold", tags=["Cold Ingest"])
api_router.include_router(infer.router, prefix="/ml", tags=["ML"])
api_router.include_router(hypotheses.router, prefix="/hypotheses", tags=["Hypotheses"])
api_router.include_router(graph_api.router, prefix="/graph", tags=["Graph"])
api_router.include_router(phase6.router, prefix="/phase6", tags=["Phase 6"])