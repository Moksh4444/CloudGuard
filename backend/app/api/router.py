"""
Central API router combining all sub-routers under /api/v1.
"""
from fastapi import APIRouter

from app.api.endpoints.health import router as health_router
from app.api.endpoints.diagnostics import router as diagnostics_router
from app.api.endpoints.cloud_sec import router as cloud_sec_router
from app.api.endpoints.history import router as history_router
from app.api.endpoints.analytics import router as analytics_router
from app.api.endpoints.reports import router as reports_router

api_router = APIRouter()

api_router.include_router(health_router, tags=["Health"])
api_router.include_router(diagnostics_router, prefix="/diagnostics", tags=["Diagnostics"])
api_router.include_router(cloud_sec_router, prefix="/cloud-security", tags=["Cloud Security"])
api_router.include_router(history_router, prefix="/history", tags=["History & Demos"])
api_router.include_router(analytics_router, prefix="/analytics", tags=["Analytics"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reports"])
