"""
Health and system capability endpoint.
"""
import platform
import sys
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.core.database import get_db
from app.services.traceroute_service import TracerouteService

router = APIRouter()


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Returns application health, database status, and network capabilities."""
    db_healthy = False
    try:
        db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception:
        db_healthy = False

    return {
        "status": "HEALTHY" if db_healthy else "DEGRADED",
        "version": settings.VERSION,
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "database_connected": db_healthy,
        "traceroute_supported": TracerouteService.is_available(),
        "ssrf_protection_active": not settings.ALLOW_PRIVATE_IPS,
        "allowed_ports_count": len(settings.ALLOWED_PORTS),
    }
