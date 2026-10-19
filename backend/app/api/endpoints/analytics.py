"""
Analytics API endpoint.
Returns aggregated statistics computed from real SQLite records.
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.analytics.analytics_engine import AnalyticsEngine
from app.schemas.diagnostic import AnalyticsOverviewResponse

router = APIRouter()


@router.get("/overview", response_model=AnalyticsOverviewResponse)
def get_analytics_overview(
    db: Session = Depends(get_db),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None)
):
    """
    Returns executive metrics, failure distribution, HTTP status codes,
    response time percentiles, and trend timelines.
    """
    s_dt = None
    e_dt = None
    if start_date:
        try:
            s_dt = datetime.fromisoformat(start_date.replace("Z", ""))
        except Exception:
            pass
    if end_date:
        try:
            e_dt = datetime.fromisoformat(end_date.replace("Z", ""))
        except Exception:
            pass

    metrics = AnalyticsEngine.get_overview_metrics(db, start_date=s_dt, end_date=e_dt)
    return AnalyticsOverviewResponse(**metrics)
