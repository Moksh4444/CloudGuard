"""
Diagnostic Reporting API endpoints.
Generates and exports professional reports in JSON, CSV, and HTML formats.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.diagnostic import ReportMetadata
from app.reports.report_generator import ReportGenerator

router = APIRouter()


class ExportReportRequest(BaseModel):
    run_id: str
    format: str = Field(default="json", description="Export format: json, csv, or html")


@router.post("/export")
def export_report(
    req: ExportReportRequest,
    db: Session = Depends(get_db)
):
    """Generates an exportable diagnostic report (JSON, CSV, or HTML)."""
    try:
        report_data = ReportGenerator.generate_run_report(
            db=db,
            run_id=req.run_id,
            export_format=req.format
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return report_data


@router.get("")
def list_reports(db: Session = Depends(get_db)):
    """Lists generated report metadata."""
    reports = db.query(ReportMetadata).order_by(desc(ReportMetadata.generated_at)).limit(50).all()
    return [
        {
            "id": r.id,
            "report_uid": r.report_uid,
            "title": r.title,
            "target": r.target,
            "scope": r.scope,
            "format": r.format,
            "generated_at": r.generated_at,
            "run_id": r.run_id
        }
        for r in reports
    ]
