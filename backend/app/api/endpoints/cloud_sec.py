"""
Cloud Security Configuration Analyzer API endpoints.
Analyzes AWS Security Group JSON configurations and flags least-privilege violations.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.diagnostic import (
    CloudConfigurationAnalysis,
    SecurityFinding,
)
from app.schemas.diagnostic import (
    CloudConfigRequest,
    CloudAnalysisResponse,
    SecurityFindingSchema,
)
from app.security.aws_sg_analyzer import analyze_security_group_json

router = APIRouter()


@router.post("/analyze", response_model=CloudAnalysisResponse)
def analyze_cloud_configuration(
    req: CloudConfigRequest,
    db: Session = Depends(get_db)
):
    """Analyzes a pasted AWS Security Group JSON string."""
    try:
        result = analyze_security_group_json(req.config_json)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    analysis = CloudConfigurationAnalysis(
        name=req.name or result.group_name,
        raw_config_json=req.config_json,
        summary=f"Analysis of {result.group_name}: {result.summary.get('CRITICAL', 0)} Critical, {result.summary.get('HIGH', 0)} High findings.",
        critical_count=result.summary.get("CRITICAL", 0),
        high_count=result.summary.get("HIGH", 0),
        medium_count=result.summary.get("MEDIUM", 0),
        low_count=result.summary.get("LOW", 0),
        info_count=result.summary.get("INFORMATIONAL", 0),
    )
    db.add(analysis)
    db.flush()

    finding_schemas: List[SecurityFindingSchema] = []
    for f in result.findings:
        rec = SecurityFinding(
            analysis_id=analysis.id,
            title=f.title,
            severity=f.severity,
            rule_id=f.rule_id,
            port_range=f.port_range,
            protocol=f.protocol,
            cidr=f.cidr,
            evidence=f.evidence,
            risk_explanation=f.risk_explanation,
            remediation=f.remediation,
            confidence=f.confidence
        )
        db.add(rec)
        finding_schemas.append(SecurityFindingSchema(
            title=f.title,
            severity=f.severity,
            rule_id=f.rule_id,
            port_range=f.port_range,
            protocol=f.protocol,
            cidr=f.cidr,
            evidence=f.evidence,
            risk_explanation=f.risk_explanation,
            remediation=f.remediation,
            confidence=f.confidence
        ))

    db.commit()

    return CloudAnalysisResponse(
        id=analysis.id,
        name=analysis.name,
        group_name=result.group_name,
        group_id=result.group_id,
        description=result.description,
        vpc_id=result.vpc_id,
        total_rules_evaluated=result.total_rules_evaluated,
        summary=result.summary,
        findings=finding_schemas,
        educational_note=result.educational_note,
        created_at=analysis.created_at
    )


@router.post("/upload", response_model=CloudAnalysisResponse)
async def upload_cloud_configuration(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Analyzes an uploaded AWS Security Group JSON file."""
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only .json files are supported.")

    content = await file.read()
    try:
        json_str = content.decode("utf-8")
        result = analyze_security_group_json(json_str)
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 encoded text.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    analysis = CloudConfigurationAnalysis(
        name=file.filename,
        raw_config_json=json_str,
        summary=f"Analysis of {file.filename}: {result.summary.get('CRITICAL', 0)} Critical, {result.summary.get('HIGH', 0)} High findings.",
        critical_count=result.summary.get("CRITICAL", 0),
        high_count=result.summary.get("HIGH", 0),
        medium_count=result.summary.get("MEDIUM", 0),
        low_count=result.summary.get("LOW", 0),
        info_count=result.summary.get("INFORMATIONAL", 0),
    )
    db.add(analysis)
    db.flush()

    finding_schemas = []
    for f in result.findings:
        rec = SecurityFinding(
            analysis_id=analysis.id,
            title=f.title,
            severity=f.severity,
            rule_id=f.rule_id,
            port_range=f.port_range,
            protocol=f.protocol,
            cidr=f.cidr,
            evidence=f.evidence,
            risk_explanation=f.risk_explanation,
            remediation=f.remediation,
            confidence=f.confidence
        )
        db.add(rec)
        finding_schemas.append(SecurityFindingSchema(
            title=f.title,
            severity=f.severity,
            rule_id=f.rule_id,
            port_range=f.port_range,
            protocol=f.protocol,
            cidr=f.cidr,
            evidence=f.evidence,
            risk_explanation=f.risk_explanation,
            remediation=f.remediation,
            confidence=f.confidence
        ))

    db.commit()

    return CloudAnalysisResponse(
        id=analysis.id,
        name=analysis.name,
        group_name=result.group_name,
        group_id=result.group_id,
        description=result.description,
        vpc_id=result.vpc_id,
        total_rules_evaluated=result.total_rules_evaluated,
        summary=result.summary,
        findings=finding_schemas,
        educational_note=result.educational_note,
        created_at=analysis.created_at
    )


@router.get("/analyses", response_model=List[dict])
def list_analyses(db: Session = Depends(get_db)):
    """Lists recent cloud security configuration analyses."""
    analyses = db.query(CloudConfigurationAnalysis).order_by(CloudConfigurationAnalysis.created_at.desc()).limit(20).all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "summary": a.summary,
            "critical_count": a.critical_count,
            "high_count": a.high_count,
            "medium_count": a.medium_count,
            "low_count": a.low_count,
            "info_count": a.info_count,
            "created_at": a.created_at
        }
        for a in analyses
    ]
