"""
History and Seed Demo Data API endpoints.
Provides search, filtering, pagination, and realistic demo data generation for portfolio presentation.
"""
from datetime import datetime, timedelta, timezone
import random
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.diagnostic import (
    DiagnosticRun,
    DiagnosticCheck,
    TroubleshootingFinding,
    CloudConfigurationAnalysis,
    SecurityFinding,
)
from app.schemas.diagnostic import (
    DiagnosticRunResponse,
    CheckResultSchema,
    FindingSchema,
)

router = APIRouter()


@router.get("/runs")
def list_runs(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    status: Optional[str] = Query(None),
    target_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None)
):
    """Lists diagnostic runs with pagination, search, and status filtering."""
    query = db.query(DiagnosticRun)

    if status and status.upper() != "ALL":
        query = query.filter(DiagnosticRun.status == status.upper())
    if target_type and target_type.upper() != "ALL":
        query = query.filter(DiagnosticRun.target_type == target_type.lower())
    if search:
        query = query.filter(DiagnosticRun.target.contains(search.strip().lower()))

    total = query.count()
    runs = query.order_by(desc(DiagnosticRun.created_at)).offset((page - 1) * page_size).limit(page_size).all()

    items = []
    for r in runs:
        items.append({
            "id": r.id,
            "target": r.target,
            "target_type": r.target_type,
            "status": r.status,
            "summary": r.summary,
            "duration_ms": r.duration_ms,
            "created_at": r.created_at,
            "checks_count": len(r.checks),
            "findings_count": len(r.findings),
        })

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items
    }


@router.get("/runs/{run_id}", response_model=DiagnosticRunResponse)
def get_run(run_id: str, db: Session = Depends(get_db)):
    """Retrieves single diagnostic run with full checks and findings details."""
    run = db.query(DiagnosticRun).filter(DiagnosticRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Diagnostic run not found")

    checks_list = [
        CheckResultSchema(
            check_type=c.check_type,
            status=c.status,
            duration_ms=c.duration_ms,
            details=c.details,
            error_message=c.error_message
        )
        for c in run.checks
    ]

    findings_list = [
        FindingSchema(
            symptom=f.symptom,
            confidence=f.confidence,
            likely_explanations=f.explanations,
            diagnostic_evidence=f.diagnostic_evidence,
            next_steps=f.next_steps,
            limitations=f.limitations
        )
        for f in run.findings
    ]

    return DiagnosticRunResponse(
        id=run.id,
        target=run.target,
        target_type=run.target_type,
        status=run.status,
        summary=run.summary,
        duration_ms=run.duration_ms,
        created_at=run.created_at,
        checks=checks_list,
        findings=findings_list
    )


@router.delete("/runs/{run_id}")
def delete_run(run_id: str, db: Session = Depends(get_db)):
    """Deletes a diagnostic run."""
    run = db.query(DiagnosticRun).filter(DiagnosticRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Diagnostic run not found")
    db.delete(run)
    db.commit()
    return {"message": f"Run {run_id} deleted successfully"}


@router.post("/seed-demo")
def seed_demo_data(db: Session = Depends(get_db)):
    """
    Seeds realistic educational demonstration datasets across diagnostic runs and security groups.
    Clearly tagged as [DEMO] for portfolio and recruiter presentations.
    """
    demo_scenarios = [
        {
            "target": "api.cloudguard-demo.internal",
            "type": "domain",
            "status": "FAILURE",
            "summary": "[DEMO] DNS resolution failure: Non-existent domain NXDOMAIN",
            "duration": 48.2,
            "days_ago": 4,
            "checks": [
                {"type": "dns", "status": "FAILURE", "duration": 48.2, "err": "NXDOMAIN: The domain does not exist in public resolver.", "details": {"records": {"A": [], "AAAA": []}}},
            ],
            "finding": {
                "symptom": "[DEMO] DNS resolution returned NXDOMAIN for 'api.cloudguard-demo.internal'.",
                "confidence": "HIGH",
                "explanations": ["Domain registration does not exist or private DNS zone not configured."],
                "evidence": "Recursive resolver returned NXDOMAIN after 48.2ms.",
                "next_steps": ["Verify internal Route 53 private hosted zone association."],
                "limitations": "Evaluated via local recursive resolver."
            }
        },
        {
            "target": "https://secure-portal.cloudguard-demo.com",
            "type": "url",
            "status": "SUCCESS",
            "summary": "[DEMO] Healthy TLS 1.3 Web Endpoint with 200 OK",
            "duration": 82.4,
            "days_ago": 3,
            "checks": [
                {"type": "http", "status": "SUCCESS", "duration": 82.4, "err": None, "details": {"status_code": 200, "is_tls": True, "redirect_count": 0}},
                {"type": "tls", "status": "SUCCESS", "duration": 45.1, "err": None, "details": {"tls_version": "TLSv1.3", "days_remaining": 64}}
            ],
            "finding": None
        },
        {
            "target": "db-staging.cloudguard-demo.net:5432",
            "type": "domain",
            "status": "FAILURE",
            "summary": "[DEMO] Connection Timeout on Database Port (SYN Dropped by Security Group)",
            "duration": 5012.0,
            "days_ago": 2,
            "checks": [
                {"type": "dns", "status": "SUCCESS", "duration": 34.0, "err": None, "details": {"records": {"A": ["198.51.100.22"]}}},
                {"type": "port", "status": "FAILURE", "duration": 4978.0, "err": "Connection timed out after 5.0s (TCP SYN dropped).", "details": {"port": 5432, "error_type": "CONNECTION_TIMEOUT"}}
            ],
            "finding": {
                "symptom": "[DEMO] TCP SYN packet to db-staging.cloudguard-demo.net:5432 timed out.",
                "confidence": "HIGH",
                "explanations": ["AWS Security Group or Network ACL drops inbound TCP 5432 from client IP."],
                "evidence": "Handshake timed out after 5.0 seconds with zero SYN-ACK response.",
                "next_steps": ["Inspect security group ingress rules for port 5432.", "Check VPC Route Table."],
                "limitations": "Result demonstrates transport drop; cannot inspect internal VPC ACLs directly."
            }
        },
        {
            "target": "https://legacy-admin.cloudguard-demo.org",
            "type": "url",
            "status": "FAILURE",
            "summary": "[DEMO] TLS Handshake Failure: Expired X.509 Certificate",
            "duration": 142.0,
            "days_ago": 1,
            "checks": [
                {"type": "tls", "status": "FAILURE", "duration": 65.0, "err": "Certificate Verification Error: certificate has expired", "details": {"is_expired": True, "days_remaining": -18}}
            ],
            "finding": {
                "symptom": "[DEMO] TLS certificate for 'legacy-admin.cloudguard-demo.org' is expired (-18 days).",
                "confidence": "HIGH",
                "explanations": ["Automated renewal pipeline failed or ACM certificate was not rotated."],
                "evidence": "Certificate expired 18 days ago.",
                "next_steps": ["Trigger renewal on Let's Encrypt / AWS Certificate Manager."],
                "limitations": "Validated against system CA bundle."
            }
        },
        {
            "target": "https://waf-protected.cloudguard-demo.com/admin",
            "type": "url",
            "status": "WARNING",
            "summary": "[DEMO] HTTP 403 Forbidden: WAF / Cloud Gateway Policy Block",
            "duration": 68.3,
            "days_ago": 1,
            "checks": [
                {"type": "http", "status": "WARNING", "duration": 68.3, "err": None, "details": {"status_code": 403, "status_phrase": "Forbidden", "redirect_count": 0}}
            ],
            "finding": {
                "symptom": "[DEMO] HTTP 403 Forbidden returned for '/admin'.",
                "confidence": "HIGH",
                "explanations": ["Cloud Security Gateway / Skyhigh WAF blocked request based on IP or RBAC."],
                "evidence": "Server returned HTTP 403 Forbidden.",
                "next_steps": ["Review WAF audit logs for triggered rule ID."],
                "limitations": "Confirms edge gateway active policy block; server is reachable."
            }
        },
        {
            "target": "https://microservice-gateway.cloudguard-demo.com",
            "type": "url",
            "status": "FAILURE",
            "summary": "[DEMO] HTTP 502 Bad Gateway: Upstream Microservice Unavailable",
            "duration": 1250.4,
            "days_ago": 0,
            "checks": [
                {"type": "http", "status": "FAILURE", "duration": 1250.4, "err": None, "details": {"status_code": 502, "status_phrase": "Bad Gateway"}}
            ],
            "finding": {
                "symptom": "[DEMO] HTTP 502 Bad Gateway returned by reverse proxy.",
                "confidence": "HIGH",
                "explanations": ["Backend ECS container/EC2 instance crashed or failed target health checks."],
                "evidence": "ALB returned 502 after upstream failed to respond.",
                "next_steps": ["Check CloudWatch TargetResponseTime and UnhealthyHostCount metrics."],
                "limitations": "Proves ingress ALB reached; internal container telemetry required."
            }
        }
    ]

    inserted_count = 0
    now = datetime.now(timezone.utc)

    for item in demo_scenarios:
        created_time = now - timedelta(days=item["days_ago"], hours=random.randint(1, 12))
        run = DiagnosticRun(
            target=item["target"],
            target_type=item["type"],
            status=item["status"],
            summary=item["summary"],
            duration_ms=item["duration"],
            created_at=created_time
        )
        db.add(run)
        db.flush()

        for c in item["checks"]:
            chk = DiagnosticCheck(
                run_id=run.id,
                check_type=c["type"],
                status=c["status"],
                duration_ms=c["duration"],
                error_message=c["err"],
                created_at=created_time
            )
            chk.details = c["details"]
            db.add(chk)

        if item.get("finding"):
            f = item["finding"]
            f_rec = TroubleshootingFinding(
                run_id=run.id,
                symptom=f["symptom"],
                confidence=f["confidence"],
                diagnostic_evidence=f["evidence"],
                limitations=f["limitations"],
                created_at=created_time
            )
            f_rec.explanations = f["explanations"]
            f_rec.next_steps = f["next_steps"]
            db.add(f_rec)

        inserted_count += 1

    # Also seed a sample cloud configuration analysis
    sample_analysis = CloudConfigurationAnalysis(
        name="[DEMO] Production DMZ & Bastion Security Group",
        raw_config_json="{}",
        summary="[DEMO] Analysis of sg-0a89f921: 2 Critical findings (Open SSH & Open MySQL).",
        critical_count=2,
        high_count=1,
        medium_count=0,
        low_count=1,
        info_count=1,
        created_at=now - timedelta(days=2)
    )
    db.add(sample_analysis)
    db.flush()

    db.add(SecurityFinding(
        analysis_id=sample_analysis.id,
        title="[DEMO] Publicly Accessible SSH Management Port (TCP 22)",
        severity="CRITICAL",
        rule_id="inbound-0",
        port_range="22",
        protocol="tcp",
        cidr="0.0.0.0/0",
        evidence='{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}',
        risk_explanation="SSH port 22 exposed to 0.0.0.0/0 allows automated password brute-forcing and unauthenticated exploit attempts.",
        remediation="Restrict SSH ingress to authorized corporate VPN CIDRs or migrate to AWS SSM Session Manager.",
        confidence="HIGH"
    ))

    db.add(SecurityFinding(
        analysis_id=sample_analysis.id,
        title="[DEMO] Publicly Accessible Database Port MySQL (Port 3306)",
        severity="CRITICAL",
        rule_id="inbound-1",
        port_range="3306",
        protocol="tcp",
        cidr="0.0.0.0/0",
        evidence='{"FromPort": 3306, "ToPort": 3306, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}',
        risk_explanation="Direct public access to relational database permits brute forcing credentials and exploits.",
        remediation="Place database in private isolated VPC subnet with security group reference.",
        confidence="HIGH"
    ))

    db.commit()
    return {
        "status": "SUCCESS",
        "message": f"Successfully seeded {inserted_count} educational diagnostic runs and 1 sample cloud security analysis.",
        "runs_seeded": inserted_count
    }
