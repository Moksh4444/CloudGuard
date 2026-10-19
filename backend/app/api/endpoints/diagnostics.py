"""
Core diagnostic endpoints: Network (DNS + Port + Route), HTTP/HTTPS, DNS, and TLS.
All executions persist runs, checks, and troubleshooting findings to SQLite.
"""
import time
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.diagnostic import (
    DiagnosticRun,
    DiagnosticCheck,
    TroubleshootingFinding,
)
from app.schemas.diagnostic import (
    NetworkDiagnosticRequest,
    HttpAnalysisRequest,
    DnsLookupRequest,
    TlsInspectionRequest,
    DiagnosticRunResponse,
    HttpAnalysisResponse,
    DnsLookupResponse,
    TlsCertificateInfo,
    CheckResultSchema,
    FindingSchema,
)
from app.services.dns_service import DnsService
from app.services.port_service import PortService
from app.services.traceroute_service import TracerouteService
from app.services.http_service import HttpService
from app.services.tls_service import TlsService

router = APIRouter()


@router.post("/network", response_model=DiagnosticRunResponse)
def run_network_diagnostic(
    req: NetworkDiagnosticRequest,
    db: Session = Depends(get_db)
):
    """
    Executes composite network diagnostic on target: DNS resolution, TCP port handshake,
    and optional bounded traceroute.
    """
    start_time = time.perf_counter()
    checks_list = []
    findings_list = []
    overall_status = "SUCCESS"

    # Create Diagnostic Run record
    run = DiagnosticRun(
        target=req.target,
        target_type="domain" if not req.target.replace(".", "").isdigit() else "ip",
        status="RUNNING",
        summary=f"Network diagnostic against {req.target}:{req.port}",
    )
    db.add(run)
    db.flush()

    # 1. DNS Check
    if req.run_dns:
        dns_res = DnsService.resolve_domain(req.target, ["A", "AAAA"])
        chk_status = dns_res.status
        if chk_status == "FAILURE":
            overall_status = "FAILURE"

        check_record = DiagnosticCheck(
            run_id=run.id,
            check_type="dns",
            status=chk_status,
            duration_ms=dns_res.duration_ms,
            error_message=dns_res.error_message,
        )
        check_record.details = {
            "records": dns_res.records,
            "educational_notes": dns_res.educational_notes
        }
        db.add(check_record)
        checks_list.append(CheckResultSchema(
            check_type="dns",
            status=chk_status,
            duration_ms=dns_res.duration_ms,
            details=check_record.details,
            error_message=dns_res.error_message
        ))

        for f in dns_res.findings:
            finding_rec = TroubleshootingFinding(
                run_id=run.id,
                symptom=f.symptom,
                confidence=f.confidence,
                diagnostic_evidence=f.diagnostic_evidence,
                limitations=f.limitations
            )
            finding_rec.explanations = f.likely_explanations
            finding_rec.next_steps = f.next_steps
            db.add(finding_rec)
            findings_list.append(f)

    # 2. TCP Port Check
    if req.run_port:
        port_res = PortService.check_tcp_port(req.target, req.port)
        chk_status = port_res["status"]
        if chk_status == "FAILURE" and overall_status != "FAILURE":
            overall_status = "WARNING" if overall_status == "SUCCESS" else overall_status

        check_record = DiagnosticCheck(
            run_id=run.id,
            check_type="port",
            status=chk_status,
            duration_ms=port_res["duration_ms"],
            error_message=port_res.get("error_message"),
        )
        check_record.details = {
            "port": req.port,
            "resolved_ip": port_res.get("resolved_ip"),
            "error_type": port_res.get("error_type"),
            "limitations": port_res.get("limitations")
        }
        db.add(check_record)
        checks_list.append(CheckResultSchema(
            check_type="port",
            status=chk_status,
            duration_ms=port_res["duration_ms"],
            details=check_record.details,
            error_message=port_res.get("error_message")
        ))

        for f_data in port_res.get("findings", []):
            f_schema = FindingSchema(**f_data)
            finding_rec = TroubleshootingFinding(
                run_id=run.id,
                symptom=f_schema.symptom,
                confidence=f_schema.confidence,
                diagnostic_evidence=f_schema.diagnostic_evidence,
                limitations=f_schema.limitations
            )
            finding_rec.explanations = f_schema.likely_explanations
            finding_rec.next_steps = f_schema.next_steps
            db.add(finding_rec)
            findings_list.append(f_schema)

    # 3. Optional Traceroute Check
    if req.run_traceroute:
        trace_res = TracerouteService.run_traceroute(req.target)
        check_record = DiagnosticCheck(
            run_id=run.id,
            check_type="traceroute",
            status=trace_res["status"],
            duration_ms=trace_res["duration_ms"],
            error_message=trace_res.get("error_message"),
        )
        check_record.details = {
            "hops_count": len(trace_res.get("hops", [])),
            "output_preview": trace_res.get("output", "")[:1000],
            "limitations": trace_res.get("limitations")
        }
        db.add(check_record)
        checks_list.append(CheckResultSchema(
            check_type="traceroute",
            status=trace_res["status"],
            duration_ms=trace_res["duration_ms"],
            details=check_record.details,
            error_message=trace_res.get("error_message")
        ))

    total_duration_ms = (time.perf_counter() - start_time) * 1000

    # Finalize run
    run.status = overall_status
    run.duration_ms = total_duration_ms
    run.summary = f"Completed {len(checks_list)} checks with status {overall_status}."
    db.commit()

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


@router.post("/http", response_model=HttpAnalysisResponse)
def analyze_http(
    req: HttpAnalysisRequest,
    db: Session = Depends(get_db)
):
    """Analyzes HTTP/HTTPS endpoint with redirect tracking and header allowlisting."""
    response = HttpService.analyze_url(
        url=req.url,
        allow_redirects=req.allow_redirects,
        timeout_seconds=req.timeout_seconds
    )

    # Persist as DiagnosticRun
    status = "SUCCESS" if (response.status_code and response.status_code < 400) else (
        "WARNING" if (response.status_code and response.status_code < 500) else "FAILURE"
    )
    if response.tls_error or response.http_error:
        status = "FAILURE"

    run = DiagnosticRun(
        target=req.url,
        target_type="url",
        status=status,
        summary=f"HTTP Analysis: status {response.status_code or 'Failed'}",
        duration_ms=response.duration_ms,
    )
    db.add(run)
    db.flush()

    check_record = DiagnosticCheck(
        run_id=run.id,
        check_type="http",
        status=status,
        duration_ms=response.duration_ms,
        error_message=response.tls_error or response.http_error
    )
    check_record.details = {
        "status_code": response.status_code,
        "status_phrase": response.status_phrase,
        "redirect_count": response.redirect_count,
        "content_type": response.content_type,
        "content_length": response.content_length,
        "is_tls": response.is_tls
    }
    db.add(check_record)

    for f in response.findings:
        finding_rec = TroubleshootingFinding(
            run_id=run.id,
            symptom=f.symptom,
            confidence=f.confidence,
            diagnostic_evidence=f.diagnostic_evidence,
            limitations=f.limitations
        )
        finding_rec.explanations = f.likely_explanations
        finding_rec.next_steps = f.next_steps
        db.add(finding_rec)

    db.commit()
    return response


@router.post("/dns", response_model=DnsLookupResponse)
def lookup_dns(
    req: DnsLookupRequest,
    db: Session = Depends(get_db)
):
    """Dedicated DNS Lookup querying multiple record types."""
    response = DnsService.resolve_domain(req.target, req.record_types)

    run = DiagnosticRun(
        target=req.target,
        target_type="domain",
        status=response.status,
        summary=f"DNS Lookup for {req.target}",
        duration_ms=response.duration_ms
    )
    db.add(run)
    db.flush()

    check_record = DiagnosticCheck(
        run_id=run.id,
        check_type="dns",
        status=response.status,
        duration_ms=response.duration_ms,
        error_message=response.error_message
    )
    check_record.details = {
        "record_types": req.record_types,
        "records": response.records
    }
    db.add(check_record)

    for f in response.findings:
        finding_rec = TroubleshootingFinding(
            run_id=run.id,
            symptom=f.symptom,
            confidence=f.confidence,
            diagnostic_evidence=f.diagnostic_evidence,
            limitations=f.limitations
        )
        finding_rec.explanations = f.likely_explanations
        finding_rec.next_steps = f.next_steps
        db.add(finding_rec)

    db.commit()
    return response


@router.post("/tls", response_model=TlsCertificateInfo)
def inspect_tls(
    req: TlsInspectionRequest,
    db: Session = Depends(get_db)
):
    """Inspects remote TLS certificate and negotiated encryption parameters."""
    cert_info = TlsService.inspect_certificate(
        hostname=req.hostname,
        port=req.port,
        timeout_seconds=req.timeout_seconds
    )

    status = "SUCCESS" if cert_info.is_valid else "FAILURE"
    run = DiagnosticRun(
        target=f"{req.hostname}:{req.port}",
        target_type="tls",
        status=status,
        summary=f"TLS Inspection for {req.hostname} (Valid: {cert_info.is_valid})",
        duration_ms=0.0
    )
    db.add(run)
    db.flush()

    check_record = DiagnosticCheck(
        run_id=run.id,
        check_type="tls",
        status=status,
        duration_ms=0.0,
        error_message=cert_info.verification_error
    )
    check_record.details = {
        "hostname_matches": cert_info.hostname_matches,
        "days_remaining": cert_info.days_remaining,
        "tls_version": cert_info.tls_version_negotiated,
        "cipher": cert_info.cipher_suite,
        "issuer": cert_info.issuer
    }
    db.add(check_record)

    for f in cert_info.findings:
        finding_rec = TroubleshootingFinding(
            run_id=run.id,
            symptom=f.symptom,
            confidence=f.confidence,
            diagnostic_evidence=f.diagnostic_evidence,
            limitations=f.limitations
        )
        finding_rec.explanations = f.likely_explanations
        finding_rec.next_steps = f.next_steps
        db.add(finding_rec)

    db.commit()
    return cert_info
