"""
Pydantic schemas for request validation and response serialization.
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


# --- Request Schemas ---

class NetworkDiagnosticRequest(BaseModel):
    target: str = Field(..., max_length=255, description="Domain name or public IP address")
    port: int = Field(default=443, ge=1, le=65535, description="Target TCP port")
    run_dns: bool = Field(default=True, description="Execute DNS resolution check")
    run_port: bool = Field(default=True, description="Execute TCP port connectivity check")
    run_traceroute: bool = Field(default=False, description="Execute optional bounded traceroute")


class HttpAnalysisRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="Target HTTP or HTTPS URL")
    allow_redirects: bool = Field(default=True, description="Follow redirects up to limit")
    timeout_seconds: float = Field(default=6.0, ge=1.0, le=30.0, description="Request timeout in seconds")


class DnsLookupRequest(BaseModel):
    target: str = Field(..., max_length=255, description="Domain name for DNS lookup")
    record_types: List[str] = Field(
        default=["A", "AAAA", "CNAME", "MX", "NS", "TXT"],
        description="DNS record types to query"
    )


class TlsInspectionRequest(BaseModel):
    hostname: str = Field(..., max_length=255, description="Hostname for TLS inspection")
    port: int = Field(default=443, ge=1, le=65535, description="Target port for TLS handshake")
    timeout_seconds: float = Field(default=6.0, ge=1.0, le=30.0, description="Handshake timeout in seconds")


class CloudConfigRequest(BaseModel):
    name: str = Field(default="Custom Security Group Analysis", max_length=255)
    config_json: str = Field(..., description="Raw AWS Security Group JSON string")


# --- Diagnostic Finding & Check Schemas ---

class FindingSchema(BaseModel):
    symptom: str
    confidence: str
    likely_explanations: List[str]
    diagnostic_evidence: str
    next_steps: List[str]
    limitations: Optional[str] = None


class CheckResultSchema(BaseModel):
    check_type: str
    status: str  # SUCCESS, WARNING, FAILURE
    duration_ms: float
    details: Dict[str, Any]
    error_message: Optional[str] = None


class DiagnosticRunResponse(BaseModel):
    id: str
    target: str
    target_type: str
    status: str
    summary: Optional[str]
    duration_ms: float
    created_at: datetime
    checks: List[CheckResultSchema] = Field(default_factory=list)
    findings: List[FindingSchema] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


# --- Specialized Module Responses ---

class DnsRecordItem(BaseModel):
    record_type: str
    value: str
    ttl: Optional[int] = None


class DnsLookupResponse(BaseModel):
    target: str
    duration_ms: float
    status: str
    records: Dict[str, List[str]]
    error_message: Optional[str] = None
    educational_notes: List[str]
    findings: List[FindingSchema] = Field(default_factory=list)


class HttpHeaderItem(BaseModel):
    name: str
    value: str


class HttpRedirectHop(BaseModel):
    status_code: int
    url: str
    location: Optional[str] = None


class HttpAnalysisResponse(BaseModel):
    initial_url: str
    final_url: str
    status_code: Optional[int] = None
    status_phrase: Optional[str] = None
    duration_ms: float
    redirect_count: int
    redirect_hops: List[HttpRedirectHop] = Field(default_factory=list)
    headers: List[HttpHeaderItem] = Field(default_factory=list)
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    is_tls: bool = False
    tls_error: Optional[str] = None
    http_error: Optional[str] = None
    findings: List[FindingSchema] = Field(default_factory=list)


class TlsCertificateInfo(BaseModel):
    subject: Dict[str, str] = Field(default_factory=dict)
    issuer: Dict[str, str] = Field(default_factory=dict)
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    days_remaining: Optional[int] = None
    is_expired: bool = False
    hostname_matches: bool = False
    subject_alt_names: List[str] = Field(default_factory=list)
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    tls_version_negotiated: Optional[str] = None
    cipher_suite: Optional[str] = None
    is_valid: bool = False
    verification_error: Optional[str] = None
    inspection_limitations: str
    findings: List[FindingSchema] = Field(default_factory=list)


class SecurityFindingSchema(BaseModel):
    title: str
    severity: str
    rule_id: Optional[str] = None
    port_range: Optional[str] = None
    protocol: Optional[str] = None
    cidr: Optional[str] = None
    evidence: str
    risk_explanation: str
    remediation: str
    confidence: str = "HIGH"


class CloudAnalysisResponse(BaseModel):
    id: str
    name: str
    group_name: str
    group_id: Optional[str] = None
    description: Optional[str] = None
    vpc_id: Optional[str] = None
    total_rules_evaluated: int
    summary: Dict[str, int]
    findings: List[SecurityFindingSchema]
    educational_note: str
    created_at: datetime


class AnalyticsOverviewResponse(BaseModel):
    total_runs: int
    successful_runs: int
    failed_runs: int
    warning_runs: int
    avg_response_time_ms: float
    median_response_time_ms: float
    p95_response_time_ms: float
    dns_failure_count: int
    http_status_distribution: Dict[str, int]
    failure_by_module: Dict[str, int]
    most_frequent_issues: List[Dict[str, Any]]
    runs_over_time: List[Dict[str, Any]]
    cloud_severity_distribution: Dict[str, int]
