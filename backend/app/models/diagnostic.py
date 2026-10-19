"""
SQLAlchemy models for CloudGuard diagnostics, findings, cloud configurations, and reports.
"""
from datetime import datetime, timezone
import json
import uuid
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class DiagnosticRun(Base):
    __tablename__ = "diagnostic_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String(255), nullable=False, index=True)
    target_type = Column(String(50), nullable=False)  # "domain", "url", "ip"
    status = Column(String(20), nullable=False, index=True)  # "SUCCESS", "WARNING", "FAILURE", "ERROR"
    summary = Column(Text, nullable=True)
    duration_ms = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)

    checks = relationship("DiagnosticCheck", back_populates="run", cascade="all, delete-orphan")
    findings = relationship("TroubleshootingFinding", back_populates="run", cascade="all, delete-orphan")


class DiagnosticCheck(Base):
    __tablename__ = "diagnostic_checks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(String(36), ForeignKey("diagnostic_runs.id"), nullable=False, index=True)
    check_type = Column(String(50), nullable=False, index=True)  # "dns", "port", "traceroute", "http", "tls"
    status = Column(String(20), nullable=False)  # "SUCCESS", "WARNING", "FAILURE"
    duration_ms = Column(Float, default=0.0)
    details_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    run = relationship("DiagnosticRun", back_populates="checks")

    @property
    def details(self):
        if self.details_json:
            try:
                return json.loads(self.details_json)
            except Exception:
                return {}
        return {}

    @details.setter
    def details(self, value):
        self.details_json = json.dumps(value) if value is not None else None


class TroubleshootingFinding(Base):
    __tablename__ = "troubleshooting_findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(String(36), ForeignKey("diagnostic_runs.id"), nullable=False, index=True)
    symptom = Column(String(255), nullable=False)
    confidence = Column(String(20), nullable=False, default="MEDIUM")  # "HIGH", "MEDIUM", "TENTATIVE"
    explanations_json = Column(Text, nullable=False)  # List[str]
    diagnostic_evidence = Column(Text, nullable=False)
    next_steps_json = Column(Text, nullable=False)  # List[str]
    limitations = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    run = relationship("DiagnosticRun", back_populates="findings")

    @property
    def explanations(self):
        try:
            return json.loads(self.explanations_json) if self.explanations_json else []
        except Exception:
            return []

    @explanations.setter
    def explanations(self, value):
        self.explanations_json = json.dumps(value) if value else "[]"

    @property
    def next_steps(self):
        try:
            return json.loads(self.next_steps_json) if self.next_steps_json else []
        except Exception:
            return []

    @next_steps.setter
    def next_steps(self, value):
        self.next_steps_json = json.dumps(value) if value else "[]"


class CloudConfigurationAnalysis(Base):
    __tablename__ = "cloud_configuration_analyses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    raw_config_json = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)

    findings = relationship("SecurityFinding", back_populates="analysis", cascade="all, delete-orphan")


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String(36), ForeignKey("cloud_configuration_analyses.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
    rule_id = Column(String(100), nullable=True)
    port_range = Column(String(100), nullable=True)
    protocol = Column(String(50), nullable=True)
    cidr = Column(String(100), nullable=True)
    evidence = Column(Text, nullable=False)
    risk_explanation = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    confidence = Column(String(20), default="HIGH")
    created_at = Column(DateTime(timezone=True), default=utc_now)

    analysis = relationship("CloudConfigurationAnalysis", back_populates="findings")


class ReportMetadata(Base):
    __tablename__ = "report_metadata"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_uid = Column(String(50), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    target = Column(String(255), nullable=False)
    scope = Column(String(100), nullable=False)  # "NETWORK", "HTTP", "DNS", "TLS", "CLOUD_SECURITY", "COMPREHENSIVE"
    format = Column(String(20), nullable=False)  # "JSON", "CSV", "HTML"
    generated_at = Column(DateTime(timezone=True), default=utc_now, index=True)
    run_id = Column(String(36), nullable=True)
    analysis_id = Column(String(36), nullable=True)
