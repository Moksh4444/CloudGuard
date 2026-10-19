"""
Unit tests for Troubleshooting Intelligence Engine.
"""
from app.intelligence.troubleshooting_engine import TroubleshootingEngine


def test_troubleshoot_dns_nxdomain():
    finding = TroubleshootingEngine.evaluate_dns_check(
        target="invalid-random-domain-xyz123.com",
        success=False,
        records={},
        duration_ms=45.0,
        error_message="NXDOMAIN: The domain does not exist."
    )
    assert finding is not None
    assert "NXDOMAIN" in finding.symptom
    assert finding.confidence == "HIGH"
    assert len(finding.likely_explanations) > 0
    assert len(finding.next_steps) > 0
    assert "spelling" in finding.next_steps[0].lower() or "whois" in finding.next_steps[1].lower()


def test_troubleshoot_port_connection_refused():
    finding = TroubleshootingEngine.evaluate_port_check(
        target="example.com",
        port=8080,
        connected=False,
        duration_ms=25.0,
        error_type="CONNECTION_REFUSED",
        error_detail="Connection refused by target operating system."
    )
    assert finding is not None
    assert "refused" in finding.symptom.lower()
    assert any("listening" in exp.lower() for exp in finding.likely_explanations)
    assert any("netstat" in step.lower() for step in finding.next_steps)


def test_troubleshoot_port_timeout():
    finding = TroubleshootingEngine.evaluate_port_check(
        target="example.com",
        port=5432,
        connected=False,
        duration_ms=5000.0,
        error_type="CONNECTION_TIMEOUT",
        error_detail="Connection timed out after 5.0s"
    )
    assert finding is not None
    assert "timed out" in finding.symptom.lower()
    assert any("firewall" in exp.lower() or "security group" in exp.lower() for exp in finding.likely_explanations)


def test_troubleshoot_http_status_codes():
    # 403 Forbidden
    f_403 = TroubleshootingEngine.evaluate_http_check(
        url="https://api.example.com/admin",
        status_code=403,
        duration_ms=120.0,
        redirect_count=0
    )
    assert f_403 is not None
    assert "403" in f_403.symptom
    assert any("waf" in exp.lower() or "credentials" in exp.lower() for exp in f_403.likely_explanations)

    # 502 Bad Gateway
    f_502 = TroubleshootingEngine.evaluate_http_check(
        url="https://api.example.com/service",
        status_code=502,
        duration_ms=500.0,
        redirect_count=0
    )
    assert f_502 is not None
    assert "502" in f_502.symptom
    assert any("upstream" in exp.lower() or "crashed" in exp.lower() for exp in f_502.likely_explanations)


def test_troubleshoot_tls_expired():
    finding = TroubleshootingEngine.evaluate_tls_check(
        hostname="expired.badssl.com",
        is_valid=False,
        error_message="certificate has expired",
        days_remaining=-10
    )
    assert finding is not None
    assert "expired" in finding.symptom.lower()
    assert any("renew" in step.lower() for step in finding.next_steps)
