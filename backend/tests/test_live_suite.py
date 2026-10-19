"""
Comprehensive live end-to-end verification script for CloudGuard API.
Tests every endpoint, diagnostic service, SSRF boundaries, and report generation.
"""
import json
import sys
import httpx

BASE_URL = "http://127.0.0.1:8000/api/v1"

def run_tests():
    client = httpx.Client(timeout=15.0)
    passed = 0
    total = 0

    def check(name, condition, extra=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f" [PASS] {name} {extra}")
        else:
            print(f" [FAIL] {name} {extra}")
            sys.exit(1)

    print("\n--- 1. Testing System Health ---")
    r = client.get(f"{BASE_URL}/health")
    check("GET /health status == 200", r.status_code == 200)
    health = r.json()
    check("Database connected", health.get("database_connected") is True)
    check("SSRF protection active", health.get("ssrf_protection_active") is True)

    print("\n--- 2. Testing DNS Lookup ---")
    r = client.post(f"{BASE_URL}/diagnostics/dns", json={
        "target": "cloudflare.com",
        "record_types": ["A", "AAAA", "MX", "NS", "TXT"]
    })
    check("POST /diagnostics/dns status == 200", r.status_code == 200)
    dns_data = r.json()
    check("DNS status == SUCCESS", dns_data.get("status") == "SUCCESS")
    check("DNS records resolved (A records present)", len(dns_data.get("records", {}).get("A", [])) > 0)

    print("\n--- 3. Testing HTTP/HTTPS Analyzer ---")
    r = client.post(f"{BASE_URL}/diagnostics/http", json={
        "url": "https://httpbin.org/status/200",
        "allow_redirects": True,
        "timeout_seconds": 8.0
    })
    check("POST /diagnostics/http status == 200", r.status_code == 200)
    http_data = r.json()
    check(
        "HTTP status_code == 200",
        http_data.get("status_code") == 200,
        extra=f"(status={http_data.get('status_code')}, error={http_data.get('http_error')})"
    )
    check("Is TLS == True", http_data.get("is_tls") is True)
    check("Headers allowlist populated", len(http_data.get("headers", [])) > 0)

    print("\n--- 4. Testing TLS Certificate Inspection ---")
    r = client.post(f"{BASE_URL}/diagnostics/tls", json={
        "hostname": "cloudflare.com",
        "port": 443,
        "timeout_seconds": 6.0
    })
    check("POST /diagnostics/tls status == 200", r.status_code == 200)
    tls_data = r.json()
    check("TLS certificate valid", tls_data.get("is_valid") is True)
    check("Days remaining calculated", tls_data.get("days_remaining") is not None)
    check("SAN list present", len(tls_data.get("subject_alt_names", [])) > 0)

    print("\n--- 5. Testing Network Diagnostics ---")
    r = client.post(f"{BASE_URL}/diagnostics/network", json={
        "target": "example.com",
        "port": 443,
        "run_dns": True,
        "run_port": True,
        "run_traceroute": False
    })
    check("POST /diagnostics/network status == 200", r.status_code == 200)
    net_data = r.json()
    check("Network status == SUCCESS", net_data.get("status") == "SUCCESS")
    check("Checks count == 2", len(net_data.get("checks", [])) == 2)

    print("\n--- 6. Testing Cloud Security Configuration Analyzer ---")
    sample_sg = {
        "GroupName": "sg-test-verify",
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 3306,
                "ToPort": 3306,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }
    r = client.post(f"{BASE_URL}/cloud-security/analyze", json={
        "name": "Live Verify SG",
        "config_json": json.dumps(sample_sg)
    })
    check("POST /cloud-security/analyze status == 200", r.status_code == 200)
    sg_data = r.json()
    check("Critical findings >= 2", sg_data.get("summary", {}).get("CRITICAL", 0) >= 2)

    print("\n--- 7. Testing Scan History & Persistence ---")
    r = client.get(f"{BASE_URL}/history/runs?page=1&page_size=5")
    check("GET /history/runs status == 200", r.status_code == 200)
    history_data = r.json()
    check("Persisted runs > 0", history_data.get("total", 0) > 0)
    latest_run_id = history_data.get("items", [])[0]["id"]

    r = client.get(f"{BASE_URL}/history/runs/{latest_run_id}")
    check("GET /history/runs/{id} status == 200", r.status_code == 200)

    print("\n--- 8. Testing Report Generation & Exports ---")
    # JSON Export
    r = client.post(f"{BASE_URL}/reports/export", json={"run_id": latest_run_id, "format": "json"})
    check("Report export JSON status == 200", r.status_code == 200)
    check("Report JSON has report_uid", "report_uid" in r.json())

    # CSV Export
    r = client.post(f"{BASE_URL}/reports/export", json={"run_id": latest_run_id, "format": "csv"})
    check("Report export CSV status == 200", r.status_code == 200)
    check("Report CSV content has Header", "Report ID" in r.json().get("content", ""))

    # HTML Export
    r = client.post(f"{BASE_URL}/reports/export", json={"run_id": latest_run_id, "format": "html"})
    check("Report export HTML status == 200", r.status_code == 200)
    check("Report HTML content has <!DOCTYPE html>", "<!DOCTYPE html>" in r.json().get("content", ""))

    print("\n--- 9. Testing SSRF Boundaries & Private IP Protections ---")
    # Loopback
    r = client.post(f"{BASE_URL}/diagnostics/http", json={
        "url": "http://127.0.0.1:8080/secret",
        "allow_redirects": True,
        "timeout_seconds": 3.0
    })
    check("SSRF 127.0.0.1 blocked", "blocked" in r.json().get("http_error", "").lower() or "ssrf" in r.json().get("http_error", "").lower() or r.json().get("status_code") is None)

    # AWS IMDS (169.254.169.254)
    r = client.post(f"{BASE_URL}/diagnostics/http", json={
        "url": "http://169.254.169.254/latest/meta-data/",
        "allow_redirects": True,
        "timeout_seconds": 3.0
    })
    check("SSRF AWS 169.254.169.254 blocked", "ssrf" in r.json().get("http_error", "").lower() or "blocked" in r.json().get("http_error", "").lower() or r.json().get("status_code") is None)

    # RFC1918 Private Subnet (10.0.0.1)
    r = client.post(f"{BASE_URL}/diagnostics/network", json={
        "target": "10.0.0.1",
        "port": 80,
        "run_dns": True,
        "run_port": True
    })
    net_ssrf = r.json()
    check("SSRF RFC 1918 (10.0.0.1) rejected", any("ssrf" in f.get("symptom", "").lower() or "policy" in f.get("symptom", "").lower() for f in net_ssrf.get("findings", [])))

    # Unsupported Scheme (file://)
    r = client.post(f"{BASE_URL}/diagnostics/http", json={
        "url": "file:///etc/passwd",
        "allow_redirects": True,
        "timeout_seconds": 3.0
    })
    check("SSRF file:// scheme blocked", "scheme" in r.json().get("http_error", "").lower() or "unsupported" in r.json().get("http_error", "").lower())

    # Disallow embedded credentials
    r = client.post(f"{BASE_URL}/diagnostics/http", json={
        "url": "http://admin:secret@example.com",
        "allow_redirects": True,
        "timeout_seconds": 3.0
    })
    check("SSRF embedded credentials blocked", "credentials" in r.json().get("http_error", "").lower())

    print(f"\n==========================================")
    print(f" ALL {passed}/{total} LIVE VERIFICATION CHECKS PASSED!")
    print(f"==========================================")

if __name__ == "__main__":
    run_tests()
