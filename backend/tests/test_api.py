"""
Integration tests for FastAPI endpoints.
"""
import json


def test_health_endpoint(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("HEALTHY", "DEGRADED")
    assert data["database_connected"] is True
    assert "version" in data


def test_seed_demo_data_and_analytics(client):
    # Seed demo data
    res = client.post("/api/v1/history/seed-demo")
    assert res.status_code == 200
    assert res.json()["status"] == "SUCCESS"

    # List runs
    runs_res = client.get("/api/v1/history/runs?page=1&page_size=10")
    assert runs_res.status_code == 200
    data = runs_res.json()
    assert data["total"] >= 6
    assert len(data["items"]) >= 6

    # Verify single run retrieval
    first_run_id = data["items"][0]["id"]
    single_res = client.get(f"/api/v1/history/runs/{first_run_id}")
    assert single_res.status_code == 200
    single_data = single_res.json()
    assert single_data["id"] == first_run_id
    assert "checks" in single_data

    # Check analytics endpoint
    analytics_res = client.get("/api/v1/analytics/overview")
    assert analytics_res.status_code == 200
    analytics_data = analytics_res.json()
    assert analytics_data["total_runs"] >= 6
    assert analytics_data["avg_response_time_ms"] > 0
    assert "CRITICAL" in analytics_data["cloud_severity_distribution"]

    # Export report in JSON format
    report_json_res = client.post("/api/v1/reports/export", json={"run_id": first_run_id, "format": "json"})
    assert report_json_res.status_code == 200
    report_json = report_json_res.json()
    assert "report_uid" in report_json
    assert report_json["format"] == "json"

    # Export report in CSV format
    report_csv_res = client.post("/api/v1/reports/export", json={"run_id": first_run_id, "format": "csv"})
    assert report_csv_res.status_code == 200
    assert "Report ID" in report_csv_res.json()["content"]

    # Export report in HTML format
    report_html_res = client.post("/api/v1/reports/export", json={"run_id": first_run_id, "format": "html"})
    assert report_html_res.status_code == 200
    assert "<!DOCTYPE html>" in report_html_res.json()["content"]


def test_cloud_security_analyze_endpoint(client):
    payload = {
        "name": "API Test SG",
        "config_json": json.dumps({
            "GroupName": "sg-test-api",
            "IpPermissions": [
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        })
    }
    res = client.post("/api/v1/cloud-security/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["group_name"] == "sg-test-api"
    assert data["summary"]["CRITICAL"] >= 1
    assert len(data["findings"]) >= 1


def test_ssrf_blocked_on_diagnostics(client):
    # Try running network diagnostic against 127.0.0.1
    res = client.post("/api/v1/diagnostics/network", json={"target": "127.0.0.1", "port": 80})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("FAILURE", "WARNING")
    # Finding must capture SSRF policy
    assert any("ssrf" in f["symptom"].lower() or "policy" in f["symptom"].lower() for f in data["findings"])
