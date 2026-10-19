"""
Unit tests for AWS Cloud Security Group Least-Privilege Analyzer.
"""
import json
import pytest
from app.security.aws_sg_analyzer import analyze_security_group_json


def test_analyze_vulnerable_sg():
    vulnerable_config = {
        "GroupName": "sg-test-vulnerable",
        "GroupId": "sg-12345",
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
            },
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ],
        "IpPermissionsEgress": []
    }

    result = analyze_security_group_json(vulnerable_config)

    assert result.group_name == "sg-test-vulnerable"
    assert result.summary["CRITICAL"] >= 3

    # Check for specific finding titles
    titles = [f.title for f in result.findings]
    assert any("SSH" in t for t in titles)
    assert any("Database" in t or "MySQL" in t for t in titles)
    assert any("ALL Traffic" in t for t in titles)


def test_analyze_hardened_sg():
    hardened_config = {
        "GroupName": "sg-hardened-cluster",
        "GroupId": "sg-67890",
        "IpPermissions": [
            {
                "FromPort": 5432,
                "ToPort": 5432,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "10.0.1.0/24",
                        "Description": "Allowed from internal microservice subnet"
                    }
                ]
            }
        ],
        "IpPermissionsEgress": []
    }

    result = analyze_security_group_json(hardened_config)

    assert result.summary["CRITICAL"] == 0
    assert result.summary["HIGH"] == 0
    assert len(result.findings) == 0  # Compliant rule with description


def test_invalid_json():
    with pytest.raises(ValueError) as exc:
        analyze_security_group_json("{invalid_json: true,}")
    assert "Invalid JSON format" in str(exc.value)
