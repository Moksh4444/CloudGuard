"""
Unit tests for SSRF Protection and IP/Hostname Validation.
"""
from app.security.ssrf import is_ip_prohibited, validate_target_host, validate_target_url


def test_prohibited_ipv4_addresses():
    # Loopback
    prohibited, reason = is_ip_prohibited("127.0.0.1")
    assert prohibited is True
    assert "loopback" in reason.lower()

    # RFC 1918 Private
    assert is_ip_prohibited("10.0.0.1")[0] is True
    assert is_ip_prohibited("172.16.5.10")[0] is True
    assert is_ip_prohibited("192.168.1.1")[0] is True

    # AWS Metadata / Link-Local
    prohibited, reason = is_ip_prohibited("169.254.169.254")
    assert prohibited is True
    assert "169.254" in reason or "link-local" in reason.lower()

    # Carrier Grade NAT
    assert is_ip_prohibited("100.64.0.1")[0] is True

    # Broadcast / Zero network
    assert is_ip_prohibited("0.0.0.0")[0] is True
    assert is_ip_prohibited("255.255.255.255")[0] is True


def test_prohibited_ipv6_addresses():
    # IPv6 Loopback
    assert is_ip_prohibited("::1")[0] is True

    # IPv6 Link-Local
    assert is_ip_prohibited("fe80::1")[0] is True

    # IPv6 ULA (Unique Local)
    assert is_ip_prohibited("fc00::1")[0] is True


def test_allowed_public_ips():
    # Public DNS IPs (Cloudflare 1.1.1.1, Google 8.8.8.8)
    assert is_ip_prohibited("1.1.1.1")[0] is False
    assert is_ip_prohibited("8.8.8.8")[0] is False
    assert is_ip_prohibited("93.184.216.34")[0] is False


def test_validate_target_host_blocking():
    # Localhost
    safe, msg, _ = validate_target_host("localhost")
    assert safe is False
    assert "loopback" in msg.lower() or "ssrf" in msg.lower()

    # Invalid syntax
    safe, msg, _ = validate_target_host("not a valid hostname!@#")
    assert safe is False


def test_validate_target_url():
    # Disallow file:// and ftp://
    safe, msg, _, _ = validate_target_url("file:///etc/passwd")
    assert safe is False
    assert "unsupported scheme" in msg.lower()

    safe, msg, _, _ = validate_target_url("ftp://example.com/file")
    assert safe is False

    # Disallow embedded credentials
    safe, msg, _, _ = validate_target_url("http://admin:secret@example.com")
    assert safe is False
    assert "credentials" in msg.lower()

    # Disallow URL targeting metadata IP
    safe, msg, _, _ = validate_target_url("http://169.254.169.254/latest/meta-data/")
    assert safe is False
