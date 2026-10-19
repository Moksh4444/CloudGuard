"""
SSRF (Server-Side Request Forgery) protection and target validation.
Validates hostnames, IP addresses, and URLs to ensure requests cannot target
loopback, RFC1918 private subnets, link-local / cloud metadata (169.254.169.254),
multicast, or reserved address spaces.
"""
import ipaddress
import re
import socket
from typing import List, Tuple, Optional
from urllib.parse import urlparse

# IPv4 prohibited network ranges with descriptive classifications
PROHIBITED_IPV4_NETWORKS = [
    (ipaddress.ip_network("0.0.0.0/8"), "Current network (RFC 1122)"),
    (ipaddress.ip_network("10.0.0.0/8"), "RFC 1918 Private subnet"),
    (ipaddress.ip_network("100.64.0.0/10"), "Shared Address Space / CGNAT"),
    (ipaddress.ip_network("127.0.0.0/8"), "Loopback network (RFC 1122)"),
    (ipaddress.ip_network("169.254.0.0/16"), "Link-Local / Cloud Metadata (169.254.169.254)"),
    (ipaddress.ip_network("172.16.0.0/12"), "RFC 1918 Private subnet"),
    (ipaddress.ip_network("192.0.0.0/24"), "IETF Protocol Assignments"),
    (ipaddress.ip_network("192.0.2.0/24"), "TEST-NET-1 documentation block"),
    (ipaddress.ip_network("192.88.99.0/24"), "6to4 Relay Anycast"),
    (ipaddress.ip_network("192.168.0.0/16"), "RFC 1918 Private subnet"),
    (ipaddress.ip_network("198.18.0.0/15"), "Benchmarking network"),
    (ipaddress.ip_network("198.51.100.0/24"), "TEST-NET-2 documentation block"),
    (ipaddress.ip_network("203.0.113.0/24"), "TEST-NET-3 documentation block"),
    (ipaddress.ip_network("224.0.0.0/4"), "Multicast address space"),
    (ipaddress.ip_network("240.0.0.0/4"), "Reserved / Future use"),
    (ipaddress.ip_network("255.255.255.255/32"), "Limited Broadcast"),
]

# IPv6 prohibited network ranges with descriptive classifications
PROHIBITED_IPV6_NETWORKS = [
    (ipaddress.ip_network("::1/128"), "IPv6 Loopback"),
    (ipaddress.ip_network("::/128"), "IPv6 Unspecified"),
    (ipaddress.ip_network("::ffff:0:0/96"), "IPv4-mapped IPv6"),
    (ipaddress.ip_network("100::/64"), "Discard prefix"),
    (ipaddress.ip_network("2001:db8::/32"), "IPv6 Documentation block"),
    (ipaddress.ip_network("fc00::/7"), "Unique Local Address (ULA)"),
    (ipaddress.ip_network("fe80::/10"), "Link-Local Unicast"),
    (ipaddress.ip_network("ff00::/8"), "IPv6 Multicast"),
]

# Hostname RFC 1123 regex
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def is_ip_prohibited(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if a given IP address string falls into any prohibited (private/internal/reserved) range.
    Returns (is_prohibited, reason).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    if ip_obj.version == 4:
        for net, desc in PROHIBITED_IPV4_NETWORKS:
            if ip_obj in net:
                return True, f"IPv4 address {ip_str} belongs to restricted network {net} ({desc})"
    elif ip_obj.version == 6:
        for net, desc in PROHIBITED_IPV6_NETWORKS:
            if ip_obj in net:
                return True, f"IPv6 address {ip_str} belongs to restricted network {net} ({desc})"

    if ip_obj.is_private:
        return True, f"IP address {ip_str} is flagged as private"
    if ip_obj.is_loopback:
        return True, f"IP address {ip_str} is flagged as loopback"
    if ip_obj.is_link_local:
        return True, f"IP address {ip_str} is flagged as link-local (cloud metadata risk)"
    if ip_obj.is_multicast:
        return True, f"IP address {ip_str} is flagged as multicast"
    if ip_obj.is_reserved:
        return True, f"IP address {ip_str} is flagged as reserved"

    return False, None


def validate_target_host(hostname_or_ip: str, allow_private: bool = False) -> Tuple[bool, str, List[str]]:
    """
    Validates a target hostname or IP address.
    Resolves DNS if hostname and checks every resolved address against prohibited ranges.
    Returns: (is_safe, error_or_info_message, resolved_ips)
    """
    target = hostname_or_ip.strip().lower()
    if not target:
        return False, "Target hostname or IP address cannot be empty.", []

    if len(target) > 255:
        return False, "Target length exceeds maximum limit of 255 characters.", []

    # Check if target is a direct IP
    try:
        ipaddress.ip_address(target)
        is_direct_ip = True
    except ValueError:
        is_direct_ip = False

    if is_direct_ip:
        if not allow_private:
            prohibited, reason = is_ip_prohibited(target)
            if prohibited:
                return False, f"Target IP rejected: {reason}", [target]
        return True, "Valid public IP target", [target]

    # Validate hostname syntax
    # Allow single label 'localhost' to fail cleanly or check regex
    if target == "localhost":
        if not allow_private:
            return False, "Target 'localhost' is a loopback address and blocked by SSRF policy.", ["127.0.0.1"]
        return True, "Localhost allowed by configuration", ["127.0.0.1"]

    if not HOSTNAME_REGEX.match(target):
        return False, f"Invalid hostname format: '{target}'. Must conform to RFC 1123.", []

    # Resolve hostname to all IP addresses
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
        for item in addr_info:
            sockaddr = item[4]
            ip = sockaddr[0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
    except socket.gaierror as e:
        return False, f"DNS resolution failed for hostname '{target}': {e.strerror}", []
    except Exception as e:
        return False, f"Unexpected error resolving hostname '{target}': {str(e)}", []

    if not resolved_ips:
        return False, f"No IP addresses resolved for hostname '{target}'.", []

    # Check each resolved IP address against SSRF rules
    if not allow_private:
        for ip in resolved_ips:
            prohibited, reason = is_ip_prohibited(ip)
            if prohibited:
                return (
                    False,
                    f"SSRF Protection: Hostname '{target}' resolved to prohibited address ({ip}). {reason}",
                    resolved_ips,
                )

    return True, "Target passed SSRF validation", resolved_ips


def validate_target_url(url_str: str, allow_private: bool = False) -> Tuple[bool, str, Optional[str], Optional[int]]:
    """
    Validates a full URL for HTTP/HTTPS analysis.
    Verifies scheme, credentials absence, port, and resolved IP against SSRF policy.
    Returns: (is_safe, message, hostname, port)
    """
    if not url_str or not url_str.strip():
        return False, "URL cannot be empty.", None, None

    url_str = url_str.strip()
    if len(url_str) > 2048:
        return False, "URL length exceeds maximum limit of 2048 characters.", None, None

    try:
        parsed = urlparse(url_str)
    except Exception as e:
        return False, f"URL parsing error: {str(e)}", None, None

    # Scheme validation
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'. Only http:// and https:// are permitted.", None, None

    # Disallow embedded credentials (e.g. http://admin:pass@example.com)
    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials (user:password) are not permitted.", None, None

    # Extract hostname and port
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname.", None, None

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80

    if port < 1 or port > 65535:
        return False, f"Port {port} is out of valid range (1-65535).", None, None

    # Validate target host for SSRF
    is_safe, message, _ = validate_target_host(hostname, allow_private=allow_private)
    if not is_safe:
        return False, message, hostname, port

    return True, "URL is safe for analysis", hostname, port
