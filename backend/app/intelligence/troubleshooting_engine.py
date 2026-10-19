"""
Transparent, rule-based Troubleshooting Intelligence Engine.
Analyzes diagnostic outputs and generates structured findings distinguishing
observed symptoms from potential root cause hypotheses and actionable next steps.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class TroubleshootingFindingData(BaseModel):
    symptom: str
    confidence: str  # "HIGH", "MEDIUM", "TENTATIVE"
    likely_explanations: List[str]
    diagnostic_evidence: str
    next_steps: List[str]
    limitations: str


class TroubleshootingEngine:
    """
    Evaluates diagnostic results across DNS, TCP connectivity, HTTP, and TLS layers
    to generate systematic, non-hallucinatory troubleshooting recommendations.
    """

    @staticmethod
    def evaluate_dns_check(
        target: str,
        success: bool,
        records: Dict[str, Any],
        duration_ms: float,
        error_message: Optional[str] = None
    ) -> Optional[TroubleshootingFindingData]:
        """Evaluates DNS resolution behavior."""
        if success:
            # Check if resolution resolved to unexpected addresses or multiple CDNs
            return None

        err = (error_message or "").lower()
        if "nxdomain" in err or "not found" in err:
            return TroubleshootingFindingData(
                symptom=f"DNS resolution returned NXDOMAIN (Non-Existent Domain) for '{target}'.",
                confidence="HIGH",
                likely_explanations=[
                    "The domain name is misspelled or does not exist in public authoritative DNS registries.",
                    "The domain registration expired or has been suspended by the registrar.",
                    "Authoritative nameservers have removed the record or are unassigned."
                ],
                diagnostic_evidence=f"DNS query failed after {duration_ms:.1f}ms with error: {error_message}.",
                next_steps=[
                    f"Check domain spelling for typos: '{target}'.",
                    f"Verify domain registration status using whois: 'whois {target}'.",
                    "Query authoritative nameservers directly using dig: 'dig @8.8.8.8 " + target + " A +trace'."
                ],
                limitations="Observation reflects the local resolver view. Does not verify private split-horizon DNS zones."
            )
        elif "timeout" in err or "timed out" in err:
            return TroubleshootingFindingData(
                symptom=f"DNS resolution query timed out while querying resolver for '{target}'.",
                confidence="MEDIUM",
                likely_explanations=[
                    "Configured local recursive DNS resolver is unresponsive or network UDP port 53 is blocked.",
                    "High network packet loss or egress firewall drop between this client and the DNS server.",
                    "Authoritative nameservers for the zone are overloaded or experiencing DDoS."
                ],
                diagnostic_evidence=f"Query timed out after {duration_ms:.1f}ms without receiving a DNS response packet.",
                next_steps=[
                    "Verify local DNS resolver configuration (e.g., /etc/resolv.conf or Windows IPConfig).",
                    "Test alternative public resolver: 'nslookup " + target + " 1.1.1.1' or '8.8.8.8'.",
                    "Check if UDP port 53 egress traffic is permitted across enterprise firewalls."
                ],
                limitations="Does not confirm whether the root cause is local client configuration or remote nameserver outage."
            )
        elif "ssrf" in err or "restricted" in err or "prohibited" in err:
            return TroubleshootingFindingData(
                symptom=f"Target resolution triggered CloudGuard SSRF security policy for '{target}'.",
                confidence="HIGH",
                likely_explanations=[
                    "The hostname resolved to a private RFC1918 IP, loopback, or cloud metadata address.",
                    "Target is an internal resource blocked by default to prevent Server-Side Request Forgery."
                ],
                diagnostic_evidence=f"SSRF Policy Engine intercepted target: {error_message}",
                next_steps=[
                    "Verify target is an authorized public hostname.",
                    "If testing internal staging in a secure lab, adjust ALLOW_PRIVATE_IPS setting."
                ],
                limitations="Security restriction enforced by CloudGuard policy; not a network connectivity failure."
            )
        else:
            return TroubleshootingFindingData(
                symptom=f"DNS query failed with general resolver error for '{target}'.",
                confidence="TENTATIVE",
                likely_explanations=[
                    "Local operating system resolver cache inconsistency or temporary resolver glitch.",
                    "DNSSEC validation failure at the upstream recursive resolver."
                ],
                diagnostic_evidence=f"Resolver error: {error_message}",
                next_steps=[
                    f"Flush local DNS resolver cache: 'ipconfig /flushdns' (Windows) or 'resolvectl flush-caches' (Linux).",
                    f"Test DNSSEC validation using: 'dig +dnssec {target}'."
                ],
                limitations="Single query failure does not prove permanent DNS outage; propagation or transient glitches may occur."
            )

    @staticmethod
    def evaluate_port_check(
        target: str,
        port: int,
        connected: bool,
        duration_ms: float,
        error_type: Optional[str] = None,
        error_detail: Optional[str] = None
    ) -> Optional[TroubleshootingFindingData]:
        """Evaluates TCP port level connectivity."""
        if connected:
            return None

        err_type = (error_type or "").lower()
        err_detail = (error_detail or "").lower()

        if "refused" in err_type or "refused" in err_detail or "econnrefused" in err_detail:
            return TroubleshootingFindingData(
                symptom=f"TCP connection to {target}:{port} was actively refused (TCP RST received).",
                confidence="HIGH",
                likely_explanations=[
                    f"The host is reachable at network layer, but no service process is actively listening on port {port}.",
                    f"A local host-based firewall (e.g. iptables/Windows Firewall) rejected the connection with a TCP RST packet.",
                    "The service crashed, was stopped, or is bound to a different interface (e.g., localhost 127.0.0.1 instead of 0.0.0.0)."
                ],
                diagnostic_evidence=f"TCP three-way handshake failed within {duration_ms:.1f}ms: Connection refused by target operating system.",
                next_steps=[
                    f"Verify the daemon/service process is running on the target machine: 'netstat -tulnp | grep {port}'.",
                    f"Confirm the service is bound to public/all interfaces (0.0.0.0), not exclusively loopback.",
                    "Inspect target service logs (e.g., systemctl status, journalctl -u <service>)."
                ],
                limitations="TCP RST confirms network reachability up to the host OS, but proves no socket is bound to that port."
            )
        elif "timeout" in err_type or "timeout" in err_detail or "timed out" in err_detail:
            return TroubleshootingFindingData(
                symptom=f"TCP SYN packet to {target}:{port} timed out with no response (SYN packet dropped).",
                confidence="HIGH",
                likely_explanations=[
                    "A network firewall, AWS Security Group, or cloud ACL is silently dropping inbound packets on port " + str(port) + ".",
                    "The target server is powered down, offline, or experiencing routing failure.",
                    "Egress network policy on the client side blocks outbound SYN traffic to port " + str(port) + "."
                ],
                diagnostic_evidence=f"Connection attempt exceeded timeout threshold after {duration_ms:.1f}ms without SYN-ACK or RST response.",
                next_steps=[
                    f"Check cloud security group inbound rules: ensure port {port} is permitted from client source IP.",
                    "Verify target instance network interface (ENI), routing table, and internet gateway attachments.",
                    f"Test intermediate path with traceroute / tcptraceroute to isolate which network hop drops packets."
                ],
                limitations="Cannot determine without internal telemetry whether drop occurred at AWS edge, client perimeter, or host firewall."
            )
        else:
            return TroubleshootingFindingData(
                symptom=f"Socket error attempting connection to {target}:{port}.",
                confidence="TENTATIVE",
                likely_explanations=[
                    "Network routing or intermediate gateway configuration error.",
                    f"Details: {error_detail or error_type}"
                ],
                diagnostic_evidence=f"Socket error returned: {error_type} - {error_detail}",
                next_steps=[
                    "Check local network routing table and gateway reachability.",
                    "Verify destination IP is correct."
                ],
                limitations="Generic socket failure requires reviewing local routing and proxy configuration."
            )

    @staticmethod
    def evaluate_http_check(
        url: str,
        status_code: Optional[int],
        duration_ms: float,
        redirect_count: int,
        error_message: Optional[str] = None
    ) -> Optional[TroubleshootingFindingData]:
        """Evaluates HTTP response status and behavior."""
        if error_message:
            return TroubleshootingFindingData(
                symptom=f"HTTP request to '{url}' failed at client or protocol level.",
                confidence="HIGH",
                likely_explanations=[
                    "Connection could not be established or protocol error occurred during HTTP transaction.",
                    f"Client error detail: {error_message}"
                ],
                diagnostic_evidence=f"HTTP client reported error after {duration_ms:.1f}ms: {error_message}",
                next_steps=[
                    f"Test raw HTTP request using curl with verbose output: 'curl -Iv \"{url}\"'.",
                    "Verify TLS certificate validity if using HTTPS.",
                    "Check if a web proxy requires authentication."
                ],
                limitations="Client-side HTTP failure does not provide server response headers."
            )

        if not status_code:
            return None

        if 200 <= status_code < 300:
            return None  # Normal healthy response

        if 300 <= status_code < 400:
            if redirect_count >= 5:
                return TroubleshootingFindingData(
                    symptom=f"HTTP redirection loop detected while accessing '{url}' (redirect count: {redirect_count}).",
                    confidence="HIGH",
                    likely_explanations=[
                        "Circular redirection configuration between HTTP and HTTPS or between domain variants (www vs apex).",
                        "Reverse proxy or CDN (e.g. Cloudflare Flexible SSL) misconfigured with origin expecting HTTPS."
                    ],
                    diagnostic_evidence=f"Exceeded maximum redirection hop limit of {redirect_count} hops.",
                    next_steps=[
                        f"Inspect redirect chain headers: 'curl -IL \"{url}\"'.",
                        "Verify CDN / ALB SSL termination mode matches origin server protocol."
                    ],
                    limitations="Redirection chain analysis requires examining intermediate Location headers."
                )
            return None

        if status_code in (401, 403):
            desc = "401 Unauthorized (Authentication Required)" if status_code == 401 else "403 Forbidden (Authorization Denied)"
            return TroubleshootingFindingData(
                symptom=f"HTTP {status_code} ({desc}) returned for '{url}'.",
                confidence="HIGH",
                likely_explanations=[
                    "Client request lacks valid authentication credentials (e.g., missing API token or session cookie).",
                    "WAF (Web Application Firewall) or Cloudflare/Skyhigh gateway blocked request based on IP or User-Agent.",
                    "Access control rules on origin server restrict access to authorized internal subnets."
                ],
                diagnostic_evidence=f"Server returned HTTP status code {status_code} in {duration_ms:.1f}ms.",
                next_steps=[
                    "Inspect response headers (e.g., 'WWW-Authenticate', 'Server', 'CF-Ray') to identify blocking entity.",
                    "Provide required credentials in Authorization header.",
                    "Check WAF / security gateway event logs for blocked signatures or geographic blocks."
                ],
                limitations="HTTP 403 proves server reached and actively denied access; not a network connectivity failure."
            )

        if status_code == 404:
            return TroubleshootingFindingData(
                symptom=f"HTTP 404 Not Found returned for '{url}'.",
                confidence="HIGH",
                likely_explanations=[
                    "The requested URI path or resource does not exist on the web server.",
                    "URL routing misconfiguration on reverse proxy or single-page-app server.",
                    "Resource was deleted or moved without configuring a 301/302 redirect."
                ],
                diagnostic_evidence=f"Web server responded with HTTP 404 in {duration_ms:.1f}ms.",
                next_steps=[
                    "Verify the URL path spelling and query parameters.",
                    "Check origin server routing configurations (nginx / Apache / app routes)."
                ],
                limitations="Proves network and TLS layers are completely functional; error is purely application-level."
            )

        if status_code == 429:
            return TroubleshootingFindingData(
                symptom=f"HTTP 429 Too Many Requests returned for '{url}'.",
                confidence="HIGH",
                likely_explanations=[
                    "Client has exceeded the rate limit quota configured by the API gateway or application.",
                    "Multiple clients sharing a NAT public gateway are triggering global rate limiting."
                ],
                diagnostic_evidence=f"Server returned HTTP 429 in {duration_ms:.1f}ms.",
                next_steps=[
                    "Inspect 'Retry-After' header in response to determine required backoff duration.",
                    "Implement exponential backoff and jitter in client requests."
                ],
                limitations="Indicates server is operational but rate throttled."
            )

        if status_code in (500, 502, 503, 504):
            desc_map = {
                500: "Internal Server Error (Backend Application Crash)",
                502: "Bad Gateway (Upstream Server Unreachable or Invalid Response)",
                503: "Service Unavailable (Server Overloaded or Maintenance)",
                504: "Gateway Timeout (Upstream Server Timed Out)"
            }
            desc = desc_map.get(status_code, "Server Error")
            return TroubleshootingFindingData(
                symptom=f"HTTP {status_code} ({desc}) returned for '{url}'.",
                confidence="HIGH",
                likely_explanations=[
                    "Upstream application server crashed or threw an unhandled exception.",
                    "Reverse proxy (Nginx, ALB, Cloudflare) could not reach backend app instances on private network.",
                    "Database connection pool exhaustion or high load on origin server."
                ],
                diagnostic_evidence=f"Reverse proxy or server returned HTTP {status_code} after {duration_ms:.1f}ms.",
                next_steps=[
                    "Check application backend error logs and APM telemetry.",
                    "Verify backend instance health checks in Load Balancer target groups.",
                    "Review database connection counts and system resource utilization (CPU/Memory)."
                ],
                limitations="External HTTP 5xx proves edge gateway reached; internal server telemetry needed to confirm root cause."
            )

        return None

    @staticmethod
    def evaluate_tls_check(
        hostname: str,
        is_valid: bool,
        error_message: Optional[str] = None,
        days_remaining: Optional[int] = None,
        version: Optional[str] = None
    ) -> Optional[TroubleshootingFindingData]:
        """Evaluates TLS certificate validity and configuration."""
        if not is_valid and error_message:
            err = error_message.lower()
            if "expired" in err or (days_remaining is not None and days_remaining < 0):
                return TroubleshootingFindingData(
                    symptom=f"TLS certificate for '{hostname}' is expired ({days_remaining} days remaining).",
                    confidence="HIGH",
                    likely_explanations=[
                        "Automated certificate renewal (e.g. Certbot / AWS ACM) failed or was not configured.",
                        "Certificate lifecycle management alert was missed."
                    ],
                    diagnostic_evidence=f"TLS handshake verification failed: {error_message}.",
                    next_steps=[
                        f"Renew TLS certificate immediately using Let's Encrypt Certbot or cloud certificate manager.",
                        f"Verify certificate dates via OpenSSL: 'openssl s_client -connect {hostname}:443 -servername {hostname}'."
                    ],
                    limitations="Verification evaluated against local system CA trust store."
                )
            elif "mismatch" in err or "hostname" in err:
                return TroubleshootingFindingData(
                    symptom=f"TLS certificate Subject Alternative Name (SAN) does not match requested hostname '{hostname}'.",
                    confidence="HIGH",
                    likely_explanations=[
                        "Target server is serving a default certificate (SNI routing missing or misconfigured).",
                        "Certificate was issued for a different domain or is missing the apex / wildcard entry."
                    ],
                    diagnostic_evidence=f"Hostname verification failure: {error_message}.",
                    next_steps=[
                        f"Check Subject and SAN fields on certificate using: 'openssl s_client -connect {hostname}:443'.",
                        "Configure Server Name Indication (SNI) on the web server / load balancer."
                    ],
                    limitations="Based on the specific hostname provided in request."
                )
            elif "self signed" in err or "unable to get local issuer" in err or "untrusted" in err:
                return TroubleshootingFindingData(
                    symptom=f"TLS certificate for '{hostname}' is not signed by a recognized Certificate Authority (CA).",
                    confidence="HIGH",
                    likely_explanations=[
                        "Server uses an internal, private, or self-signed certificate without public CA trust.",
                        "Intermediate CA certificate is missing from the server's certificate bundle.",
                        "Client machine lacks the enterprise root CA certificate in its trust store."
                    ],
                    diagnostic_evidence=f"Trust chain verification failure: {error_message}.",
                    next_steps=[
                        "Ensure web server sends the complete intermediate certificate bundle (fullchain.pem).",
                        "If this is an enterprise internal server, install corporate Root CA in system trust store."
                    ],
                    limitations="Verification depends on the local operating system CA bundle."
                )
            else:
                return TroubleshootingFindingData(
                    symptom=f"TLS handshake or certificate verification failed for '{hostname}'.",
                    confidence="MEDIUM",
                    likely_explanations=[
                        "Cipher suite or TLS protocol version incompatibility between client and server.",
                        f"Verification detail: {error_message}"
                    ],
                    diagnostic_evidence=f"TLS error: {error_message}",
                    next_steps=[
                        f"Inspect supported TLS versions: 'openssl s_client -connect {hostname}:443 -tls1_2'.",
                        "Check web server SSL configuration."
                    ],
                    limitations="Evaluated according to Python ssl module capabilities."
                )

        if days_remaining is not None and 0 <= days_remaining <= 14:
            return TroubleshootingFindingData(
                symptom=f"TLS certificate for '{hostname}' will expire soon ({days_remaining} days remaining).",
                confidence="HIGH",
                likely_explanations=[
                    "Automated certificate renewal process has not completed."
                ],
                diagnostic_evidence=f"Certificate valid until expiry in {days_remaining} days.",
                next_steps=[
                    "Trigger automated certificate renewal.",
                    "Verify ACME challenge records and DNS validation."
                ],
                limitations="Informational warning ahead of certificate expiration."
            )

        return None
