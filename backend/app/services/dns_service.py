"""
DNS Resolution Service for CloudGuard.
Queries standard DNS record types (A, AAAA, CNAME, MX, NS, TXT) with latency tracking,
robust error classification, and integration with the Troubleshooting Engine.
"""
import time
from typing import Dict, List, Any
import socket

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from app.security.ssrf import validate_target_host
from app.intelligence.troubleshooting_engine import TroubleshootingEngine
from app.schemas.diagnostic import DnsLookupResponse, FindingSchema


class DnsService:
    @staticmethod
    def resolve_domain(target: str, record_types: List[str] = None) -> DnsLookupResponse:
        """
        Executes DNS lookup for the given target domain across requested record types.
        """
        if record_types is None:
            record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

        clean_target = target.strip().lower()
        # Remove any protocol prefix if accidentally included
        if "://" in clean_target:
            clean_target = clean_target.split("://")[1].split("/")[0].split(":")[0]

        start_time = time.perf_counter()
        records: Dict[str, List[str]] = {rtype: [] for rtype in record_types}
        educational_notes: List[str] = [
            "Operating System DNS Resolution: Queries are resolved via the locally configured recursive DNS resolver.",
            "Authoritative vs Recursive: This check inspects recursive cached/resolved data; it does not directly query the root nameservers."
        ]
        findings = []
        error_msg = None

        # 1. SSRF Validation
        is_safe, ssrf_msg, resolved_ips = validate_target_host(clean_target)
        if not is_safe:
            duration_ms = (time.perf_counter() - start_time) * 1000
            finding = TroubleshootingEngine.evaluate_dns_check(
                target=clean_target,
                success=False,
                records={},
                duration_ms=duration_ms,
                error_message=ssrf_msg
            )
            if finding:
                findings.append(FindingSchema(**finding.model_dump()))

            return DnsLookupResponse(
                target=clean_target,
                duration_ms=duration_ms,
                status="FAILURE",
                records=records,
                error_message=ssrf_msg,
                educational_notes=educational_notes,
                findings=findings
            )

        # 2. Query using dnspython if available, else socket fallback
        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 4.0
            resolver.lifetime = 5.0

            overall_success = False
            for rtype in record_types:
                try:
                    answers = resolver.resolve(clean_target, rtype)
                    for rdata in answers:
                        records[rtype].append(str(rdata))
                    overall_success = True
                except dns.resolver.NXDOMAIN:
                    error_msg = f"NXDOMAIN: The domain '{clean_target}' does not exist."
                    break
                except dns.resolver.NoAnswer:
                    # Specific record type does not exist, but domain does
                    pass
                except dns.resolver.Timeout:
                    error_msg = f"DNS query timed out for record type {rtype}."
                    break
                except Exception as e:
                    # Other resolution errors
                    if not error_msg:
                        error_msg = str(e)

            duration_ms = (time.perf_counter() - start_time) * 1000
            status = "SUCCESS" if (overall_success or any(records.values())) else "FAILURE"

        else:
            # Fallback using standard socket library
            overall_success = False
            try:
                addr_info = socket.getaddrinfo(clean_target, None, proto=socket.IPPROTO_TCP)
                for item in addr_info:
                    family, _, _, _, sockaddr = item
                    ip = sockaddr[0]
                    if family == socket.AF_INET and "A" in records and ip not in records["A"]:
                        records["A"].append(ip)
                        overall_success = True
                    elif family == socket.AF_INET6 and "AAAA" in records and ip not in records["AAAA"]:
                        records["AAAA"].append(ip)
                        overall_success = True
            except socket.gaierror as e:
                error_msg = f"Socket getaddrinfo error: {e.strerror}"

            duration_ms = (time.perf_counter() - start_time) * 1000
            status = "SUCCESS" if overall_success else "FAILURE"

        # 3. Generate Troubleshooting findings if failed
        finding = TroubleshootingEngine.evaluate_dns_check(
            target=clean_target,
            success=(status == "SUCCESS"),
            records=records,
            duration_ms=duration_ms,
            error_message=error_msg
        )
        if finding:
            findings.append(FindingSchema(**finding.model_dump()))

        return DnsLookupResponse(
            target=clean_target,
            duration_ms=duration_ms,
            status=status,
            records=records,
            error_message=error_msg,
            educational_notes=educational_notes,
            findings=findings
        )
