"""
TLS Certificate Inspector Service for CloudGuard.
Performs read-only inspection of remote TLS certificates and protocol negotiation.
Evaluates expiration, Subject Alternative Names (SAN), and chain validity.
"""
from datetime import datetime, timezone
import socket
import ssl
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from app.security.ssrf import validate_target_host
from app.intelligence.troubleshooting_engine import TroubleshootingEngine
from app.schemas.diagnostic import TlsCertificateInfo, FindingSchema


class TlsService:
    @staticmethod
    def inspect_certificate(
        hostname: str,
        port: int = 443,
        timeout_seconds: float = 6.0
    ) -> TlsCertificateInfo:
        """
        Inspects TLS certificate presented by hostname:port using standard Python ssl library.
        """
        clean_host = hostname.strip().lower()
        if "://" in clean_host:
            clean_host = clean_host.split("://")[1].split("/")[0].split(":")[0]

        start_time = time.perf_counter()
        findings: List[FindingSchema] = []

        inspection_limitations = (
            "TLS Inspection Limitations: Verification is evaluated against the local system CA trust store. "
            "Results reflect the leaf certificate and intermediate certificates supplied by the server. "
            "Does not execute active OCSP / CRL revocation checks unless configured in the system environment."
        )

        # 1. SSRF Validation
        is_safe, ssrf_msg, resolved_ips = validate_target_host(clean_host)
        if not is_safe:
            duration_ms = (time.perf_counter() - start_time) * 1000
            finding = TroubleshootingEngine.evaluate_tls_check(
                hostname=clean_host,
                is_valid=False,
                error_message=f"SSRF Policy Violation: {ssrf_msg}"
            )
            if finding:
                findings.append(FindingSchema(**finding.model_dump()))

            return TlsCertificateInfo(
                is_valid=False,
                verification_error=f"SSRF Protection: {ssrf_msg}",
                inspection_limitations=inspection_limitations,
                findings=findings
            )

        # 2. Connect with SSL Context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        is_valid = False
        verification_error: Optional[str] = None
        cert_dict: Dict[str, Any] = {}
        tls_version: Optional[str] = None
        cipher: Optional[str] = None

        try:
            with socket.create_connection((clean_host, port), timeout=timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    cert_dict = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher_info = ssock.cipher()
                    cipher = f"{cipher_info[0]} ({cipher_info[1]})" if cipher_info else None
                    is_valid = True

        except ssl.SSLCertVerificationError as e:
            verification_error = f"Certificate Verification Error: {e.verify_message} (code: {e.verify_code})"
            # Retrieve unverified certificate to still extract inspection metadata
            try:
                unverified_ctx = ssl._create_unverified_context()
                with socket.create_connection((clean_host, port), timeout=timeout_seconds) as sock:
                    with unverified_ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                        cert_dict = ssock.getpeercert(binary_form=False) or {}
                        tls_version = ssock.version()
                        cipher_info = ssock.cipher()
                        cipher = f"{cipher_info[0]} ({cipher_info[1]})" if cipher_info else None
            except Exception:
                pass
        except socket.timeout:
            verification_error = f"Connection to {clean_host}:{port} timed out after {timeout_seconds}s."
        except ConnectionRefusedError:
            verification_error = f"TCP connection refused on {clean_host}:{port}."
        except Exception as e:
            verification_error = f"TLS handshake error: {str(e)}"

        # 3. Parse certificate fields
        subject: Dict[str, str] = {}
        issuer: Dict[str, str] = {}
        san_list: List[str] = []
        valid_from: Optional[datetime] = None
        valid_until: Optional[datetime] = None
        days_remaining: Optional[int] = None
        is_expired = False
        hostname_matches = False

        if cert_dict:
            # Parse Subject
            for item in cert_dict.get("subject", ()):
                for key, val in item:
                    subject[key] = val

            # Parse Issuer
            for item in cert_dict.get("issuer", ()):
                for key, val in item:
                    issuer[key] = val

            # Parse SAN
            for item in cert_dict.get("subjectAltName", ()):
                if len(item) == 2 and item[0] == "DNS":
                    san_list.append(item[1])

            # Parse Dates: format is e.g. 'Oct 18 12:00:00 2026 GMT'
            date_fmt = "%b %d %H:%M:%S %Y %Z"
            if "notBefore" in cert_dict:
                try:
                    valid_from = datetime.strptime(cert_dict["notBefore"], date_fmt).replace(tzinfo=timezone.utc)
                except Exception:
                    pass

            if "notAfter" in cert_dict:
                try:
                    valid_until = datetime.strptime(cert_dict["notAfter"], date_fmt).replace(tzinfo=timezone.utc)
                    now_utc = datetime.now(timezone.utc)
                    delta = valid_until - now_utc
                    days_remaining = delta.days
                    is_expired = days_remaining < 0
                except Exception:
                    pass

            # Check hostname match against SAN or CN
            common_name = subject.get("commonName", "")
            match_candidates = [common_name] + san_list
            for cand in match_candidates:
                if cand == clean_host:
                    hostname_matches = True
                    break
                elif cand.startswith("*.") and clean_host.endswith(cand[1:]):
                    hostname_matches = True
                    break

            serial = cert_dict.get("serialNumber")
        else:
            serial = None

        # 4. Generate troubleshooting findings
        finding = TroubleshootingEngine.evaluate_tls_check(
            hostname=clean_host,
            is_valid=is_valid,
            error_message=verification_error,
            days_remaining=days_remaining,
            version=tls_version
        )
        if finding:
            findings.append(FindingSchema(**finding.model_dump()))

        return TlsCertificateInfo(
            subject=subject,
            issuer=issuer,
            valid_from=valid_from,
            valid_until=valid_until,
            days_remaining=days_remaining,
            is_expired=is_expired,
            hostname_matches=hostname_matches,
            subject_alt_names=san_list,
            serial_number=serial,
            tls_version_negotiated=tls_version,
            cipher_suite=cipher,
            is_valid=is_valid,
            verification_error=verification_error,
            inspection_limitations=inspection_limitations,
            findings=findings
        )
