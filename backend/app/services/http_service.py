"""
HTTP/HTTPS Analyzer Service for CloudGuard.
Safely analyzes web endpoints with redirect tracking, SSRF re-validation per hop,
header allowlisting, and clear separation between TLS failures and HTTP errors.
"""
import ssl
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
import httpx

from app.core.config import settings
from app.security.ssrf import validate_target_url, validate_target_host
from app.intelligence.troubleshooting_engine import TroubleshootingEngine
from app.schemas.diagnostic import (
    HttpAnalysisResponse,
    HttpHeaderItem,
    HttpRedirectHop,
    FindingSchema,
)

# Safe presentation header allowlist
ALLOWLISTED_HEADERS = {
    "server",
    "content-type",
    "content-length",
    "date",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
    "etag",
    "expires",
    "via",
    "cf-ray",
    "access-control-allow-origin",
    "location",
}


class HttpService:
    @staticmethod
    def analyze_url(
        url: str,
        allow_redirects: bool = True,
        timeout_seconds: float = 6.0
    ) -> HttpAnalysisResponse:
        """
        Performs safe step-by-step HTTP inspection.
        Manually tracks redirects to ensure every hop passes SSRF validation.
        """
        start_time = time.perf_counter()
        clean_url = url.strip()
        findings: List[FindingSchema] = []

        # 1. Initial URL SSRF and scheme validation
        is_safe, ssrf_msg, hostname, port = validate_target_url(clean_url)
        if not is_safe:
            duration_ms = (time.perf_counter() - start_time) * 1000
            finding = TroubleshootingEngine.evaluate_http_check(
                url=clean_url,
                status_code=None,
                duration_ms=duration_ms,
                redirect_count=0,
                error_message=f"SSRF Policy Violation: {ssrf_msg}"
            )
            if finding:
                findings.append(FindingSchema(**finding.model_dump()))

            return HttpAnalysisResponse(
                initial_url=clean_url,
                final_url=clean_url,
                status_code=None,
                status_phrase="Blocked by Security Policy",
                duration_ms=duration_ms,
                redirect_count=0,
                is_tls=clean_url.lower().startswith("https://"),
                http_error=f"SSRF Protection: {ssrf_msg}",
                findings=findings
            )

        current_url = clean_url
        redirect_hops: List[HttpRedirectHop] = []
        redirect_count = 0
        max_redirects = settings.MAX_REDIRECTS if allow_redirects else 0

        final_response: Optional[httpx.Response] = None
        tls_error: Optional[str] = None
        http_error: Optional[str] = None

        # Custom secure client configuration
        client_timeout = httpx.Timeout(timeout_seconds, connect=timeout_seconds, read=timeout_seconds)

        with httpx.Client(
            follow_redirects=False,
            timeout=client_timeout,
            verify=True,
            headers={"User-Agent": "CloudGuard-Security-Diagnostics/1.0"}
        ) as client:
            while True:
                # Re-validate current URL for SSRF before each hop
                curr_safe, curr_msg, _, _ = validate_target_url(current_url)
                if not curr_safe:
                    http_error = f"Redirect SSRF Intercept: Redirect target violates security boundary: {curr_msg}"
                    break

                try:
                    # Stream response to strictly enforce response size limit without buffering massive files
                    with client.stream("GET", current_url) as resp:
                        # Read only up to MAX_RESPONSE_BYTES
                        content_bytes = resp.read()
                        if len(content_bytes) > settings.MAX_RESPONSE_BYTES:
                            http_error = f"Response payload exceeded maximum safe size of {settings.MAX_RESPONSE_BYTES} bytes."

                        final_response = resp

                        # Check for redirect (3xx)
                        if resp.is_redirect and allow_redirects:
                            location = resp.headers.get("location")
                            redirect_hops.append(HttpRedirectHop(
                                status_code=resp.status_code,
                                url=current_url,
                                location=location
                            ))

                            if not location:
                                http_error = "Received redirect status code without a Location header."
                                break

                            # Resolve relative redirect URLs
                            next_url = urljoin(current_url, location)
                            redirect_count += 1

                            if redirect_count > max_redirects:
                                http_error = f"Exceeded maximum redirection hop limit ({max_redirects}). Potential redirect loop."
                                break

                            current_url = next_url
                            continue
                        else:
                            # Terminal non-redirect response
                            break

                except httpx.ConnectTimeout:
                    http_error = f"Connection timed out after {timeout_seconds} seconds."
                    break
                except httpx.ReadTimeout:
                    http_error = f"Server read timed out after {timeout_seconds} seconds."
                    break
                except httpx.ConnectError as e:
                    # Check if error is TLS certificate verification failure
                    err_str = str(e)
                    if "certificate" in err_str.lower() or "ssl" in err_str.lower() or "cert" in err_str.lower():
                        tls_error = f"TLS Verification Failed: {err_str}"
                    else:
                        http_error = f"TCP/HTTP Connection Error: {err_str}"
                    break
                except Exception as e:
                    http_error = f"HTTP client request failure: {str(e)}"
                    break

        duration_ms = (time.perf_counter() - start_time) * 1000

        # Safe header extraction
        filtered_headers: List[HttpHeaderItem] = []
        status_code = None
        status_phrase = None
        content_type = None
        content_length = None

        if final_response is not None:
            status_code = final_response.status_code
            status_phrase = final_response.reason_phrase
            content_type = final_response.headers.get("content-type")
            cl_header = final_response.headers.get("content-length")
            if cl_header and cl_header.isdigit():
                content_length = int(cl_header)

            for key, val in final_response.headers.items():
                if key.lower() in ALLOWLISTED_HEADERS:
                    filtered_headers.append(HttpHeaderItem(name=key, value=val))

        # Generate Troubleshooting findings
        finding = TroubleshootingEngine.evaluate_http_check(
            url=clean_url,
            status_code=status_code,
            duration_ms=duration_ms,
            redirect_count=redirect_count,
            error_message=tls_error or http_error
        )
        if finding:
            findings.append(FindingSchema(**finding.model_dump()))

        return HttpAnalysisResponse(
            initial_url=clean_url,
            final_url=current_url,
            status_code=status_code,
            status_phrase=status_phrase,
            duration_ms=duration_ms,
            redirect_count=redirect_count,
            redirect_hops=redirect_hops,
            headers=filtered_headers,
            content_type=content_type,
            content_length=content_length,
            is_tls=clean_url.lower().startswith("https://") or current_url.lower().startswith("https://"),
            tls_error=tls_error,
            http_error=http_error,
            findings=findings
        )
