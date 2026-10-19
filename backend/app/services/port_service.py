"""
TCP Port Connectivity Diagnostic Service for CloudGuard.
Performs safe, controlled TCP connection handshakes to approved ports.
Accurately differentiates between Connection Refused, Timeout, and DNS errors.
"""
import errno
import socket
import time
from typing import Dict, Any, Optional
from app.core.config import settings
from app.security.ssrf import validate_target_host
from app.intelligence.troubleshooting_engine import TroubleshootingEngine
from app.schemas.diagnostic import FindingSchema


class PortService:
    @staticmethod
    def check_tcp_port(
        target: str,
        port: int,
        timeout_seconds: float = 5.0
    ) -> Dict[str, Any]:
        """
        Tests TCP three-way handshake to target:port.
        Returns detailed status, duration, error classification, and troubleshooting findings.
        """
        clean_target = target.strip().lower()
        if "://" in clean_target:
            clean_target = clean_target.split("://")[1].split("/")[0].split(":")[0]

        start_time = time.perf_counter()

        # Port validation (guard against arbitrary range scanning)
        if port not in settings.ALLOWED_PORTS:
            return {
                "connected": False,
                "status": "FAILURE",
                "duration_ms": 0.0,
                "port": port,
                "target": clean_target,
                "error_type": "PORT_RESTRICTED",
                "error_message": f"Port {port} is not in the approved diagnostic ports list.",
                "limitations": "CloudGuard restricts arbitrary port ranges to prevent unauthorized network scanning.",
                "findings": []
            }

        # SSRF Validation
        is_safe, ssrf_msg, resolved_ips = validate_target_host(clean_target)
        if not is_safe:
            duration_ms = (time.perf_counter() - start_time) * 1000
            finding = TroubleshootingEngine.evaluate_port_check(
                target=clean_target,
                port=port,
                connected=False,
                duration_ms=duration_ms,
                error_type="SSRF_POLICY_VIOLATION",
                error_detail=ssrf_msg
            )
            return {
                "connected": False,
                "status": "FAILURE",
                "duration_ms": duration_ms,
                "port": port,
                "target": clean_target,
                "error_type": "SSRF_POLICY_VIOLATION",
                "error_message": ssrf_msg,
                "limitations": "Target IP address violates SSRF protection boundaries.",
                "findings": [finding.model_dump()] if finding else []
            }

        # Attempt TCP connection to first resolved public IP
        target_ip = resolved_ips[0]
        sock = socket.socket(socket.AF_INET if ":" not in target_ip else socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(timeout_seconds)

        connected = False
        error_type: Optional[str] = None
        error_message: Optional[str] = None

        try:
            sock.connect((target_ip, port))
            connected = True
        except socket.timeout:
            error_type = "CONNECTION_TIMEOUT"
            error_message = f"Connection to {target_ip}:{port} timed out after {timeout_seconds}s (packet dropped)."
        except ConnectionRefusedError:
            error_type = "CONNECTION_REFUSED"
            error_message = f"Connection to {target_ip}:{port} was refused (TCP RST packet received)."
        except OSError as e:
            if e.errno == errno.ECONNREFUSED:
                error_type = "CONNECTION_REFUSED"
                error_message = f"Connection refused by target host on port {port}."
            elif e.errno == errno.ETIMEDOUT:
                error_type = "CONNECTION_TIMEOUT"
                error_message = f"Connection attempt timed out on port {port}."
            elif e.errno == errno.ENETUNREACH:
                error_type = "NETWORK_UNREACHABLE"
                error_message = "Network routing unreachable."
            else:
                error_type = "SOCKET_ERROR"
                error_message = f"Socket error (code {e.errno}): {e.strerror}"
        except Exception as e:
            error_type = "UNEXPECTED_ERROR"
            error_message = str(e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

        duration_ms = (time.perf_counter() - start_time) * 1000
        status = "SUCCESS" if connected else "FAILURE"

        # Generate findings via Troubleshooting Engine
        finding = TroubleshootingEngine.evaluate_port_check(
            target=clean_target,
            port=port,
            connected=connected,
            duration_ms=duration_ms,
            error_type=error_type,
            error_detail=error_message
        )

        return {
            "connected": connected,
            "status": status,
            "duration_ms": duration_ms,
            "port": port,
            "target": clean_target,
            "resolved_ip": target_ip,
            "error_type": error_type,
            "error_message": error_message,
            "limitations": "Confirms TCP transport handshake reachability; does not evaluate application-level session or payload health.",
            "findings": [finding.model_dump()] if finding else []
        }
