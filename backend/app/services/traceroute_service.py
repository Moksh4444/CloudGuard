"""
Safe bounded traceroute utility for network path discovery.
Executes OS-level tracert/traceroute with strict hop boundaries, subprocess timeout,
and defense against command injection (no shell=True).
"""
import platform
import shutil
import subprocess
import time
from typing import Dict, Any, List
from app.core.config import settings
from app.security.ssrf import validate_target_host


class TracerouteService:
    @staticmethod
    def is_available() -> bool:
        """Checks if a platform traceroute executable is in PATH."""
        is_windows = platform.system().lower() == "windows"
        cmd = "tracert" if is_windows else "traceroute"
        return shutil.which(cmd) is not None

    @staticmethod
    def run_traceroute(target: str) -> Dict[str, Any]:
        """
        Executes bounded traceroute to target hostname or IP.
        """
        clean_target = target.strip().lower()
        if "://" in clean_target:
            clean_target = clean_target.split("://")[1].split("/")[0].split(":")[0]

        start_time = time.perf_counter()

        # SSRF Validation
        is_safe, ssrf_msg, resolved_ips = validate_target_host(clean_target)
        if not is_safe:
            return {
                "available": True,
                "executed": False,
                "target": clean_target,
                "status": "FAILURE",
                "duration_ms": (time.perf_counter() - start_time) * 1000,
                "output": "",
                "hops": [],
                "error_message": f"SSRF boundary policy violation: {ssrf_msg}",
                "limitations": "Traceroute to private/restricted IP ranges is blocked."
            }

        is_windows = platform.system().lower() == "windows"
        cmd_name = "tracert" if is_windows else "traceroute"
        executable = shutil.which(cmd_name)

        if not executable:
            return {
                "available": False,
                "executed": False,
                "target": clean_target,
                "status": "WARNING",
                "duration_ms": 0.0,
                "output": "",
                "hops": [],
                "error_message": f"Utility '{cmd_name}' is not installed or accessible in system PATH.",
                "limitations": "Route diagnostics require a supported system utility."
            }

        # Safe command arguments: no shell=True, strict bounding
        max_hops = settings.TRACEROUTE_MAX_HOPS
        timeout_sec = settings.TRACEROUTE_TIMEOUT_SECONDS

        if is_windows:
            # -d: Do not resolve addresses to hostnames (faster)
            # -h: Maximum number of hops
            # -w: Timeout in milliseconds per reply
            cmd = [executable, "-d", "-h", str(max_hops), "-w", "1000", clean_target]
        else:
            # -n: Numeric IP output
            # -m: Max hops
            # -w: Wait time per probe
            cmd = [executable, "-n", "-m", str(max_hops), "-w", "1", clean_target]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                shell=False
            )
            raw_output = process.stdout
            status = "SUCCESS" if process.returncode == 0 else "WARNING"
            err_msg = process.stderr if process.returncode != 0 else None
        except subprocess.TimeoutExpired:
            raw_output = "Traceroute reached maximum execution timeout limit."
            status = "WARNING"
            err_msg = f"Bounded execution timeout ({timeout_sec}s) reached."
        except Exception as e:
            raw_output = ""
            status = "FAILURE"
            err_msg = str(e)

        duration_ms = (time.perf_counter() - start_time) * 1000

        # Parse hops
        parsed_hops: List[Dict[str, Any]] = []
        for line in raw_output.splitlines():
            line_str = line.strip()
            # Match hop lines starting with digits
            parts = line_str.split()
            if parts and parts[0].isdigit():
                parsed_hops.append({
                    "hop": int(parts[0]),
                    "raw_line": line_str
                })

        return {
            "available": True,
            "executed": True,
            "target": clean_target,
            "status": status,
            "duration_ms": duration_ms,
            "output": raw_output[:4000],  # Bound output size
            "hops": parsed_hops,
            "error_message": err_msg,
            "limitations": "Intermediate routers may drop ICMP/UDP TTL-expired packets by policy, showing '*' (request timed out) without indicating an outage."
        }
