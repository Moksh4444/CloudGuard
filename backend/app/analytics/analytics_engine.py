"""
Analytics and Aggregation Engine for CloudGuard.
Computes real statistical metrics, percentiles, and trend aggregations from SQLite history.
"""
from collections import Counter
from datetime import datetime
import json
import statistics
from typing import Dict, Any, List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.diagnostic import (
    DiagnosticRun,
    DiagnosticCheck,
    TroubleshootingFinding,
    CloudConfigurationAnalysis,
    SecurityFinding,
)


class AnalyticsEngine:
    @staticmethod
    def get_overview_metrics(db: Session, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Calculates executive metrics and distributions from real persisted runs.
        """
        query = db.query(DiagnosticRun)
        if start_date:
            query = query.filter(DiagnosticRun.created_at >= start_date)
        if end_date:
            query = query.filter(DiagnosticRun.created_at <= end_date)

        runs = query.all()
        total_runs = len(runs)

        if total_runs == 0:
            return {
                "total_runs": 0,
                "successful_runs": 0,
                "failed_runs": 0,
                "warning_runs": 0,
                "avg_response_time_ms": 0.0,
                "median_response_time_ms": 0.0,
                "p95_response_time_ms": 0.0,
                "dns_failure_count": 0,
                "http_status_distribution": {},
                "failure_by_module": {},
                "most_frequent_issues": [],
                "runs_over_time": [],
                "cloud_severity_distribution": {
                    "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0
                }
            }

        successful_runs = sum(1 for r in runs if r.status == "SUCCESS")
        failed_runs = sum(1 for r in runs if r.status in ("FAILURE", "ERROR"))
        warning_runs = sum(1 for r in runs if r.status == "WARNING")

        # Response times calculation
        durations = [r.duration_ms for r in runs if r.duration_ms and r.duration_ms > 0]
        avg_rt = round(statistics.mean(durations), 1) if durations else 0.0
        median_rt = round(statistics.median(durations), 1) if durations else 0.0

        if len(durations) >= 5:
            sorted_durations = sorted(durations)
            p95_idx = int(len(sorted_durations) * 0.95)
            p95_rt = round(sorted_durations[min(p95_idx, len(sorted_durations) - 1)], 1)
        else:
            p95_rt = max(durations) if durations else 0.0

        # Query checks for detailed breakdown
        checks_query = db.query(DiagnosticCheck)
        if start_date or end_date:
            run_ids = [r.id for r in runs]
            checks_query = checks_query.filter(DiagnosticCheck.run_id.in_(run_ids))
        checks = checks_query.all()

        dns_failure_count = sum(1 for c in checks if c.check_type == "dns" and c.status == "FAILURE")

        # HTTP status code distribution
        http_status_counts: Counter = Counter()
        for c in checks:
            if c.check_type == "http" and c.details_json:
                try:
                    dt = json.loads(c.details_json)
                    code = dt.get("status_code")
                    if code:
                        group = f"{str(code)[0]}xx ({code})"
                        http_status_counts[group] += 1
                except Exception:
                    pass

        # Failure by module
        failure_by_module: Counter = Counter()
        for c in checks:
            if c.status == "FAILURE":
                failure_by_module[c.check_type.upper()] += 1

        # Most frequent findings symptoms
        findings_query = db.query(TroubleshootingFinding)
        if start_date or end_date:
            run_ids = [r.id for r in runs]
            findings_query = findings_query.filter(TroubleshootingFinding.run_id.in_(run_ids))
        findings = findings_query.all()

        symptom_counter = Counter(f.symptom for f in findings)
        most_frequent_issues = [
            {"symptom": sym, "count": count}
            for sym, count in symptom_counter.most_common(5)
        ]

        # Runs over time (grouped by day)
        date_counts: Counter = Counter()
        for r in runs:
            if r.created_at:
                day_str = r.created_at.strftime("%Y-%m-%d")
                date_counts[day_str] += 1

        sorted_days = sorted(date_counts.keys())
        runs_over_time = [{"date": d, "runs": date_counts[d]} for d in sorted_days]

        # Cloud Security Group findings distribution
        sec_findings = db.query(SecurityFinding).all()
        cloud_sev = Counter(f.severity for f in sec_findings)
        cloud_severity_distribution = {
            "CRITICAL": cloud_sev.get("CRITICAL", 0),
            "HIGH": cloud_sev.get("HIGH", 0),
            "MEDIUM": cloud_sev.get("MEDIUM", 0),
            "LOW": cloud_sev.get("LOW", 0),
            "INFORMATIONAL": cloud_sev.get("INFORMATIONAL", 0),
        }

        return {
            "total_runs": total_runs,
            "successful_runs": successful_runs,
            "failed_runs": failed_runs,
            "warning_runs": warning_runs,
            "avg_response_time_ms": avg_rt,
            "median_response_time_ms": median_rt,
            "p95_response_time_ms": p95_rt,
            "dns_failure_count": dns_failure_count,
            "http_status_distribution": dict(http_status_counts),
            "failure_by_module": dict(failure_by_module),
            "most_frequent_issues": most_frequent_issues,
            "runs_over_time": runs_over_time,
            "cloud_severity_distribution": cloud_severity_distribution,
        }
