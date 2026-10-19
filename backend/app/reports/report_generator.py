"""
Professional Diagnostic and Security Report Generator for CloudGuard.
Generates structured JSON, downloadable CSV, and styled executive HTML reports.
"""
import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.diagnostic import (
    DiagnosticRun,
    ReportMetadata,
    CloudConfigurationAnalysis,
)


class ReportGenerator:
    @staticmethod
    def generate_run_report(
        db: Session,
        run_id: str,
        export_format: str = "json"
    ) -> Dict[str, Any]:
        """
        Generates a comprehensive report for a specific DiagnosticRun.
        """
        run = db.query(DiagnosticRun).filter(DiagnosticRun.id == run_id).first()
        if not run:
            raise ValueError(f"Diagnostic run with ID '{run_id}' not found.")

        report_uid = f"RPT-{uuid.uuid4().hex[:8].upper()}"

        checks_data = []
        for c in run.checks:
            checks_data.append({
                "check_type": c.check_type,
                "status": c.status,
                "duration_ms": c.duration_ms,
                "error_message": c.error_message,
                "details": c.details
            })

        findings_data = []
        for f in run.findings:
            findings_data.append({
                "symptom": f.symptom,
                "confidence": f.confidence,
                "likely_explanations": f.explanations,
                "diagnostic_evidence": f.diagnostic_evidence,
                "next_steps": f.next_steps,
                "limitations": f.limitations
            })

        report_content = {
            "report_id": report_uid,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run.id,
            "target": run.target,
            "target_type": run.target_type,
            "status": run.status,
            "summary": run.summary,
            "duration_ms": run.duration_ms,
            "run_timestamp": run.created_at.isoformat() + "Z" if run.created_at else None,
            "checks": checks_data,
            "findings": findings_data,
            "limitations_notice": (
                "Educational Disclaimer: This report represents automated diagnostics evaluated from the perspective "
                "of the scanning agent. It does not replace comprehensive incident response or root cause analysis."
            )
        }

        # Save metadata to DB
        metadata = ReportMetadata(
            report_uid=report_uid,
            title=f"Diagnostic Report: {run.target} ({run.status})",
            target=run.target,
            scope=run.target_type.upper(),
            format=export_format.upper(),
            run_id=run.id
        )
        db.add(metadata)
        db.commit()

        if export_format.lower() == "csv":
            csv_output = io.StringIO()
            writer = csv.writer(csv_output)
            writer.writerow(["Report ID", "Generated At", "Target", "Status", "Duration (ms)"])
            writer.writerow([report_uid, report_content["generated_at"], run.target, run.status, run.duration_ms])
            writer.writerow([])
            writer.writerow(["Check Type", "Status", "Duration (ms)", "Error Message"])
            for c in checks_data:
                writer.writerow([c["check_type"], c["status"], c["duration_ms"], c["error_message"] or "None"])
            writer.writerow([])
            writer.writerow(["Symptom", "Confidence", "Diagnostic Evidence", "Next Steps"])
            for f in findings_data:
                writer.writerow([
                    f["symptom"],
                    f["confidence"],
                    f["diagnostic_evidence"],
                    "; ".join(f["next_steps"])
                ])
            return {
                "report_uid": report_uid,
                "format": "csv",
                "filename": f"cloudguard-report-{report_uid}.csv",
                "content": csv_output.getvalue()
            }

        elif export_format.lower() == "html":
            html_content = ReportGenerator._render_html_report(report_content)
            return {
                "report_uid": report_uid,
                "format": "html",
                "filename": f"cloudguard-report-{report_uid}.html",
                "content": html_content
            }

        return {
            "report_uid": report_uid,
            "format": "json",
            "filename": f"cloudguard-report-{report_uid}.json",
            "content": json.dumps(report_content, indent=2)
        }

    @staticmethod
    def _render_html_report(data: Dict[str, Any]) -> str:
        """Renders a standalone, printable, executive HTML report."""
        status_color = "#10b981" if data["status"] == "SUCCESS" else ("#f59e0b" if data["status"] == "WARNING" else "#ef4444")
        findings_html = ""
        for f in data.get("findings", []):
            steps_li = "".join(f"<li>{s}</li>" for s in f.get("next_steps", []))
            expl_li = "".join(f"<li>{e}</li>" for e in f.get("likely_explanations", []))
            findings_html += f"""
            <div style="background:#1e293b; border-left: 4px solid #38bdf8; padding: 16px; margin-bottom: 16px; border-radius: 4px;">
                <h3 style="margin: 0 0 8px 0; color: #f8fafc; font-size: 16px;">{f.get('symptom')}</h3>
                <p style="margin: 4px 0; color: #94a3b8; font-size: 13px;"><strong>Confidence:</strong> {f.get('confidence')} | <strong>Evidence:</strong> {f.get('diagnostic_evidence')}</p>
                <div style="margin-top: 8px;">
                    <strong style="color: #cbd5e1; font-size: 13px;">Likely Explanations:</strong>
                    <ul style="color: #94a3b8; font-size: 13px; margin: 4px 0 8px 20px;">{expl_li}</ul>
                </div>
                <div>
                    <strong style="color: #cbd5e1; font-size: 13px;">Recommended Next Steps:</strong>
                    <ul style="color: #38bdf8; font-size: 13px; margin: 4px 0 0 20px;">{steps_li}</ul>
                </div>
            </div>
            """

        checks_html = ""
        for c in data.get("checks", []):
            chk_color = "#10b981" if c["status"] == "SUCCESS" else ("#f59e0b" if c["status"] == "WARNING" else "#ef4444")
            checks_html += f"""
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #334155; font-family: monospace;">{c['check_type'].upper()}</td>
                <td style="padding: 10px; border-bottom: 1px solid #334155;"><span style="background:{chk_color}22; color:{chk_color}; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px;">{c['status']}</span></td>
                <td style="padding: 10px; border-bottom: 1px solid #334155;">{c['duration_ms']:.1f} ms</td>
                <td style="padding: 10px; border-bottom: 1px solid #334155; color: #94a3b8;">{c['error_message'] or 'None'}</td>
            </tr>
            """

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CloudGuard Report - {data['report_id']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; margin: 0; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #0b1120; border: 1px solid #1e293b; border-radius: 8px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 20px; margin-bottom: 24px; }}
        .badge {{ background: {status_color}; color: #ffffff; padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 14px; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th {{ text-align: left; padding: 10px; background: #1e293b; color: #cbd5e1; font-size: 12px; text-transform: uppercase; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #1e293b; font-size: 12px; color: #64748b; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin: 0; font-size: 24px; color: #38bdf8;">CloudGuard Diagnostic Report</h1>
                <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 14px;">Report ID: <strong>{data['report_id']}</strong></p>
            </div>
            <div>
                <span class="badge">{data['status']}</span>
            </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px;">
            <div style="background: #1e293b; padding: 16px; border-radius: 6px;">
                <div style="font-size: 12px; color: #94a3b8;">Target</div>
                <div style="font-size: 16px; font-weight: bold; color: #f8fafc; word-break: break-all;">{data['target']}</div>
            </div>
            <div style="background: #1e293b; padding: 16px; border-radius: 6px;">
                <div style="font-size: 12px; color: #94a3b8;">Generated At</div>
                <div style="font-size: 14px; font-weight: bold; color: #f8fafc;">{data['generated_at']}</div>
            </div>
            <div style="background: #1e293b; padding: 16px; border-radius: 6px;">
                <div style="font-size: 12px; color: #94a3b8;">Total Latency</div>
                <div style="font-size: 16px; font-weight: bold; color: #f8fafc;">{data['duration_ms']:.1f} ms</div>
            </div>
        </div>

        <h2 style="font-size: 18px; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-top: 24px;">Executed Diagnostic Checks</h2>
        <table>
            <thead>
                <tr>
                    <th>Check Type</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Error Detail</th>
                </tr>
            </thead>
            <tbody>
                {checks_html}
            </tbody>
        </table>

        <h2 style="font-size: 18px; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-top: 32px;">Troubleshooting Intelligence & Guidance</h2>
        {findings_html if findings_html else '<p style="color: #10b981;">No active issues or anomalies identified during this run.</p>'}

        <div class="footer">
            <p>{data['limitations_notice']}</p>
            <p>CloudGuard &bull; Cloud Security & Network Troubleshooting Platform</p>
        </div>
    </div>
</body>
</html>"""
