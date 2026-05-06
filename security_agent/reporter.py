"""
Security Agent - report generator.

Produces structured security assessment reports from a list of Findings.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .analyzer import Finding, Severity


_SEVERITY_ORDER = [s.value for s in Severity]


def _severity_index(s: Severity) -> int:
    try:
        return _SEVERITY_ORDER.index(s.value)
    except ValueError:
        return len(_SEVERITY_ORDER)


class ReportGenerator:
    """Generate security assessment reports in text or JSON format."""

    def generate_text(
        self,
        findings: list[Finding],
        title: str = "Security Assessment Report",
        system_name: str = "Target System",
    ) -> str:
        lines: list[str] = []
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines.append("=" * 70)
        lines.append(f"  {title}")
        lines.append(f"  System : {system_name}")
        lines.append(f"  Date   : {ts}")
        lines.append("=" * 70)

        if not findings:
            lines.append("")
            lines.append("✅  No findings. All checked controls passed.")
            lines.append("")
            return "\n".join(lines)

        # Summary
        counts = Counter(f.severity for f in findings)
        cis_count = sum(1 for f in findings if f.framework == "CIS")
        nist_count = sum(1 for f in findings if f.framework == "NIST")

        lines.append("")
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Total Findings : {len(findings)}")
        lines.append(f"  CIS Findings : {cis_count}")
        lines.append(f"  NIST Findings: {nist_count}")
        lines.append("")
        for sev in Severity:
            n = counts.get(sev, 0)
            if n:
                lines.append(f"  {sev.value:<10}: {n}")
        lines.append("")

        # Risk Score (simple weighted score out of 100)
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        raw_score = sum(weights[f.severity] for f in findings)
        risk_score = min(100, raw_score)
        risk_label = (
            "CRITICAL" if risk_score >= 70
            else "HIGH" if risk_score >= 40
            else "MODERATE" if risk_score >= 20
            else "LOW"
        )
        lines.append(f"Risk Score : {risk_score}/100  ({risk_label})")
        lines.append("")

        # Findings by severity
        for sev in Severity:
            sev_findings = [f for f in findings if f.severity == sev]
            if not sev_findings:
                continue
            lines.append("")
            lines.append(f"{'─' * 70}")
            lines.append(f"  {sev.value} SEVERITY FINDINGS  ({len(sev_findings)})")
            lines.append(f"{'─' * 70}")
            for finding in sev_findings:
                lines.append("")
                lines.append(f"  [{finding.framework}] {finding.control_id}")
                lines.append(f"  Title      : {finding.title}")
                lines.append(f"  Description: {finding.description}")
                lines.append(f"  Remediation: {finding.remediation}")
                if "failed_checks" in finding.details:
                    lines.append(f"  Failed Checks: {', '.join(finding.details['failed_checks'])}")
                if "category" in finding.details:
                    lines.append(f"  Category   : {finding.details['category']}")
                if "family" in finding.details:
                    lines.append(f"  Family     : {finding.details['family']}")
                    lines.append(f"  Baseline   : {', '.join(finding.details.get('baseline', []))}")
                lines.append("")

        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)
        return "\n".join(lines)

    def generate_json(
        self,
        findings: list[Finding],
        title: str = "Security Assessment Report",
        system_name: str = "Target System",
    ) -> str:
        ts = datetime.now(timezone.utc).isoformat()
        counts = Counter(f.severity.value for f in findings)
        data: dict[str, Any] = {
            "report": {
                "title": title,
                "system": system_name,
                "generated_at": ts,
                "summary": {
                    "total": len(findings),
                    "by_severity": dict(counts),
                    "by_framework": {
                        "CIS": sum(1 for f in findings if f.framework == "CIS"),
                        "NIST": sum(1 for f in findings if f.framework == "NIST"),
                    },
                },
                "findings": [
                    {
                        "id": f.id,
                        "control_id": f.control_id,
                        "framework": f.framework,
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity.value,
                        "remediation": f.remediation,
                        "details": f.details,
                    }
                    for f in findings
                ],
            }
        }
        return json.dumps(data, indent=2)
