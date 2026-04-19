"""
AuditReport — aggregates findings from multiple analyzers into a unified report.

Supports output as:
  - Pretty-printed console summary
  - JSON
  - Markdown
  - CSV
"""

from __future__ import annotations

import csv
import io
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cloudsec_audit.models.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)


class AuditReport:
    """
    Aggregates findings from one or more analyzers.

    Usage::

        report = AuditReport(findings, account_id="123456789012")
        print(report.summary())
        report.to_json("audit-results.json")
        report.to_markdown("audit-results.md")

    Args:
        findings: Combined list of findings from all analyzers.
        account_id: AWS account ID for report headers.
        scan_duration_seconds: Optional scan duration to include in metadata.
    """

    def __init__(
        self,
        findings: List[Finding],
        account_id: Optional[str] = None,
        scan_duration_seconds: Optional[float] = None,
    ) -> None:
        self.findings = findings
        self.account_id = account_id or (findings[0].account_id if findings else "unknown")
        self.scan_duration_seconds = scan_duration_seconds
        self.generated_at = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Filtering helpers
    # ------------------------------------------------------------------

    @property
    def open_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.OPEN]

    @property
    def critical(self) -> List[Finding]:
        return [f for f in self.open_findings if f.severity == Severity.CRITICAL]

    @property
    def high(self) -> List[Finding]:
        return [f for f in self.open_findings if f.severity == Severity.HIGH]

    @property
    def medium(self) -> List[Finding]:
        return [f for f in self.open_findings if f.severity == Severity.MEDIUM]

    @property
    def low(self) -> List[Finding]:
        return [f for f in self.open_findings if f.severity == Severity.LOW]

    def by_category(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = defaultdict(list)
        for f in self.open_findings:
            result[f.category].append(f)
        return dict(result)

    def by_severity(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = defaultdict(list)
        for f in self.open_findings:
            result[f.severity.value].append(f)
        return dict(result)

    def by_resource_type(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = defaultdict(list)
        for f in self.open_findings:
            result[f.resource_type].append(f)
        return dict(result)

    def sorted_by_severity(self) -> List[Finding]:
        return sorted(
            self.open_findings,
            key=lambda f: f.severity.score,
            reverse=True,
        )

    # ------------------------------------------------------------------
    # Output formats
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """
        Return a rich console summary of the audit report.
        """
        open_f = self.open_findings
        by_sev = Counter(f.severity.value for f in open_f)

        lines = [
            "",
            "╔══════════════════════════════════════════════════════════╗",
            "║         cloudsec-audit — AWS Security Audit Report       ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            f"  Account ID  : {self.account_id}",
            f"  Generated   : {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        ]

        if self.scan_duration_seconds is not None:
            lines.append(f"  Scan Time   : {self.scan_duration_seconds:.1f}s")

        lines += [
            f"  Total Findings: {len(self.findings)}  (Open: {len(open_f)})",
            "",
            "  ┌─────────────────────────────────────┐",
            "  │         SEVERITY BREAKDOWN           │",
            "  ├─────────────────────────────────────┤",
            f"  │  🔴 CRITICAL    {by_sev.get('CRITICAL', 0):>4}                  │",
            f"  │  🟠 HIGH        {by_sev.get('HIGH', 0):>4}                  │",
            f"  │  🟡 MEDIUM      {by_sev.get('MEDIUM', 0):>4}                  │",
            f"  │  🔵 LOW         {by_sev.get('LOW', 0):>4}                  │",
            f"  │  ⚪ INFO        {by_sev.get('INFORMATIONAL', 0):>4}                  │",
            "  └─────────────────────────────────────┘",
            "",
        ]

        # Category breakdown
        lines.append("  FINDINGS BY CATEGORY")
        lines.append("  " + "─" * 44)
        for cat, cat_findings in sorted(self.by_category().items()):
            sev_counts = Counter(f.severity.value for f in cat_findings)
            lines.append(
                f"  {cat:<14}  "
                f"C:{sev_counts.get('CRITICAL',0)}  "
                f"H:{sev_counts.get('HIGH',0)}  "
                f"M:{sev_counts.get('MEDIUM',0)}  "
                f"L:{sev_counts.get('LOW',0)}"
            )

        lines.append("")

        # Top 10 open findings
        if open_f:
            lines.append("  TOP FINDINGS (by severity)")
            lines.append("  " + "─" * 56)
            for i, finding in enumerate(self.sorted_by_severity()[:10], 1):
                sev_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🔵",
                    "INFORMATIONAL": "⚪",
                }.get(finding.severity.value, " ")

                lines.append(f"  {i:>2}. {sev_icon} [{finding.severity.value:<12}] {finding.title[:45]}")
                if finding.resource_id:
                    rid = (finding.resource_id[-50:] if len(finding.resource_id) > 50
                           else finding.resource_id)
                    lines.append(f"       Resource: {rid}")
                lines.append("")

        lines += [
            "══════════════════════════════════════════════════════════════",
            "",
        ]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full report to a dictionary."""
        return {
            "meta": {
                "account_id": self.account_id,
                "generated_at": self.generated_at.isoformat(),
                "scan_duration_seconds": self.scan_duration_seconds,
                "tool": "cloudsec-audit",
                "version": "0.1.0",
            },
            "stats": {
                "total": len(self.findings),
                "open": len(self.open_findings),
                "by_severity": {
                    sev.value: sum(
                        1 for f in self.open_findings if f.severity == sev
                    )
                    for sev in Severity
                },
                "by_category": {
                    cat: len(findings)
                    for cat, findings in self.by_category().items()
                },
            },
            "findings": [f.to_dict() for f in self.sorted_by_severity()],
        }

    def to_json(self, path: str, indent: int = 2) -> None:
        """Write the full report to a JSON file."""
        with open(path, "w") as fh:
            json.dump(self.to_dict(), fh, indent=indent, default=str)
        logger.info("Audit report written to %s", path)

    def to_markdown(self, path: str) -> None:
        """Write the report as a Markdown document."""
        lines = [
            f"# cloudsec-audit Report",
            f"",
            f"**Account:** `{self.account_id}`  ",
            f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Total Findings:** {len(self.findings)} ({len(self.open_findings)} open)",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]:
            count = sum(1 for f in self.open_findings if f.severity == sev)
            lines.append(f"| {sev.value} | {count} |")

        lines += [
            f"",
            f"## Findings",
            f"",
        ]

        for finding in self.sorted_by_severity():
            lines += [
                f"### [{finding.severity.value}] {finding.title}",
                f"",
                f"- **Resource:** `{finding.resource_id}`",
                f"- **Type:** `{finding.resource_type}`",
                f"- **Region:** `{finding.region or 'global'}`",
                f"- **Category:** {finding.category} / {finding.subcategory}",
                f"",
                f"{finding.description}",
                f"",
            ]

            if finding.attack_path:
                ap = finding.attack_path
                lines.append(f"**Attack Path:**")
                for step in ap.steps:
                    lines.append(f"1. {step}")
                if ap.blast_radius:
                    lines.append(f"\n**Blast Radius:** {ap.blast_radius}")
                lines.append("")

            if finding.remediation_steps:
                lines.append("**Remediation:**")
                for step in finding.remediation_steps:
                    lines.append(f"{step.order}. {step.description}")
                    if step.code_snippet:
                        lines.append(f"   ```bash\n   {step.code_snippet}\n   ```")
                lines.append("")

            if finding.compliance_controls:
                ctrl_parts = []
                for fw, ctrls in finding.compliance_controls.items():
                    ctrl_parts.append(f"{fw}: {', '.join(ctrls)}")
                lines.append(f"**Compliance:** {' | '.join(ctrl_parts)}")
                lines.append("")

            lines.append("---")
            lines.append("")

        with open(path, "w") as fh:
            fh.write("\n".join(lines))

        logger.info("Markdown report written to %s", path)

    def to_csv(self, path: str) -> None:
        """Write findings to a CSV file for spreadsheet analysis."""
        fieldnames = [
            "finding_id", "severity", "title", "category", "subcategory",
            "resource_id", "resource_type", "region", "account_id",
            "status", "first_seen", "mitre_techniques",
        ]

        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for f in self.sorted_by_severity():
                writer.writerow({
                    "finding_id": f.finding_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "category": f.category,
                    "subcategory": f.subcategory,
                    "resource_id": f.resource_id,
                    "resource_type": f.resource_type,
                    "region": f.region,
                    "account_id": f.account_id,
                    "status": f.status.value,
                    "first_seen": f.first_seen.isoformat(),
                    "mitre_techniques": ", ".join(f.mitre_techniques),
                })

        logger.info("CSV report written to %s", path)

    def __repr__(self) -> str:
        return (
            f"AuditReport(account={self.account_id}, "
            f"findings={len(self.findings)}, "
            f"open={len(self.open_findings)})"
        )