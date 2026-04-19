"""
ComplianceReporter — maps findings to compliance frameworks and generates reports.

Supported frameworks:
  - CIS AWS Foundations Benchmark v1.5
  - SOC 2 (CC controls)
  - ISO 27001
  - HIPAA
  - PCI-DSS v4.0
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from cloudsec_audit.models.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# Control definitions per framework
# Maps control_id -> human-readable description
FRAMEWORK_CONTROLS: Dict[str, Dict[str, str]] = {
    "CIS": {
        "1.4": "Ensure no root account access key exists",
        "1.5": "Ensure MFA is enabled for the root account",
        "1.8": "Ensure IAM password policy requires minimum length of 14+",
        "1.9": "Ensure IAM password policy requires at least one uppercase letter",
        "1.10": "Ensure IAM password policy requires at least one lowercase letter",
        "1.11": "Ensure IAM password policy requires at least one symbol",
        "1.12": "Ensure IAM password policy requires at least one number",
        "1.13": "Ensure IAM password policy expires passwords within 90 days or less",
        "1.14": "Ensure IAM password policy prevents password reuse",
        "1.16": "Ensure IAM policies are attached only to groups or roles",
        "2.1.1": "Ensure S3 Bucket Policy is set to deny HTTP requests",
        "2.1.2": "Ensure S3 bucket policy does not allow * principal",
        "2.1.3": "Ensure MFA Delete is enabled on S3 bucket policies",
        "2.1.4": "Ensure all S3 buckets employ encryption-at-rest",
        "2.1.5": "Ensure all S3 buckets have access logging enabled",
        "3.9": "Ensure VPC flow logging is enabled in all VPCs",
        "5.1": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to port 22 or 3389",
        "5.2": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "5.3": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
        "5.4": "Ensure routing tables for VPC peering are least access",
    },
    "SOC2": {
        "CC6.1": "Logical and Physical Access Controls — Restrict access to information assets",
        "CC6.3": "Logical Access Security — Remove user access promptly on termination",
        "CC6.6": "Logical Access Security — Implement boundary protection",
        "CC6.7": "Logical Access Security — Encrypt data in transit and at rest",
        "CC7.2": "System Operations — Monitor system components",
        "A1.2": "Availability — Implement backup and recovery procedures",
    },
    "ISO27001": {
        "A.9.1.1": "Access control policy",
        "A.9.2.3": "Management of privileged access rights",
        "A.9.4.2": "Secure log-on procedures",
        "A.10.1.1": "Policy on the use of cryptographic controls",
        "A.12.4.1": "Event logging",
        "A.13.1.1": "Network controls",
    },
    "HIPAA": {
        "164.312(a)(1)": "Access Control — Implement technical policies to allow only authorized persons access",
        "164.312(a)(2)(iv)": "Encryption and decryption of ePHI",
        "164.312(b)": "Audit Controls — Hardware, software, and procedural mechanisms to record ePHI activity",
        "164.312(e)(1)": "Transmission Security — Guard against unauthorized access to ePHI in transit",
    },
    "PCI-DSS": {
        "1.3": "Prohibit direct public access to any component in the cardholder data environment",
        "3.4": "Render PAN unreadable anywhere it is stored",
        "7.1": "Limit access to system components and cardholder data to only those individuals whose job requires such access",
        "8.2": "User identification and authentication controls",
        "8.3": "Multi-factor authentication for all non-console access",
        "10.2": "Implement automated audit trails for all system components",
    },
}


class ControlResult:
    """Result of a single compliance control evaluation."""

    def __init__(
        self,
        control_id: str,
        framework: str,
        description: str,
    ) -> None:
        self.control_id = control_id
        self.framework = framework
        self.description = description
        self.findings: List[Finding] = []

    @property
    def status(self) -> str:
        open_findings = [f for f in self.findings if f.status == FindingStatus.OPEN]
        if not open_findings:
            return "PASS"
        critical_or_high = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in open_findings
        )
        return "FAIL" if critical_or_high else "WARN"

    @property
    def severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings if f.status == FindingStatus.OPEN)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "framework": self.framework,
            "description": self.description,
            "status": self.status,
            "severity": self.severity.value if self.severity else None,
            "finding_count": len(self.findings),
            "finding_ids": [f.finding_id for f in self.findings],
        }


class ComplianceReporter:
    """
    Maps findings to compliance framework controls and generates reports.

    Usage::

        from cloudsec_audit import ComplianceReporter

        reporter = ComplianceReporter(findings, frameworks=["CIS", "SOC2"])
        report = reporter.generate()

        print(reporter.summary())
        reporter.to_json("compliance-report.json")

    Args:
        findings: List of :class:`~cloudsec_audit.models.finding.Finding` objects.
        frameworks: Which frameworks to evaluate. Defaults to all supported frameworks.
        account_id: AWS account ID for report metadata.
    """

    SUPPORTED_FRAMEWORKS = list(FRAMEWORK_CONTROLS.keys())

    def __init__(
        self,
        findings: List[Finding],
        frameworks: Optional[List[str]] = None,
        account_id: Optional[str] = None,
    ) -> None:
        self.findings = findings
        self.frameworks = frameworks or self.SUPPORTED_FRAMEWORKS
        self.account_id = account_id or (findings[0].account_id if findings else "unknown")
        self._control_results: Dict[str, Dict[str, ControlResult]] = {}
        self._generated_at: Optional[datetime] = None

    def generate(self) -> Dict[str, Any]:
        """
        Build the compliance control matrix from findings.

        Returns a dict with full compliance status per framework.
        """
        self._generated_at = datetime.now(timezone.utc)
        self._control_results = {}

        for framework in self.frameworks:
            if framework not in FRAMEWORK_CONTROLS:
                logger.warning("Unknown framework: %s — skipping", framework)
                continue

            controls = FRAMEWORK_CONTROLS[framework]
            self._control_results[framework] = {
                ctrl_id: ControlResult(ctrl_id, framework, desc)
                for ctrl_id, desc in controls.items()
            }

        # Map findings to controls
        for finding in self.findings:
            for framework, control_ids in finding.compliance_controls.items():
                if framework not in self._control_results:
                    continue
                for ctrl_id in control_ids:
                    if ctrl_id in self._control_results[framework]:
                        self._control_results[framework][ctrl_id].findings.append(finding)

        return self._build_report()

    def _build_report(self) -> Dict[str, Any]:
        frameworks_data = {}
        overall_pass = 0
        overall_fail = 0
        overall_warn = 0

        for framework, controls in self._control_results.items():
            pass_count = sum(1 for c in controls.values() if c.status == "PASS")
            fail_count = sum(1 for c in controls.values() if c.status == "FAIL")
            warn_count = sum(1 for c in controls.values() if c.status == "WARN")
            total = len(controls)

            overall_pass += pass_count
            overall_fail += fail_count
            overall_warn += warn_count

            score = round((pass_count / total) * 100, 1) if total else 0

            frameworks_data[framework] = {
                "score_percent": score,
                "total_controls": total,
                "pass": pass_count,
                "fail": fail_count,
                "warn": warn_count,
                "controls": {
                    ctrl_id: result.to_dict()
                    for ctrl_id, result in sorted(controls.items())
                },
            }

        total_controls = overall_pass + overall_fail + overall_warn
        overall_score = round((overall_pass / total_controls * 100), 1) if total_controls else 0

        return {
            "meta": {
                "generated_at": self._generated_at.isoformat() if self._generated_at else None,
                "account_id": self.account_id,
                "frameworks_evaluated": self.frameworks,
                "total_findings_mapped": len(self.findings),
            },
            "overall": {
                "score_percent": overall_score,
                "total_controls": total_controls,
                "pass": overall_pass,
                "fail": overall_fail,
                "warn": overall_warn,
            },
            "frameworks": frameworks_data,
        }

    def summary(self) -> str:
        """Return a human-readable text summary of compliance posture."""
        if not self._control_results:
            self.generate()

        lines = [
            "=" * 60,
            f"  COMPLIANCE SUMMARY — Account: {self.account_id}",
            f"  Generated: {self._generated_at.strftime('%Y-%m-%d %H:%M UTC') if self._generated_at else 'N/A'}",
            "=" * 60,
            "",
        ]

        for framework, controls in self._control_results.items():
            total = len(controls)
            passing = sum(1 for c in controls.values() if c.status == "PASS")
            failing = sum(1 for c in controls.values() if c.status == "FAIL")
            score = round(passing / total * 100, 1) if total else 0

            lines.append(f"  {framework:<12} {score:>5.1f}%   Pass:{passing}  Fail:{failing}  Total:{total}")

        lines.append("")

        # List failing controls
        any_failures = False
        for framework, controls in self._control_results.items():
            failing = [(cid, c) for cid, c in controls.items() if c.status == "FAIL"]
            if failing:
                if not any_failures:
                    lines.append("FAILING CONTROLS:")
                    any_failures = True
                for ctrl_id, ctrl in failing:
                    sev = ctrl.severity.value if ctrl.severity else "N/A"
                    lines.append(f"  [{framework}] {ctrl_id} [{sev}] — {ctrl.description[:60]}")

        if not any_failures:
            lines.append("  No failing controls detected.")

        lines.append("=" * 60)
        return "\n".join(lines)

    def to_json(self, path: str) -> None:
        """Write compliance report to a JSON file."""
        report = self.generate()
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info("Compliance report written to %s", path)

    def to_dict(self) -> Dict[str, Any]:
        """Return the compliance report as a dictionary."""
        return self.generate()

    def failing_controls(self, framework: Optional[str] = None) -> List[ControlResult]:
        """Return all failing controls, optionally filtered by framework."""
        if not self._control_results:
            self.generate()

        results = []
        for fw, controls in self._control_results.items():
            if framework and fw != framework:
                continue
            results.extend(c for c in controls.values() if c.status == "FAIL")
        return sorted(results, key=lambda c: c.severity or Severity.INFORMATIONAL, reverse=True)