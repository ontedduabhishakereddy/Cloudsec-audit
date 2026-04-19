"""
examples/cross_account_audit.py — Audit multiple AWS accounts via role assumption.

Run with:
  python examples/cross_account_audit.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cloudsec_audit import CloudSecAudit, AWSSession
from cloudsec_audit.reporters.compliance import ComplianceReporter
from cloudsec_audit.reporters.report import AuditReport
from cloudsec_audit.utils.logging import configure_logging

configure_logging("INFO")

# Define the accounts to audit
ACCOUNTS = [
    {
        "role_arn": "arn:aws:iam::111111111111:role/SecurityAuditRole",
        "name": "Production",
        "regions": ["us-east-1", "eu-west-1"],
    },
    {
        "role_arn": "arn:aws:iam::222222222222:role/SecurityAuditRole",
        "name": "Staging",
        "regions": ["us-east-1"],
    },
]

all_findings = []

for account in ACCOUNTS:
    print(f"\n{'='*50}")
    print(f"Auditing: {account['name']} ({account['role_arn']})")
    print(f"{'='*50}")

    try:
        session = AWSSession.from_role(
            role_arn=account["role_arn"],
            session_name=f"cloudsec-audit-{account['name'].lower()}",
        )

        audit = CloudSecAudit(
            session=session,
            regions=account["regions"],
            run_iam=True,
            run_network=True,
            run_storage=True,
        )

        report = audit.run()
        print(report.summary())

        # Save per-account results
        report.to_json(f"findings-{account['name'].lower()}.json")

        all_findings.extend(report.findings)

    except Exception as exc:
        print(f"ERROR auditing {account['name']}: {exc}")

# Combined report across all accounts
if all_findings:
    print(f"\n{'='*60}")
    print(f"CONSOLIDATED REPORT — {len(all_findings)} total findings")
    print(f"{'='*60}")

    combined_report = AuditReport(all_findings, account_id="multi-account")
    print(combined_report.summary())
    combined_report.to_json("findings-all-accounts.json")

    # Combined compliance
    compliance = ComplianceReporter(all_findings, frameworks=["CIS", "SOC2"])
    print(compliance.summary())
    compliance.to_json("compliance-all-accounts.json")