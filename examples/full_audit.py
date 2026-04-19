"""
examples/full_audit.py — Full AWS security audit example.

Run with:
  python examples/full_audit.py
  python examples/full_audit.py --profile my-profile --regions us-east-1 eu-west-1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from the repo root without installing
sys.path.insert(0, str(Path(__file__).parent.parent))

from cloudsec_audit import CloudSecAudit, AWSSession
from cloudsec_audit.utils.logging import configure_logging


def main():
    parser = argparse.ArgumentParser(description="Full AWS security audit example")
    parser.add_argument("--profile", default=None, help="AWS CLI profile name")
    parser.add_argument("--role-arn", default=None, help="IAM role to assume")
    parser.add_argument("--regions", nargs="+", default=["us-east-1"])
    parser.add_argument("--output-dir", default=".", help="Directory for output files")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    configure_logging(args.log_level)

    # 1. Build session
    if args.role_arn:
        session = AWSSession.from_role(args.role_arn)
    elif args.profile:
        session = AWSSession.from_profile(args.profile)
    else:
        session = AWSSession()

    print(f"Auditing AWS account: {session.account_id}")
    print(f"Regions: {', '.join(args.regions)}")
    print()

    # 2. Run audit
    audit = CloudSecAudit(
        session=session,
        regions=args.regions,
        run_iam=True,
        run_network=True,
        run_storage=True,
    )

    report = audit.run()

    # 3. Print console summary
    print(report.summary())

    # 4. Write output files
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "findings.json"
    md_path = output_dir / "findings.md"
    csv_path = output_dir / "findings.csv"
    compliance_path = output_dir / "compliance.json"

    report.to_json(str(json_path))
    report.to_markdown(str(md_path))
    report.to_csv(str(csv_path))
    print(f"Findings written to {json_path}, {md_path}, {csv_path}")

    # 5. Compliance report
    compliance = audit.compliance_report(frameworks=["CIS", "SOC2", "PCI-DSS"])
    print(compliance.summary())
    compliance.to_json(str(compliance_path))
    print(f"Compliance report written to {compliance_path}")

    # 6. Exit non-zero if critical findings
    if report.critical:
        print(f"\n⛔  {len(report.critical)} CRITICAL finding(s) detected.")
        sys.exit(1)
    elif report.high:
        print(f"\n⚠️   {len(report.high)} HIGH finding(s) detected.")
        sys.exit(1)
    else:
        print("\n✅  No critical or high findings.")
        sys.exit(0)


if __name__ == "__main__":
    main()