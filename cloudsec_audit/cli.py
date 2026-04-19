"""
cloudsec-audit CLI — run cloud security audits from the command line.

Usage:
  cloudsec-audit --regions us-east-1 eu-west-1 --output results.json
  cloudsec-audit --only iam --profile my-profile
  cloudsec-audit --compliance CIS SOC2
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from cloudsec_audit.models.session import AWSSession
from cloudsec_audit.orchestrator import CloudSecAudit
from cloudsec_audit.reporters.compliance import ComplianceReporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudsec-audit",
        description="Continuous cloud security posture auditing for AWS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full audit with default credentials, single region
  cloudsec-audit

  # Audit multiple regions with a named profile
  cloudsec-audit --profile prod-readonly --regions us-east-1 eu-west-1

  # IAM-only audit, output JSON
  cloudsec-audit --only iam --output iam-findings.json

  # Compliance report against CIS and SOC2
  cloudsec-audit --compliance CIS SOC2 --output-compliance compliance.json

  # Assume a cross-account role
  cloudsec-audit --role-arn arn:aws:iam::123456789012:role/AuditRole
        """,
    )

    # Authentication
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("--profile", metavar="NAME", help="AWS CLI profile name")
    auth.add_argument(
        "--role-arn",
        metavar="ARN",
        help="IAM role ARN to assume before auditing",
    )
    auth.add_argument(
        "--external-id",
        metavar="ID",
        help="External ID for role assumption (used with --role-arn)",
    )

    # Scope
    scope = parser.add_argument_group("Scope")
    scope.add_argument(
        "--regions",
        nargs="+",
        default=["us-east-1"],
        metavar="REGION",
        help="AWS regions to audit (default: us-east-1)",
    )
    scope.add_argument(
        "--only",
        nargs="+",
        choices=["iam", "network", "storage"],
        metavar="ANALYZER",
        help="Run only specific analyzers (iam, network, storage)",
    )

    # Output
    output = parser.add_argument_group("Output")
    output.add_argument(
        "--output",
        metavar="FILE",
        help="Write JSON findings report to this file",
    )
    output.add_argument(
        "--output-markdown",
        metavar="FILE",
        help="Write Markdown report to this file",
    )
    output.add_argument(
        "--output-csv",
        metavar="FILE",
        help="Write CSV findings to this file",
    )
    output.add_argument(
        "--compliance",
        nargs="+",
        choices=ComplianceReporter.SUPPORTED_FRAMEWORKS,
        metavar="FRAMEWORK",
        help="Generate compliance report for these frameworks",
    )
    output.add_argument(
        "--output-compliance",
        metavar="FILE",
        help="Write compliance report JSON to this file",
    )

    # Misc
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # Build session
    try:
        if args.role_arn:
            session = AWSSession.from_role(
                role_arn=args.role_arn,
                external_id=args.external_id,
            )
        elif args.profile:
            session = AWSSession.from_profile(args.profile)
        else:
            session = AWSSession()

        session.validate()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Determine which analyzers to run
    only = set(args.only) if args.only else {"iam", "network", "storage"}

    audit = CloudSecAudit(
        session=session,
        regions=args.regions,
        run_iam="iam" in only,
        run_network="network" in only,
        run_storage="storage" in only,
    )

    try:
        report = audit.run()
    except Exception as exc:
        print(f"ERROR: Audit failed: {exc}", file=sys.stderr)
        return 1

    # Console output
    print(report.summary())

    # File outputs
    if args.output:
        report.to_json(args.output)
        print(f"JSON report written to {args.output}")

    if args.output_markdown:
        report.to_markdown(args.output_markdown)
        print(f"Markdown report written to {args.output_markdown}")

    if args.output_csv:
        report.to_csv(args.output_csv)
        print(f"CSV report written to {args.output_csv}")

    if args.compliance:
        compliance = audit.compliance_report(frameworks=args.compliance)
        print(compliance.summary())

        if args.output_compliance:
            compliance.to_json(args.output_compliance)
            print(f"Compliance report written to {args.output_compliance}")

    # Exit code: 1 if any critical/high findings
    has_critical_or_high = any(
        f.severity.value in ("CRITICAL", "HIGH")
        for f in report.open_findings
    )
    return 1 if has_critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())