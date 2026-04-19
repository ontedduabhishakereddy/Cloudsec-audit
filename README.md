# cloudsec-audit

**Continuous cloud security posture auditing for AWS** — IAM, network, storage, and compliance checks in a single pip-installable Python library.

[![PyPI version](https://badge.fury.io/py/cloudsec-audit.svg)](https://pypi.org/project/cloudsec-audit/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)

---

## The Problem

Cloud misconfigurations cause the majority of cloud breaches, yet most teams run audits manually or quarterly. Existing CSPM tools are expensive SaaS platforms. There is no open-source Python library for continuous, scriptable cloud posture auditing that developers can embed directly in their own CI/CD pipelines and workflows.

## The Solution

`cloudsec-audit` uses native AWS SDK clients (`boto3`) to continuously audit IAM permissions, network exposure, storage access controls, and logging configurations — producing prioritized, actionable findings with MITRE ATT&CK mappings and compliance framework evidence.

---

## Install

```bash
pip install cloudsec-audit
```

---

## Quick Start

### Python API

```python
from cloudsec_audit import CloudSecAudit, AWSSession

# Uses ambient credentials (env vars, ~/.aws/credentials, instance profile)
audit = CloudSecAudit(
    session=AWSSession(),
    regions=["us-east-1", "eu-west-1"],
)

report = audit.run()
print(report.summary())

# Export results
report.to_json("findings.json")
report.to_markdown("findings.md")
report.to_csv("findings.csv")

# Compliance evidence report
compliance = audit.compliance_report(frameworks=["CIS", "SOC2", "PCI-DSS"])
print(compliance.summary())
compliance.to_json("compliance-evidence.json")
```

### CLI

```bash
# Full audit, default region
cloudsec-audit

# Multi-region with a named profile
cloudsec-audit --profile prod-readonly --regions us-east-1 eu-west-1 ap-southeast-1

# IAM-only audit, save results
cloudsec-audit --only iam --output iam-findings.json

# Assume a cross-account audit role
cloudsec-audit --role-arn arn:aws:iam::123456789012:role/SecurityAuditRole

# Generate compliance report
cloudsec-audit --compliance CIS SOC2 --output-compliance compliance.json

# Debug mode
cloudsec-audit --log-level DEBUG
```

---

## Analyzers

### `IAMAnalyzer`

Audits IAM roles, users, policies, and trust relationships.

**Detects:**
- Root account without MFA or with active access keys
- Long-lived IAM access keys (default: > 90 days)
- Console users without MFA
- Users or roles with `AdministratorAccess`
- Inline policies with wildcard `Action` or `Resource`
- Cross-account trust misconfigurations
- Wildcard principal (`*`) in trust policies
- Weak account password policy

```python
from cloudsec_audit import IAMAnalyzer, AWSSession

analyzer = IAMAnalyzer(
    session=AWSSession(),
    key_age_threshold_days=90,
    unused_threshold_days=45,
)
findings = analyzer.run()

for f in findings:
    print(f"[{f.severity.value}] {f.title}")
    print(f"  Resource: {f.resource_id}")
    if f.attack_path:
        print(f"  Blast radius: {f.attack_path.blast_radius}")
    for step in f.remediation_steps:
        print(f"  Fix {step.order}: {step.description}")
        if step.code_snippet:
            print(f"    $ {step.code_snippet}")
```

### `NetworkExposureAuditor`

Audits security groups, NACLs, and VPC configurations.

**Detects:**
- Security groups allowing all traffic (`-1`) from `0.0.0.0/0`
- Publicly exposed sensitive ports (SSH, RDP, all database ports, Docker, Kubernetes)
- Permissive Network ACL rules
- VPCs without flow logs enabled

```python
from cloudsec_audit import NetworkExposureAuditor, AWSSession

auditor = NetworkExposureAuditor(
    session=AWSSession(),
    regions=["us-east-1", "us-west-2"],
    check_flow_logs=True,
)
findings = auditor.run()
```

### `StorageAuditor`

Audits S3 bucket security configurations.

**Detects:**
- Buckets with public ACL grants (`AllUsers`, `AuthenticatedUsers`)
- Bucket policies with `Principal: "*"`
- Missing server-side encryption (SSE-S3 or SSE-KMS)
- Disabled access logging
- Versioning not enabled
- S3 account-level public access block not fully configured

```python
from cloudsec_audit import StorageAuditor, AWSSession

auditor = StorageAuditor(
    session=AWSSession(),
    check_encryption=True,
    check_logging=True,
    check_versioning=True,
)
findings = auditor.run()
```

---

## Compliance Frameworks

`ComplianceReporter` maps findings to controls and generates audit-ready evidence:

| Framework | Controls Covered |
|-----------|-----------------|
| CIS AWS Foundations Benchmark v1.5 | IAM, S3, Networking, Logging |
| SOC 2 (CC controls) | CC6.x, CC7.x, A1.x |
| ISO 27001 | A.9, A.10, A.12, A.13 |
| HIPAA | 164.312 |
| PCI-DSS v4.0 | Requirements 1, 3, 7, 8, 10 |

```python
from cloudsec_audit import ComplianceReporter

reporter = ComplianceReporter(
    findings=findings,
    frameworks=["CIS", "SOC2", "HIPAA"],
    account_id="123456789012",
)

report_data = reporter.generate()

print(reporter.summary())
# ============================================================
#   COMPLIANCE SUMMARY — Account: 123456789012
#   Generated: 2026-04-16 10:30 UTC
# ============================================================
#   CIS           73.1%   Pass:19  Fail:5  Total:26
#   SOC2          83.3%   Pass:5   Fail:1  Total:6
#   HIPAA         75.0%   Pass:3   Fail:1  Total:4

reporter.to_json("evidence-report.json")

# List only failing controls
for ctrl in reporter.failing_controls(framework="CIS"):
    print(f"FAIL [{ctrl.control_id}] {ctrl.description}")
```

---

## Finding Schema

Every finding includes:

```python
Finding(
    finding_id="uuid",
    title="Root account MFA is not enabled",
    description="...",
    severity=Severity.CRITICAL,           # CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
    category="IAM",
    subcategory="Root Account",
    cloud_provider=CloudProvider.AWS,
    resource_id="arn:aws:iam::123456789012:root",
    resource_type="AWS::IAM::Root",
    region="global",
    account_id="123456789012",
    mitre_tactics=["Persistence", "Privilege Escalation"],
    mitre_techniques=["T1078"],
    compliance_controls={"CIS": ["1.5"], "SOC2": ["CC6.1"]},
    attack_path=AttackPath(
        steps=["Attacker obtains root credentials", "No MFA — login succeeds", "Full account takeover"],
        blast_radius="Full AWS account takeover",
        mitre_technique="T1078 — Valid Accounts",
    ),
    remediation_steps=[
        RemediationStep(order=1, description="Enable MFA for root account"),
    ],
    raw_evidence={...},                   # Raw API response for evidence
    status=FindingStatus.OPEN,
    first_seen=datetime(...),
)
```

---

## Authentication

```python
from cloudsec_audit import AWSSession

# Ambient credentials (env vars, ~/.aws/credentials, EC2/ECS instance profile)
session = AWSSession()

# Named AWS CLI profile
session = AWSSession.from_profile("prod-readonly")

# Assume an IAM role (cross-account auditing)
session = AWSSession.from_role(
    role_arn="arn:aws:iam::TARGET_ACCOUNT:role/SecurityAuditRole",
    external_id="my-external-id",   # optional, for confused deputy protection
)

# Wrap an existing boto3 session
import boto3
session = AWSSession.from_boto_session(boto3.Session(region_name="eu-west-1"))

# Validate credentials before running
session.validate()
print(f"Auditing account: {session.account_id}")
```

---

## CI/CD Integration

Add to your CI pipeline to fail builds on critical findings:

```yaml
# .github/workflows/cloud-audit.yml
name: Cloud Security Audit

on:
  schedule:
    - cron: "0 6 * * *"   # Daily at 06:00 UTC
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_AUDIT_ROLE_ARN }}
          aws-region: us-east-1

      - name: Install cloudsec-audit
        run: pip install cloudsec-audit

      - name: Run security audit
        run: |
          cloudsec-audit \
            --regions us-east-1 eu-west-1 \
            --output findings.json \
            --compliance CIS SOC2 \
            --output-compliance compliance.json
        # Exit code 1 = critical/high findings found → fails the build

      - name: Upload findings
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-findings
          path: |
            findings.json
            compliance.json
```

---

## Cross-Account Auditing

```python
from cloudsec_audit import CloudSecAudit, AWSSession

ACCOUNTS_TO_AUDIT = [
    ("arn:aws:iam::111111111111:role/SecurityAudit", "Production"),
    ("arn:aws:iam::222222222222:role/SecurityAudit", "Staging"),
    ("arn:aws:iam::333333333333:role/SecurityAudit", "Development"),
]

all_findings = []

for role_arn, account_name in ACCOUNTS_TO_AUDIT:
    print(f"Auditing {account_name}...")
    session = AWSSession.from_role(role_arn=role_arn)

    audit = CloudSecAudit(
        session=session,
        regions=["us-east-1", "eu-west-1"],
    )
    report = audit.run()
    all_findings.extend(report.findings)
    report.to_json(f"findings-{account_name.lower()}.json")

print(f"Total findings across all accounts: {len(all_findings)}")
```

---

## Roadmap

- [x] AWS — IAM
- [x] AWS — Network (Security Groups, NACLs, VPC Flow Logs)
- [x] AWS — Storage (S3)
- [ ] AWS — CloudTrail / GuardDuty configuration
- [ ] AWS — RDS, Lambda, EKS checks
- [ ] AWS — Secrets Manager / Parameter Store exposure
- [ ] GCP — IAM, GCS, Firewall Rules
- [ ] Azure — RBAC, Storage Accounts, NSGs
- [ ] Slack / PagerDuty alerting integration
- [ ] HTML dashboard report

---

## Required IAM Permissions

Create a read-only audit role with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "ec2:Describe*",
        "s3:GetBucket*",
        "s3:ListAllMyBuckets",
        "s3:GetAccountPublicAccessBlock",
        "s3control:GetPublicAccessBlock",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

AWS managed policy `SecurityAudit` also covers these permissions.

---

## License

MIT — see [LICENSE](LICENSE).