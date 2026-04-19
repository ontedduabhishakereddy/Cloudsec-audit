# Changelog

All notable changes to cloudsec-audit will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- AWS CloudTrail configuration checks
- AWS RDS public accessibility checks
- AWS Lambda function policy auditing
- AWS Secrets Manager exposure detection
- GCP IAM, GCS, and Firewall Rules support
- Azure RBAC, Storage Accounts, and NSG support
- HTML dashboard report format
- Slack and PagerDuty alerting integration

---

## [0.1.0] — 2026-04-16

### Added
- `IAMAnalyzer` — audits IAM users, roles, policies, and trust relationships
  - Root account MFA and access key checks
  - Account password policy auditing
  - Long-lived access key detection (configurable threshold)
  - Console users without MFA
  - AdministratorAccess on users and roles
  - Inline wildcard policies
  - Cross-account trust misconfiguration detection
  - Wildcard principal (`*`) in trust policies
- `NetworkExposureAuditor` — audits security groups, NACLs, and VPC configurations
  - Unrestricted ingress (all traffic from 0.0.0.0/0)
  - 30+ sensitive port definitions (databases, admin, infra)
  - IPv6 ingress checks
  - Permissive NACL rule detection
  - VPC flow log auditing
- `StorageAuditor` — audits S3 bucket security
  - Public ACL grants (AllUsers, AuthenticatedUsers)
  - Bucket policies with Principal=*
  - Server-side encryption (SSE-S3/SSE-KMS)
  - Access logging configuration
  - Versioning status
  - Account-level and bucket-level public access block
- `ComplianceReporter` — maps findings to compliance frameworks
  - CIS AWS Foundations Benchmark v1.5 (26 controls)
  - SOC 2 (6 CC controls)
  - ISO 27001 (6 A-controls)
  - HIPAA (4 §164.312 controls)
  - PCI-DSS v4.0 (6 requirements)
- `AuditReport` — aggregation and multi-format export
  - Console summary with severity breakdown
  - JSON export
  - Markdown export
  - CSV export
- `CloudSecAudit` — high-level orchestrator
- `AWSSession` — credential and session management
  - Profile, role assumption, and ambient credentials
- CLI (`cloudsec-audit`) with full flag support
- Unit tests using moto (IAM, Network, Storage)
- Integration tests (full pipeline)
- CloudFormation template for read-only audit role deployment
- GitHub Actions workflow for CI/CD integration
- Examples: full audit, cross-account audit