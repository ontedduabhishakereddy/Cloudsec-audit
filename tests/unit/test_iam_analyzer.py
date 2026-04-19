"""
Unit tests for IAMAnalyzer using moto (AWS mock library).
"""

from __future__ import annotations

import contextlib
import json

import boto3
import pytest

# Import shared mock_aws — always a callable (no-op fallback when moto absent)
from tests.conftest import MOTO_AVAILABLE, mock_aws

import cloudsec_audit.analyzers.iam as _iam_module
from cloudsec_audit.analyzers.iam import IAMAnalyzer
from cloudsec_audit.models.finding import Severity
from cloudsec_audit.models.session import AWSSession


def requires_moto(fn):  # type: ignore[no-untyped-def]
    return pytest.mark.skipif(not MOTO_AVAILABLE, reason="moto not installed")(fn)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_admin_policy(iam_client) -> str:  # type: ignore[no-untyped-def]
    """Create AdministratorAccess in moto (it doesn't exist by default)."""
    resp = iam_client.create_policy(
        PolicyName="AdministratorAccess",
        Path="/",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )
    return str(resp["Policy"]["Arn"])


def _attach_admin_to_user(iam_client, username: str) -> str:  # type: ignore[no-untyped-def]
    arn = _create_admin_policy(iam_client)
    iam_client.attach_user_policy(UserName=username, PolicyArn=arn)
    return arn


def _attach_admin_to_role(iam_client, role_name: str) -> str:  # type: ignore[no-untyped-def]
    arn = _create_admin_policy(iam_client)
    iam_client.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    return arn


@contextlib.contextmanager  # type: ignore[misc]
def _patch_admin_arns(extra_arn: str):  # type: ignore[no-untyped-def]
    """Temporarily add extra_arn to ADMIN_POLICY_ARNS so the analyzer detects it."""
    original = _iam_module.ADMIN_POLICY_ARNS.copy()
    _iam_module.ADMIN_POLICY_ARNS.add(extra_arn)
    try:
        yield
    finally:
        _iam_module.ADMIN_POLICY_ARNS = original


# ---------------------------------------------------------------------------
# Root account checks
# ---------------------------------------------------------------------------

@requires_moto
class TestIAMAnalyzerRootChecks:

    @mock_aws
    def test_no_password_policy_creates_finding(self) -> None:
        """Missing password policy should produce a HIGH finding."""
        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        analyzer = IAMAnalyzer(session, check_root=False, check_password_policy=True)
        findings = analyzer.run()

        pw_findings = [f for f in findings if "password policy" in f.title.lower()]
        assert len(pw_findings) >= 1
        assert pw_findings[0].severity in (Severity.HIGH, Severity.MEDIUM)


# ---------------------------------------------------------------------------
# User checks
# ---------------------------------------------------------------------------

@requires_moto
class TestIAMAnalyzerUsers:

    @mock_aws
    def test_detects_admin_policy_on_user(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-admin")
        policy_arn = _attach_admin_to_user(iam, "test-admin")

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        with _patch_admin_arns(policy_arn):
            analyzer = IAMAnalyzer(session, check_root=False, check_password_policy=False)
            findings = analyzer.run()

        admin_findings = [
            f for f in findings
            if "AdministratorAccess" in f.title and "test-admin" in f.title
        ]
        assert len(admin_findings) == 1
        assert admin_findings[0].severity == Severity.CRITICAL

    @mock_aws
    def test_detects_user_without_mfa(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="console-user")
        iam.create_login_profile(UserName="console-user", Password="TempPass123!")

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        analyzer = IAMAnalyzer(session, check_root=False, check_password_policy=False)
        findings = analyzer.run()

        mfa_findings = [
            f for f in findings
            if "MFA" in f.title and "console-user" in f.title
        ]
        assert len(mfa_findings) >= 1
        assert mfa_findings[0].severity == Severity.HIGH

    @mock_aws
    def test_detects_wildcard_inline_policy(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="wildcard-user")
        iam.put_user_policy(
            UserName="wildcard-user",
            PolicyName="DangerousInline",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }),
        )

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        analyzer = IAMAnalyzer(session, check_root=False, check_password_policy=False)
        findings = analyzer.run()

        wildcard_findings = [
            f for f in findings
            if "wildcard" in f.title.lower() and "DangerousInline" in f.title
        ]
        assert len(wildcard_findings) >= 1
        assert wildcard_findings[0].severity == Severity.CRITICAL

    @mock_aws
    def test_no_findings_for_clean_user(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="service-account")

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        analyzer = IAMAnalyzer(session, check_root=False, check_password_policy=False)
        findings = analyzer.run()

        user_findings = [f for f in findings if "service-account" in f.resource_id]
        assert len(user_findings) == 0


# ---------------------------------------------------------------------------
# Role checks
# ---------------------------------------------------------------------------

@requires_moto
class TestIAMAnalyzerRoles:

    @mock_aws
    def test_detects_admin_role(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="AllPowerfulRole",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
        )
        policy_arn = _attach_admin_to_role(iam, "AllPowerfulRole")

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        with _patch_admin_arns(policy_arn):
            analyzer = IAMAnalyzer(session, check_root=False, check_password_policy=False)
            findings = analyzer.run()

        role_findings = [
            f for f in findings
            if "AdministratorAccess" in f.title and "AllPowerfulRole" in f.title
        ]
        assert len(role_findings) >= 1
        assert role_findings[0].severity == Severity.CRITICAL

    @mock_aws
    def test_detects_cross_account_trust(self) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="CrossAccountRole",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999888777666:root"},
                    "Action": "sts:AssumeRole",
                }],
            }),
        )

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        analyzer = IAMAnalyzer(session, check_root=False, check_password_policy=False)
        findings = analyzer.run()

        trust_findings = [
            f for f in findings
            if "Cross-account trust" in f.title and "CrossAccountRole" in f.title
        ]
        assert len(trust_findings) >= 1
        assert trust_findings[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Finding model unit tests (no AWS needed)
# ---------------------------------------------------------------------------

class TestFindingModel:

    def test_finding_serialization(self) -> None:
        from cloudsec_audit.models.finding import (
            AttackPath, CloudProvider, Finding, RemediationStep, Severity,
        )
        f = Finding(
            title="Test finding",
            description="A test",
            severity=Severity.HIGH,
            category="IAM",
            subcategory="Test",
            cloud_provider=CloudProvider.AWS,
            resource_id="arn:aws:iam::123:user/test",
            resource_type="AWS::IAM::User",
            region="us-east-1",
            account_id="123456789012",
            mitre_techniques=["T1078"],
            compliance_controls={"CIS": ["1.5"]},
            attack_path=AttackPath(steps=["step 1", "step 2"], blast_radius="Account takeover"),
            remediation_steps=[RemediationStep(order=1, description="Fix it")],
        )
        d = f.to_dict()
        assert d["title"] == "Test finding"
        assert d["severity"] == "HIGH"
        assert d["compliance_controls"] == {"CIS": ["1.5"]}
        assert d["attack_path"]["blast_radius"] == "Account takeover"
        assert len(d["remediation_steps"]) == 1

    def test_finding_suppress(self) -> None:
        from cloudsec_audit.models.finding import Finding, FindingStatus, Severity
        f = Finding(title="Test", severity=Severity.LOW)
        assert f.status == FindingStatus.OPEN
        f.suppress("Accepted risk")
        assert f.status == FindingStatus.SUPPRESSED
        assert f.suppression_reason == "Accepted risk"

    def test_severity_ordering(self) -> None:
        from cloudsec_audit.models.finding import Severity
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFORMATIONAL

    def test_finding_resolve(self) -> None:
        from cloudsec_audit.models.finding import Finding, FindingStatus, Severity
        f = Finding(title="Test", severity=Severity.MEDIUM)
        f.resolve()
        assert f.status == FindingStatus.RESOLVED


# ---------------------------------------------------------------------------
# AuditReport tests (no AWS needed)
# ---------------------------------------------------------------------------

class TestAuditReport:

    def _make_findings(self):  # type: ignore[no-untyped-def]
        from cloudsec_audit.models.finding import Finding, Severity
        return [
            Finding(title="Crit 1", severity=Severity.CRITICAL, category="IAM", resource_id="arn:1"),
            Finding(title="High 1", severity=Severity.HIGH, category="Network", resource_id="arn:2"),
            Finding(title="Med 1", severity=Severity.MEDIUM, category="Storage", resource_id="arn:3"),
            Finding(title="Low 1", severity=Severity.LOW, category="IAM", resource_id="arn:4"),
        ]

    def test_severity_counts(self) -> None:
        from cloudsec_audit.reporters.report import AuditReport
        report = AuditReport(self._make_findings(), account_id="123456789012")
        assert len(report.critical) == 1
        assert len(report.high) == 1
        assert len(report.medium) == 1
        assert len(report.low) == 1

    def test_sorted_by_severity(self) -> None:
        from cloudsec_audit.models.finding import Severity
        from cloudsec_audit.reporters.report import AuditReport
        report = AuditReport(self._make_findings(), account_id="123456789012")
        sorted_f = report.sorted_by_severity()
        assert sorted_f[0].severity == Severity.CRITICAL
        assert sorted_f[-1].severity == Severity.LOW

    def test_summary_contains_key_sections(self) -> None:
        from cloudsec_audit.reporters.report import AuditReport
        report = AuditReport(self._make_findings(), account_id="123456789012")
        summary = report.summary()
        assert "SEVERITY BREAKDOWN" in summary
        assert "CRITICAL" in summary
        assert "123456789012" in summary

    def test_to_dict_structure(self) -> None:
        from cloudsec_audit.reporters.report import AuditReport
        report = AuditReport(self._make_findings(), account_id="111222333444")
        d = report.to_dict()
        assert "meta" in d and "stats" in d and "findings" in d
        assert d["meta"]["account_id"] == "111222333444"
        assert d["stats"]["total"] == 4

    def test_to_json(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        import json as jsonlib
        from cloudsec_audit.reporters.report import AuditReport
        report = AuditReport(self._make_findings(), account_id="123")
        out_path = str(tmp_path / "report.json")
        report.to_json(out_path)
        with open(out_path) as fh:
            data = jsonlib.load(fh)
        assert data["stats"]["total"] == 4

    def test_to_markdown(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        from cloudsec_audit.reporters.report import AuditReport
        report = AuditReport(self._make_findings(), account_id="123")
        out_path = str(tmp_path / "report.md")
        report.to_markdown(out_path)
        with open(out_path) as fh:
            content = fh.read()
        assert "# cloudsec-audit Report" in content
        assert "CRITICAL" in content

    def test_to_csv(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        import csv
        from cloudsec_audit.reporters.report import AuditReport
        report = AuditReport(self._make_findings(), account_id="123")
        out_path = str(tmp_path / "report.csv")
        report.to_csv(out_path)
        with open(out_path) as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 4
        assert "severity" in rows[0]


# ---------------------------------------------------------------------------
# ComplianceReporter tests (no AWS needed)
# ---------------------------------------------------------------------------

class TestComplianceReporter:

    def _make_findings(self):  # type: ignore[no-untyped-def]
        from cloudsec_audit.models.finding import Finding, Severity
        return [
            Finding(title="Root no MFA", severity=Severity.CRITICAL,
                    compliance_controls={"CIS": ["1.5"], "SOC2": ["CC6.1"]}),
            Finding(title="No password policy", severity=Severity.HIGH,
                    compliance_controls={"CIS": ["1.8", "1.9"]}),
        ]

    def test_generates_report(self) -> None:
        from cloudsec_audit.reporters.compliance import ComplianceReporter
        reporter = ComplianceReporter(self._make_findings(), frameworks=["CIS", "SOC2"])
        report = reporter.generate()
        assert "CIS" in report["frameworks"]
        assert "SOC2" in report["frameworks"]
        assert report["overall"]["total_controls"] > 0

    def test_failing_controls(self) -> None:
        from cloudsec_audit.reporters.compliance import ComplianceReporter
        reporter = ComplianceReporter(self._make_findings(), frameworks=["CIS"])
        reporter.generate()
        failing = reporter.failing_controls(framework="CIS")
        assert any(c.control_id == "1.5" for c in failing)

    def test_summary_string(self) -> None:
        from cloudsec_audit.reporters.compliance import ComplianceReporter
        reporter = ComplianceReporter(self._make_findings(), frameworks=["CIS"])
        summary = reporter.summary()
        assert "CIS" in summary
        assert "COMPLIANCE SUMMARY" in summary

    def test_to_json(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        import json as jsonlib
        from cloudsec_audit.reporters.compliance import ComplianceReporter
        reporter = ComplianceReporter(self._make_findings(), frameworks=["CIS"])
        out = str(tmp_path / "compliance.json")
        reporter.to_json(out)
        with open(out) as fh:
            data = jsonlib.load(fh)
        assert "CIS" in data["frameworks"]