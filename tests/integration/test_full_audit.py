"""
Integration tests — full orchestrator pipeline against a mocked AWS environment.
"""

from __future__ import annotations

import contextlib
import json

import boto3
import pytest

from tests.conftest import MOTO_AVAILABLE, mock_aws

import cloudsec_audit.analyzers.iam as _iam_module
from cloudsec_audit import CloudSecAudit, AWSSession

pytestmark = pytest.mark.skipif(not MOTO_AVAILABLE, reason="moto not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_admin_policy(iam_client) -> str:  # type: ignore[no-untyped-def]
    resp = iam_client.create_policy(
        PolicyName="AdministratorAccess",
        Path="/",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )
    return str(resp["Policy"]["Arn"])


@contextlib.contextmanager  # type: ignore[misc]
def _patch_admin_arns(extra_arn: str):  # type: ignore[no-untyped-def]
    original = _iam_module.ADMIN_POLICY_ARNS.copy()
    _iam_module.ADMIN_POLICY_ARNS.add(extra_arn)
    try:
        yield
    finally:
        _iam_module.ADMIN_POLICY_ARNS = original


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@mock_aws
def test_full_audit_pipeline_produces_report() -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="admin-user")
    policy_arn = _create_admin_policy(iam)
    iam.attach_user_policy(UserName="admin-user", PolicyArn=policy_arn)

    session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
    with _patch_admin_arns(policy_arn):
        audit = CloudSecAudit(
            session=session, regions=["us-east-1"],
            run_iam=True, run_network=False, run_storage=False,
        )
        report = audit.run()

    assert report is not None
    assert len(report.findings) > 0
    assert len(report.critical) > 0 or len(report.high) > 0
    assert "cloudsec-audit" in report.summary()


@mock_aws
def test_compliance_report_after_audit() -> None:
    session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
    audit = CloudSecAudit(
        session=session, regions=["us-east-1"],
        run_iam=True, run_network=False, run_storage=False,
    )
    audit.run()

    compliance = audit.compliance_report(frameworks=["CIS", "SOC2"])
    assert compliance is not None
    summary = compliance.summary()
    assert "CIS" in summary
    assert "SOC2" in summary


@mock_aws
def test_report_json_serializable() -> None:
    session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
    audit = CloudSecAudit(
        session=session, regions=["us-east-1"],
        run_iam=True, run_network=False, run_storage=False,
    )
    report = audit.run()
    parsed = json.loads(json.dumps(report.to_dict(), default=str))
    assert "findings" in parsed
    assert "stats" in parsed


@mock_aws
def test_audit_without_findings_for_clean_env() -> None:
    session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
    audit = CloudSecAudit(
        session=session, regions=["us-east-1"],
        run_iam=True, run_network=False, run_storage=False,
        iam_kwargs={"check_root": False, "check_password_policy": False},
    )
    report = audit.run()
    assert report is not None
    assert report.scan_duration_seconds is not None
    assert report.scan_duration_seconds >= 0


@mock_aws
def test_multi_analyzer_findings_aggregated() -> None:
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-multi-bucket")

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="multi-test-user")
    policy_arn = _create_admin_policy(iam)
    iam.attach_user_policy(UserName="multi-test-user", PolicyArn=policy_arn)

    session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
    with _patch_admin_arns(policy_arn):
        audit = CloudSecAudit(
            session=session, regions=["us-east-1"],
            run_iam=True, run_network=False, run_storage=True,
            iam_kwargs={"check_root": False, "check_password_policy": False},
            storage_kwargs={"check_public_access_block": False},
        )
        report = audit.run()

    iam_findings = [f for f in report.findings if f.category == "IAM"]
    storage_findings = [f for f in report.findings if f.category == "Storage"]

    assert len(iam_findings) > 0
    assert len(storage_findings) > 0
    assert len(report.findings) == len(iam_findings) + len(storage_findings)