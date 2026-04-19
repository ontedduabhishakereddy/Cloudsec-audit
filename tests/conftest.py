"""
Shared pytest fixtures and test utilities for cloudsec-audit tests.
"""

from __future__ import annotations

import os
from typing import Any, Callable, TypeVar

# Ensure we never accidentally hit real AWS during tests
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")


# ---------------------------------------------------------------------------
# Shared moto import helper
#
# The type checker sees `mock_aws = None` as Optional[None] and then complains
# when it's used as a decorator (@mock_aws).  Instead we provide a real no-op
# callable fallback so the type is always Callable — tests are skipped at
# runtime via the `requires_moto` marker before the decorator ever fires.
# ---------------------------------------------------------------------------

F = TypeVar("F", bound=Callable[..., Any])


def _noop_decorator(fn: F) -> F:
    """No-op decorator used as fallback when moto is not installed."""
    return fn


try:
    from moto import mock_aws as _mock_aws  # type: ignore[import]
    MOTO_AVAILABLE = True
    mock_aws = _mock_aws
except ImportError:  # pragma: no cover
    MOTO_AVAILABLE = False
    mock_aws = _noop_decorator  # type: ignore[assignment]


import pytest


@pytest.fixture
def aws_credentials():
    """Mocked AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def sample_findings():
    """A mixed set of findings for reporter tests."""
    from cloudsec_audit.models.finding import (
        AttackPath,
        CloudProvider,
        Finding,
        RemediationStep,
        Severity,
    )

    return [
        Finding(
            title="Root account MFA is not enabled",
            severity=Severity.CRITICAL,
            category="IAM",
            subcategory="Root Account",
            cloud_provider=CloudProvider.AWS,
            resource_id="arn:aws:iam::123456789012:root",
            resource_type="AWS::IAM::Root",
            region="global",
            account_id="123456789012",
            mitre_techniques=["T1078"],
            compliance_controls={"CIS": ["1.5"], "SOC2": ["CC6.1"]},
            attack_path=AttackPath(
                steps=["Obtain root credentials", "No MFA — login succeeds", "Full account takeover"],
                blast_radius="Full AWS account takeover",
            ),
            remediation_steps=[RemediationStep(order=1, description="Enable root MFA")],
        ),
        Finding(
            title="Security group exposes SSH (port 22) to internet",
            severity=Severity.HIGH,
            category="Network",
            subcategory="Public Port Exposure",
            cloud_provider=CloudProvider.AWS,
            resource_id="arn:aws:ec2:us-east-1:123456789012:security-group/sg-abc123",
            resource_type="AWS::EC2::SecurityGroup",
            region="us-east-1",
            account_id="123456789012",
            compliance_controls={"CIS": ["5.2"], "SOC2": ["CC6.6"]},
        ),
        Finding(
            title="S3 bucket access logging disabled: my-bucket",
            severity=Severity.MEDIUM,
            category="Storage",
            subcategory="Logging",
            cloud_provider=CloudProvider.AWS,
            resource_id="arn:aws:s3:::my-bucket",
            resource_type="AWS::S3::Bucket",
            region="us-east-1",
            account_id="123456789012",
            compliance_controls={"CIS": ["2.1.4"], "SOC2": ["CC7.2"]},
        ),
        Finding(
            title="S3 bucket versioning disabled: my-bucket",
            severity=Severity.LOW,
            category="Storage",
            subcategory="Data Protection",
            cloud_provider=CloudProvider.AWS,
            resource_id="arn:aws:s3:::my-bucket",
            resource_type="AWS::S3::Bucket",
            region="us-east-1",
            account_id="123456789012",
            compliance_controls={"CIS": ["2.1.3"]},
        ),
    ]