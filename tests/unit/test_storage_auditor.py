"""
Unit tests for StorageAuditor using moto.
"""

from __future__ import annotations

import json

import boto3
import pytest

from tests.conftest import MOTO_AVAILABLE, mock_aws

from cloudsec_audit.analyzers.storage import StorageAuditor
from cloudsec_audit.models.finding import Severity
from cloudsec_audit.models.session import AWSSession


def requires_moto(fn):  # type: ignore[no-untyped-def]
    return pytest.mark.skipif(not MOTO_AVAILABLE, reason="moto not installed")(fn)


@requires_moto
class TestStorageAuditor:

    @mock_aws
    def test_detects_public_acl(self) -> None:
        """Bucket with public ACL should produce HIGH or CRITICAL finding."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-public-bucket")
        s3.delete_public_access_block(Bucket="test-public-bucket")
        s3.put_bucket_acl(Bucket="test-public-bucket", ACL="public-read")

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = StorageAuditor(
            session,
            check_encryption=False,
            check_logging=False,
            check_versioning=False,
            check_public_access_block=False,
        )
        findings = auditor.run()

        acl_findings = [
            f for f in findings
            if "public ACL" in f.title and "test-public-bucket" in f.title
        ]
        assert len(acl_findings) >= 1
        assert acl_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    @mock_aws
    def test_detects_missing_encryption(self) -> None:
        """Bucket without encryption should produce HIGH finding."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="unencrypted-bucket")

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = StorageAuditor(
            session,
            check_encryption=True,
            check_logging=False,
            check_versioning=False,
            check_public_access_block=False,
        )
        findings = auditor.run()

        enc_findings = [
            f for f in findings
            if "not encrypted" in f.title and "unencrypted-bucket" in f.title
        ]
        assert len(enc_findings) >= 1
        assert enc_findings[0].severity == Severity.HIGH

    @mock_aws
    def test_detects_missing_access_logging(self) -> None:
        """Bucket without access logging should produce MEDIUM finding."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="no-logging-bucket")

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = StorageAuditor(
            session,
            check_encryption=False,
            check_logging=True,
            check_versioning=False,
            check_public_access_block=False,
        )
        findings = auditor.run()

        log_findings = [
            f for f in findings
            if "logging disabled" in f.title and "no-logging-bucket" in f.title
        ]
        assert len(log_findings) >= 1
        assert log_findings[0].severity == Severity.MEDIUM

    @mock_aws
    def test_detects_versioning_disabled(self) -> None:
        """Bucket without versioning should produce LOW finding."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="no-versioning-bucket")

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = StorageAuditor(
            session,
            check_encryption=False,
            check_logging=False,
            check_versioning=True,
            check_public_access_block=False,
        )
        findings = auditor.run()

        ver_findings = [
            f for f in findings
            if "versioning disabled" in f.title and "no-versioning-bucket" in f.title
        ]
        assert len(ver_findings) >= 1
        assert ver_findings[0].severity == Severity.LOW

    @mock_aws
    def test_detects_public_bucket_policy(self) -> None:
        """Bucket policy with Principal=* should produce HIGH/CRITICAL finding."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="policy-public-bucket")
        s3.delete_public_access_block(Bucket="policy-public-bucket")

        public_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::policy-public-bucket/*",
            }],
        })
        s3.put_bucket_policy(Bucket="policy-public-bucket", Policy=public_policy)

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = StorageAuditor(
            session,
            check_encryption=False,
            check_logging=False,
            check_versioning=False,
            check_public_access_block=False,
        )
        findings = auditor.run()

        policy_findings = [
            f for f in findings
            if "policy allows public access" in f.title and "policy-public-bucket" in f.title
        ]
        assert len(policy_findings) >= 1

    @mock_aws
    def test_clean_bucket_with_encryption_and_logging(self) -> None:
        """Well-configured bucket should produce no encryption, logging, or versioning findings."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="secure-bucket")

        # Enable encryption
        s3.put_bucket_encryption(
            Bucket="secure-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )

        # Enable versioning
        s3.put_bucket_versioning(
            Bucket="secure-bucket",
            VersioningConfiguration={"Status": "Enabled"},
        )

        # Enable logging — moto requires log-delivery group ACL on the target bucket first
        s3.create_bucket(Bucket="log-bucket")
        s3.put_bucket_acl(
            Bucket="log-bucket",
            GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
            GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        )
        s3.put_bucket_logging(
            Bucket="secure-bucket",
            BucketLoggingStatus={
                "LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "logs/"}
            },
        )

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = StorageAuditor(
            session,
            check_encryption=True,
            check_logging=True,
            check_versioning=True,
            check_public_access_block=False,
        )
        findings = auditor.run()

        # Filter to only secure-bucket findings
        bucket_findings = [f for f in findings if "secure-bucket" in f.title]

        enc = [f for f in bucket_findings if "encrypt" in f.title.lower()]
        log = [f for f in bucket_findings if "logging" in f.title.lower()]
        ver = [f for f in bucket_findings if "versioning" in f.title.lower()]

        assert len(enc) == 0, f"Unexpected encryption findings: {[f.title for f in enc]}"
        assert len(log) == 0, f"Unexpected logging findings: {[f.title for f in log]}"
        assert len(ver) == 0, f"Unexpected versioning findings: {[f.title for f in ver]}"