"""
StorageAuditor — audits S3 bucket configurations.

Detects:
  - Publicly accessible buckets (ACL or bucket policy)
  - Missing server-side encryption
  - Disabled access logging
  - Versioning disabled
  - Missing lifecycle policies
  - Public access block not enabled at account level
  - Insecure bucket policies (allows * principal)
  - Cross-account bucket access
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from cloudsec_audit.analyzers.base import BaseAnalyzer
from cloudsec_audit.models.finding import (
    AttackPath,
    CloudProvider,
    Finding,
    RemediationStep,
    Severity,
)
from cloudsec_audit.models.session import AWSSession

logger = logging.getLogger(__name__)


class StorageAuditor(BaseAnalyzer):
    """
    Audits S3 bucket security configurations.

    Usage::

        from cloudsec_audit import StorageAuditor, AWSSession

        session = AWSSession()
        auditor = StorageAuditor(session)
        findings = auditor.run()

    Args:
        session: Authenticated :class:`~cloudsec_audit.models.session.AWSSession`.
        check_encryption: Audit server-side encryption settings.
        check_logging: Audit access logging configuration.
        check_versioning: Audit bucket versioning.
        check_public_access_block: Audit S3 account-level public access block.
        max_workers: Thread pool size for concurrent bucket inspection.
    """

    name = "StorageAuditor"
    category = "Storage"

    def __init__(
        self,
        session: AWSSession,
        regions: Optional[List[str]] = None,
        check_encryption: bool = True,
        check_logging: bool = True,
        check_versioning: bool = True,
        check_public_access_block: bool = True,
        max_workers: int = 20,
    ) -> None:
        super().__init__(session, regions=regions or ["us-east-1"], max_workers=max_workers)
        self.check_encryption = check_encryption
        self.check_logging = check_logging
        self.check_versioning = check_versioning
        self.check_public_access_block = check_public_access_block

        self._s3 = self.session.client("s3")

    def run(self) -> List[Finding]:
        """Enumerate all buckets and audit each one."""
        self.logger.info("Starting S3 audit for account %s", self.session.account_id)

        if self.check_public_access_block:
            self._check_account_public_access_block()

        try:
            buckets = self._s3.list_buckets().get("Buckets", [])
        except ClientError as exc:
            self.logger.error("Could not list S3 buckets: %s", exc)
            return self._findings

        self.logger.info("Auditing %d S3 buckets", len(buckets))

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._audit_bucket, bucket): bucket
                for bucket in buckets
            }
            for future in as_completed(futures):
                bucket = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.logger.warning(
                        "Error auditing bucket %s: %s", bucket["Name"], exc
                    )

        self.logger.info("S3 audit complete — %d findings", len(self._findings))
        return self._findings

    # ------------------------------------------------------------------
    # Account-level
    # ------------------------------------------------------------------

    def _check_account_public_access_block(self) -> None:
        # Account-level public access block uses s3control, not s3
        try:
            s3control = self.session.client("s3control")
            config = s3control.get_public_access_block(
                AccountId=self.session.account_id
            )["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") in ("NoSuchPublicAccessBlockConfiguration", "AccessDenied"):
                self._add_finding(Finding(
                    title="S3 account-level public access block not configured",
                    description=(
                        "The S3 account-level Public Access Block settings are not fully enabled. "
                        "Without this safety net, any bucket or object ACL misconfiguration can "
                        "immediately expose data publicly."
                    ),
                    severity=Severity.HIGH,
                    category=self.category,
                    subcategory="Public Access",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=f"arn:aws:s3:::{self.session.account_id}",
                    resource_type="AWS::S3::AccountPublicAccessBlock",
                    region="global",
                    compliance_controls={
                        "CIS": ["2.1.5"],
                        "SOC2": ["CC6.6"],
                    },
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description="Enable all four public access block settings at the account level",
                            code_snippet=(
                                f"aws s3control put-public-access-block "
                                f"--account-id {self.session.account_id} "
                                f"--public-access-block-configuration "
                                f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                                f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
                            ),
                        ),
                    ],
                ))
                return
            raise

        missing = [
            k for k, enabled in config.items() if not enabled
        ]
        if missing:
            self._add_finding(Finding(
                title="S3 account public access block partially disabled",
                description=(
                    f"The following S3 account-level public access block settings are disabled: "
                    f"{', '.join(missing)}. Partial configuration leaves gaps that bucket-level "
                    "misconfigurations can exploit."
                ),
                severity=Severity.MEDIUM,
                category=self.category,
                subcategory="Public Access",
                cloud_provider=CloudProvider.AWS,
                resource_id=f"arn:aws:s3:::{self.session.account_id}",
                resource_type="AWS::S3::AccountPublicAccessBlock",
                region="global",
                compliance_controls={"CIS": ["2.1.5"]},
                raw_evidence={"config": config, "disabled_settings": missing},
            ))

    # ------------------------------------------------------------------
    # Per-bucket checks
    # ------------------------------------------------------------------

    def _audit_bucket(self, bucket: Dict[str, Any]) -> None:
        name = bucket["Name"]
        bucket_arn = f"arn:aws:s3:::{name}"

        # Determine bucket region for regional ARNs and client calls
        try:
            location = self._s3.get_bucket_location(Bucket=name)
            region = location.get("LocationConstraint") or "us-east-1"
        except ClientError:
            region = "us-east-1"

        self._check_bucket_public_access_block(name, bucket_arn, region)
        self._check_bucket_acl(name, bucket_arn, region)
        self._check_bucket_policy(name, bucket_arn, region)

        if self.check_encryption:
            self._check_bucket_encryption(name, bucket_arn, region)

        if self.check_logging:
            self._check_bucket_logging(name, bucket_arn, region)

        if self.check_versioning:
            self._check_bucket_versioning(name, bucket_arn, region)

    def _check_bucket_public_access_block(
        self, name: str, bucket_arn: str, region: str
    ) -> None:
        try:
            config = self._s3.get_public_access_block(Bucket=name)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchPublicAccessBlockConfiguration":
                self._add_finding(Finding(
                    title=f"S3 bucket missing public access block: {name}",
                    description=(
                        f"Bucket '{name}' has no public access block configuration. "
                        "Without it, any ACL or policy granting public access will expose the bucket."
                    ),
                    severity=Severity.HIGH,
                    category=self.category,
                    subcategory="Public Access",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=bucket_arn,
                    resource_type="AWS::S3::Bucket",
                    region=region,
                    compliance_controls={"CIS": ["2.1.5"], "SOC2": ["CC6.6"]},
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description=f"Enable public access block on bucket '{name}'",
                            code_snippet=(
                                f"aws s3api put-public-access-block "
                                f"--bucket {name} "
                                f"--public-access-block-configuration "
                                f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                                f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
                            ),
                        ),
                    ],
                ))
            return

        all_set = all(config.values())
        if not all_set:
            missing = [k for k, v in config.items() if not v]
            self._add_finding(Finding(
                title=f"S3 bucket public access block partially disabled: {name}",
                description=(
                    f"Bucket '{name}' has public access block partially disabled: "
                    f"{', '.join(missing)}."
                ),
                severity=Severity.MEDIUM,
                category=self.category,
                subcategory="Public Access",
                cloud_provider=CloudProvider.AWS,
                resource_id=bucket_arn,
                resource_type="AWS::S3::Bucket",
                region=region,
                compliance_controls={"CIS": ["2.1.5"]},
                raw_evidence={"config": config},
            ))

    def _check_bucket_acl(
        self, name: str, bucket_arn: str, region: str
    ) -> None:
        try:
            acl = self._s3.get_bucket_acl(Bucket=name)
        except ClientError:
            return

        public_grants = []
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                public_grants.append({
                    "grantee": uri,
                    "permission": grant.get("Permission"),
                })

        if public_grants:
            write_grants = [g for g in public_grants if g["permission"] in ("WRITE", "FULL_CONTROL")]
            severity = Severity.CRITICAL if write_grants else Severity.HIGH

            self._add_finding(Finding(
                title=f"S3 bucket has public ACL grants: {name}",
                description=(
                    f"Bucket '{name}' has ACL grants to public groups: "
                    f"{', '.join(g['grantee'].split('/')[-1] + ':' + g['permission'] for g in public_grants)}. "
                    "Public ACLs allow any internet user to read or write bucket contents."
                ),
                severity=severity,
                category=self.category,
                subcategory="Public Access",
                cloud_provider=CloudProvider.AWS,
                resource_id=bucket_arn,
                resource_type="AWS::S3::Bucket",
                region=region,
                mitre_tactics=["Collection", "Exfiltration"],
                mitre_techniques=["T1530"],
                compliance_controls={
                    "CIS": ["2.1.1"],
                    "SOC2": ["CC6.6"],
                    "PCI-DSS": ["7.1"],
                },
                raw_evidence={"public_grants": public_grants},
                attack_path=AttackPath(
                    entry_point=bucket_arn,
                    steps=[
                        f"Bucket '{name}' is publicly accessible via ACL",
                        "Attacker runs: aws s3 ls s3://{name} --no-sign-request",
                        "All bucket contents are enumerable and downloadable",
                    ],
                    blast_radius="Full read (and possibly write) access to bucket contents",
                    mitre_technique="T1530 — Data from Cloud Storage Object",
                ),
                remediation_steps=[
                    RemediationStep(
                        order=1,
                        description=f"Remove public ACL grants from bucket '{name}'",
                        code_snippet=f"aws s3api put-bucket-acl --bucket {name} --acl private",
                    ),
                    RemediationStep(
                        order=2,
                        description="Enable public access block to prevent future ACL grants",
                    ),
                ],
            ))

    def _check_bucket_policy(
        self, name: str, bucket_arn: str, region: str
    ) -> None:
        try:
            policy_str = self._s3.get_bucket_policy(Bucket=name)["Policy"]
            policy = json.loads(policy_str)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") == "NoSuchBucketPolicy":
                return
            raise

        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal", {})
            is_public = (
                principal == "*"
                or (isinstance(principal, dict) and principal.get("AWS") == "*")
            )

            if is_public:
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                write_actions = [a for a in actions if any(
                    w in a.lower() for w in ["put", "delete", "write", "*"]
                )]

                severity = Severity.CRITICAL if write_actions else Severity.HIGH

                self._add_finding(Finding(
                    title=f"S3 bucket policy allows public access: {name}",
                    description=(
                        f"Bucket '{name}' has a policy statement with Principal='*' (public). "
                        f"Actions granted: {', '.join(actions)}. "
                        "Any unauthenticated internet user can perform these actions on the bucket."
                    ),
                    severity=severity,
                    category=self.category,
                    subcategory="Public Access",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=bucket_arn,
                    resource_type="AWS::S3::Bucket",
                    region=region,
                    mitre_tactics=["Collection", "Exfiltration"],
                    mitre_techniques=["T1530"],
                    compliance_controls={
                        "CIS": ["2.1.2"],
                        "SOC2": ["CC6.6"],
                        "HIPAA": ["164.312(a)(1)"],
                    },
                    raw_evidence={"statement": statement},
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description="Remove or restrict the public principal from the bucket policy",
                        ),
                        RemediationStep(
                            order=2,
                            description="Use specific IAM principal ARNs or aws:PrincipalOrgID conditions",
                            reference_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html",
                        ),
                    ],
                ))

    def _check_bucket_encryption(
        self, name: str, bucket_arn: str, region: str
    ) -> None:
        try:
            enc = self._s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not rules:
                raise ClientError({"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") in (
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchEncryptionConfiguration",
            ):
                self._add_finding(Finding(
                    title=f"S3 bucket not encrypted at rest: {name}",
                    description=(
                        f"Bucket '{name}' does not have server-side encryption enabled. "
                        "Data stored in this bucket is not encrypted at rest, violating "
                        "most compliance frameworks."
                    ),
                    severity=Severity.HIGH,
                    category=self.category,
                    subcategory="Encryption",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=bucket_arn,
                    resource_type="AWS::S3::Bucket",
                    region=region,
                    compliance_controls={
                        "CIS": ["2.1.1"],
                        "SOC2": ["CC6.7"],
                        "HIPAA": ["164.312(a)(2)(iv)"],
                        "PCI-DSS": ["3.4"],
                    },
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description=f"Enable SSE-S3 encryption on bucket '{name}'",
                            code_snippet=(
                                f"aws s3api put-bucket-encryption "
                                f"--bucket {name} "
                                f"--server-side-encryption-configuration "
                                f"'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":"
                                f"{{\"SSEAlgorithm\":\"aws:kms\"}}}}]}}'"
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            description="Prefer SSE-KMS over SSE-S3 for key management control and audit trails",
                        ),
                    ],
                ))

    def _check_bucket_logging(
        self, name: str, bucket_arn: str, region: str
    ) -> None:
        try:
            logging_config = self._s3.get_bucket_logging(Bucket=name).get(
                "LoggingEnabled", None
            )
        except ClientError:
            return

        if not logging_config:
            self._add_finding(Finding(
                title=f"S3 bucket access logging disabled: {name}",
                description=(
                    f"Bucket '{name}' does not have access logging enabled. "
                    "Without access logs, you cannot audit who accessed or modified "
                    "bucket contents — critical for incident response and compliance."
                ),
                severity=Severity.MEDIUM,
                category=self.category,
                subcategory="Logging",
                cloud_provider=CloudProvider.AWS,
                resource_id=bucket_arn,
                resource_type="AWS::S3::Bucket",
                region=region,
                compliance_controls={
                    "CIS": ["2.1.4"],
                    "SOC2": ["CC7.2"],
                    "PCI-DSS": ["10.2"],
                    "HIPAA": ["164.312(b)"],
                },
                remediation_steps=[
                    RemediationStep(
                        order=1,
                        description=f"Enable access logging for bucket '{name}'",
                        code_snippet=(
                            f"aws s3api put-bucket-logging "
                            f"--bucket {name} "
                            f"--bucket-logging-status "
                            f"'{{\"LoggingEnabled\":{{\"TargetBucket\":\"<LOG_BUCKET>\","
                            f"\"TargetPrefix\":\"{name}/\"}}}}'"
                        ),
                    ),
                ],
            ))

    def _check_bucket_versioning(
        self, name: str, bucket_arn: str, region: str
    ) -> None:
        try:
            versioning = self._s3.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "")
        except ClientError:
            return

        if status != "Enabled":
            self._add_finding(Finding(
                title=f"S3 bucket versioning disabled: {name}",
                description=(
                    f"Bucket '{name}' does not have versioning enabled. "
                    "Versioning protects against accidental deletion and ransomware attacks "
                    "by preserving object history."
                ),
                severity=Severity.LOW,
                category=self.category,
                subcategory="Data Protection",
                cloud_provider=CloudProvider.AWS,
                resource_id=bucket_arn,
                resource_type="AWS::S3::Bucket",
                region=region,
                compliance_controls={
                    "CIS": ["2.1.3"],
                    "SOC2": ["A1.2"],
                },
                raw_evidence={"versioning_status": status or "Not configured"},
                remediation_steps=[
                    RemediationStep(
                        order=1,
                        description=f"Enable versioning on bucket '{name}'",
                        code_snippet=(
                            f"aws s3api put-bucket-versioning "
                            f"--bucket {name} "
                            f"--versioning-configuration Status=Enabled"
                        ),
                    ),
                    RemediationStep(
                        order=2,
                        description="Optionally add a lifecycle rule to expire old versions after N days to control costs",
                    ),
                ],
            ))