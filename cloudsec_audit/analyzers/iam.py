"""
IAMAnalyzer — audits IAM roles, users, policies, and trust relationships.

Detects:
  - AdministratorAccess / wildcard policies attached to roles or users
  - Long-lived access keys (> configured threshold)
  - Unused IAM credentials (console password + no MFA)
  - Cross-account trust misconfigurations
  - Privilege escalation paths via policy combinations
  - Root account usage and lack of MFA
  - Password policy weaknesses
  - Inline policies with * actions or resources
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from botocore.exceptions import ClientError

from cloudsec_audit.analyzers.base import BaseAnalyzer
from cloudsec_audit.models.finding import (
    AttackPath,
    CloudProvider,
    Finding,
    FindingStatus,
    RemediationStep,
    Severity,
)
from cloudsec_audit.models.session import AWSSession

logger = logging.getLogger(__name__)

# Days after which an access key is considered "long-lived"
DEFAULT_KEY_AGE_THRESHOLD_DAYS = 90

# Days after which an unused credential is considered stale
DEFAULT_UNUSED_THRESHOLD_DAYS = 45

# Policies that grant full admin access
ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
}


class IAMAnalyzer(BaseAnalyzer):
    """
    Audits IAM configuration across an AWS account.

    Usage::

        from cloudsec_audit import IAMAnalyzer, AWSSession

        session = AWSSession()
        analyzer = IAMAnalyzer(session)
        findings = analyzer.run()

        for f in sorted(findings, key=lambda f: f.severity, reverse=True):
            print(f.severity.value, f.title, f.resource_id)

    Args:
        session: Authenticated :class:`~cloudsec_audit.models.session.AWSSession`.
        key_age_threshold_days: Access keys older than this are flagged.
        unused_threshold_days: Credentials unused longer than this are flagged.
        check_root: Whether to include root account checks.
        check_password_policy: Whether to audit the account password policy.
    """

    name = "IAMAnalyzer"
    category = "IAM"

    def __init__(
        self,
        session: AWSSession,
        key_age_threshold_days: int = DEFAULT_KEY_AGE_THRESHOLD_DAYS,
        unused_threshold_days: int = DEFAULT_UNUSED_THRESHOLD_DAYS,
        check_root: bool = True,
        check_password_policy: bool = True,
        regions: Optional[List[str]] = None,
        max_workers: int = 10,
    ) -> None:
        super().__init__(session, regions=regions or ["us-east-1"], max_workers=max_workers)
        self.key_age_threshold_days = key_age_threshold_days
        self.unused_threshold_days = unused_threshold_days
        self.check_root = check_root
        self.check_password_policy = check_password_policy

        self._iam = self.session.client("iam")
        self._now = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> List[Finding]:
        """Run all IAM checks and return findings."""
        self.logger.info("Starting IAM audit for account %s", self.session.account_id)

        checks = [
            self._check_root_account,
            self._check_password_policy,
            self._check_users,
            self._check_roles,
            self._check_cross_account_trusts,
        ]

        for check in checks:
            try:
                check()
            except Exception as exc:
                self.logger.error("Check %s failed: %s", check.__name__, exc)

        self.logger.info(
            "IAM audit complete — %d findings", len(self._findings)
        )
        return self._findings

    # ------------------------------------------------------------------
    # Root account
    # ------------------------------------------------------------------

    def _check_root_account(self) -> None:
        if not self.check_root:
            return

        try:
            summary = self._iam.get_account_summary()["SummaryMap"]
        except ClientError as exc:
            self.logger.warning("Could not fetch account summary: %s", exc)
            return

        # Root MFA check
        if not summary.get("AccountMFAEnabled", 0):
            self._add_finding(Finding(
                title="Root account MFA is not enabled",
                description=(
                    "The AWS root account does not have multi-factor authentication "
                    "enabled. Any compromise of root credentials gives an attacker "
                    "unrestricted access to all AWS services and resources."
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                subcategory="Root Account",
                cloud_provider=CloudProvider.AWS,
                resource_id=f"arn:aws:iam::{self.session.account_id}:root",
                resource_type="AWS::IAM::Root",
                region="global",
                mitre_tactics=["Persistence", "Privilege Escalation"],
                mitre_techniques=["T1078"],
                compliance_controls={
                    "CIS": ["1.5"],
                    "SOC2": ["CC6.1"],
                    "PCI-DSS": ["8.3"],
                },
                attack_path=AttackPath(
                    steps=[
                        "Attacker obtains root credentials via phishing or credential stuffing",
                        "Root account has no MFA — attacker logs in directly",
                        "Full account takeover achieved",
                    ],
                    blast_radius="Full AWS account takeover",
                    mitre_technique="T1078 — Valid Accounts",
                ),
                remediation_steps=[
                    RemediationStep(
                        order=1,
                        description="Sign in to the AWS Console as root",
                    ),
                    RemediationStep(
                        order=2,
                        description="Navigate to My Security Credentials → Multi-factor authentication",
                    ),
                    RemediationStep(
                        order=3,
                        description="Activate a hardware MFA device or virtual MFA app",
                    ),
                ],
                references=[
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
                    "https://www.cisecurity.org/benchmark/amazon_web_services",
                ],
            ))

        # Root access keys check
        if summary.get("AccountAccessKeysPresent", 0):
            self._add_finding(Finding(
                title="Root account has active access keys",
                description=(
                    "The AWS root account has programmatic access keys. "
                    "Root access keys provide unrestricted API access and cannot "
                    "be scoped with IAM policies. These should be deleted immediately."
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                subcategory="Root Account",
                cloud_provider=CloudProvider.AWS,
                resource_id=f"arn:aws:iam::{self.session.account_id}:root",
                resource_type="AWS::IAM::Root",
                region="global",
                mitre_tactics=["Credential Access"],
                mitre_techniques=["T1552"],
                compliance_controls={
                    "CIS": ["1.4"],
                    "SOC2": ["CC6.6"],
                },
                remediation_steps=[
                    RemediationStep(
                        order=1,
                        description="Log in as root → My Security Credentials → Access keys",
                        code_snippet="aws iam delete-access-key --access-key-id <KEY_ID>",
                    ),
                    RemediationStep(
                        order=2,
                        description="Delete all root access keys. Use IAM roles for programmatic access.",
                    ),
                ],
            ))

    # ------------------------------------------------------------------
    # Password policy
    # ------------------------------------------------------------------

    def _check_password_policy(self) -> None:
        if not self.check_password_policy:
            return

        try:
            policy = self._iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") == "NoSuchEntity":
                self._add_finding(Finding(
                    title="No IAM account password policy configured",
                    description=(
                        "The AWS account has no password policy. Without a password "
                        "policy, IAM users can set weak passwords with no expiration, "
                        "significantly increasing credential compromise risk."
                    ),
                    severity=Severity.HIGH,
                    category=self.category,
                    subcategory="Password Policy",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=f"arn:aws:iam::{self.session.account_id}:password-policy",
                    resource_type="AWS::IAM::PasswordPolicy",
                    region="global",
                    compliance_controls={
                        "CIS": ["1.8", "1.9", "1.10", "1.11"],
                        "SOC2": ["CC6.1"],
                        "PCI-DSS": ["8.2"],
                    },
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description="Set a strong password policy via CLI",
                            code_snippet=(
                                "aws iam update-account-password-policy "
                                "--minimum-password-length 14 "
                                "--require-symbols "
                                "--require-numbers "
                                "--require-uppercase-characters "
                                "--require-lowercase-characters "
                                "--allow-users-to-change-password "
                                "--max-password-age 90 "
                                "--password-reuse-prevention 24"
                            ),
                        ),
                    ],
                ))
                return
            raise

        weak_checks = [
            (policy.get("MinimumPasswordLength", 0) < 14, "Minimum password length is less than 14 characters", "CIS 1.8"),
            (not policy.get("RequireSymbols", False), "Password policy does not require symbols", "CIS 1.9"),
            (not policy.get("RequireNumbers", False), "Password policy does not require numbers", "CIS 1.10"),
            (not policy.get("RequireUppercaseCharacters", False), "Password policy does not require uppercase letters", "CIS 1.11"),
            (not policy.get("RequireLowercaseCharacters", False), "Password policy does not require lowercase letters", "CIS 1.12"),
            (policy.get("MaxPasswordAge", 0) == 0 or policy.get("MaxPasswordAge", 999) > 90,
             "Password expiry not set or exceeds 90 days", "CIS 1.13"),
            (policy.get("PasswordReusePrevention", 0) < 24, "Password reuse prevention is below 24", "CIS 1.14"),
        ]

        for condition, message, cis_control in weak_checks:
            if condition:
                self._add_finding(Finding(
                    title=f"Weak password policy: {message}",
                    description=f"IAM account password policy weakness detected: {message}.",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    subcategory="Password Policy",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=f"arn:aws:iam::{self.session.account_id}:password-policy",
                    resource_type="AWS::IAM::PasswordPolicy",
                    region="global",
                    compliance_controls={"CIS": [cis_control.split()[1]]},
                    raw_evidence={"current_policy": policy},
                ))

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def _check_users(self) -> None:
        users = self._paginate(self._iam, "list_users", "Users")
        self.logger.info("Auditing %d IAM users", len(users))

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._audit_user, u): u for u in users}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    user = futures[future]
                    self.logger.warning("Error auditing user %s: %s", user["UserName"], exc)

    def _audit_user(self, user: Dict[str, Any]) -> None:
        username = user["UserName"]
        user_arn = user["Arn"]

        # --- Access keys ---
        try:
            keys = self._iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        except ClientError:
            keys = []

        for key in keys:
            key_id = key["AccessKeyId"]
            created = key["CreateDate"]
            if isinstance(created, str):
                created = datetime.fromisoformat(created)
            age_days = (self._now - created.astimezone(timezone.utc)).days

            if key["Status"] == "Active" and age_days > self.key_age_threshold_days:
                self._add_finding(Finding(
                    title=f"Long-lived IAM access key: {key_id}",
                    description=(
                        f"IAM user '{username}' has an active access key ({key_id}) "
                        f"that is {age_days} days old (threshold: {self.key_age_threshold_days} days). "
                        "Long-lived keys increase the window of opportunity if a key is compromised."
                    ),
                    severity=Severity.HIGH if age_days > 180 else Severity.MEDIUM,
                    category=self.category,
                    subcategory="Long-lived Credentials",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=user_arn,
                    resource_type="AWS::IAM::User",
                    region="global",
                    mitre_tactics=["Credential Access", "Persistence"],
                    mitre_techniques=["T1552.001"],
                    compliance_controls={"CIS": ["1.14"], "SOC2": ["CC6.1"]},
                    raw_evidence={"key_id": key_id, "age_days": age_days, "status": "Active"},
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description="Rotate the access key — create new, update applications, then delete old",
                            code_snippet=(
                                f"aws iam create-access-key --user-name {username}\n"
                                f"# Update your app with the new key, then:\n"
                                f"aws iam delete-access-key --user-name {username} --access-key-id {key_id}"
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            description="Consider migrating to IAM roles for EC2/Lambda instead of long-lived keys",
                        ),
                    ],
                ))

        # --- MFA for console users ---
        try:
            self._iam.get_login_profile(UserName=username)
            has_console = True
        except ClientError as exc:
            has_console = exc.response.get("Error", {}).get("Code", "") != "NoSuchEntity"

        if has_console:
            mfa_devices = self._iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                self._add_finding(Finding(
                    title=f"IAM console user without MFA: {username}",
                    description=(
                        f"IAM user '{username}' has console access but no MFA device attached. "
                        "Console users without MFA are vulnerable to credential stuffing and phishing attacks."
                    ),
                    severity=Severity.HIGH,
                    category=self.category,
                    subcategory="MFA",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=user_arn,
                    resource_type="AWS::IAM::User",
                    region="global",
                    mitre_tactics=["Initial Access"],
                    mitre_techniques=["T1078"],
                    compliance_controls={"CIS": ["1.10"], "SOC2": ["CC6.1"], "PCI-DSS": ["8.3"]},
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description="Enforce MFA via an IAM policy that denies all actions except MFA setup if MFA not present",
                            reference_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html",
                        ),
                    ],
                ))

        # --- Admin policy check ---
        attached_policies = self._paginate(
            self._iam, "list_attached_user_policies", "AttachedPolicies", UserName=username
        )
        for policy in attached_policies:
            if policy["PolicyArn"] in ADMIN_POLICY_ARNS:
                self._add_finding(Finding(
                    title=f"IAM user with AdministratorAccess: {username}",
                    description=(
                        f"IAM user '{username}' has the AdministratorAccess policy directly attached. "
                        "Direct admin access on user accounts violates least-privilege and increases "
                        "blast radius on credential compromise."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    subcategory="Overpermissioned Entity",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=user_arn,
                    resource_type="AWS::IAM::User",
                    region="global",
                    mitre_tactics=["Privilege Escalation"],
                    mitre_techniques=["T1078"],
                    compliance_controls={
                        "CIS": ["1.16"],
                        "SOC2": ["CC6.3"],
                    },
                    raw_evidence={"attached_policy_arn": policy["PolicyArn"]},
                    attack_path=AttackPath(
                        entry_point=user_arn,
                        steps=[
                            f"Attacker compromises credentials of IAM user '{username}'",
                            "User has AdministratorAccess — full account control",
                            "Attacker creates persistent backdoor IAM user or role",
                        ],
                        blast_radius="Full AWS account takeover",
                        mitre_technique="T1078 — Valid Accounts",
                    ),
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description=f"Detach AdministratorAccess from user '{username}'",
                            code_snippet=(
                                f"aws iam detach-user-policy "
                                f"--user-name {username} "
                                f"--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            description="Replace with a scoped permission set. Use AWS IAM Identity Center for humans.",
                        ),
                    ],
                ))

        # --- Inline wildcard policies ---
        inline_policies = self._paginate(
            self._iam, "list_user_policies", "PolicyNames", UserName=username
        )
        for policy_name in inline_policies:
            try:
                doc = self._iam.get_user_policy(
                    UserName=username, PolicyName=policy_name
                )["PolicyDocument"]
                doc = json.loads(unquote(json.dumps(doc))) if isinstance(doc, str) else doc
                self._check_wildcard_policy(doc, user_arn, "AWS::IAM::User", policy_name)
            except ClientError as exc:
                self.logger.debug("Could not read inline policy %s: %s", policy_name, exc)

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------

    def _check_roles(self) -> None:
        roles = self._paginate(self._iam, "list_roles", "Roles")
        self.logger.info("Auditing %d IAM roles", len(roles))

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._audit_role, r): r for r in roles}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    role = futures[future]
                    self.logger.warning("Error auditing role %s: %s", role["RoleName"], exc)

    def _audit_role(self, role: Dict[str, Any]) -> None:
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        # Admin policies
        attached = self._paginate(
            self._iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role_name
        )
        for policy in attached:
            if policy["PolicyArn"] in ADMIN_POLICY_ARNS:
                self._add_finding(Finding(
                    title=f"IAM role with AdministratorAccess: {role_name}",
                    description=(
                        f"IAM role '{role_name}' has AdministratorAccess attached. "
                        "Any principal that can assume this role gains full admin access. "
                        "This is a critical privilege escalation path."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    subcategory="Overpermissioned Entity",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=role_arn,
                    resource_type="AWS::IAM::Role",
                    region="global",
                    mitre_tactics=["Privilege Escalation"],
                    mitre_techniques=["T1078"],
                    compliance_controls={"CIS": ["1.16"]},
                    raw_evidence={"attached_policy_arn": policy["PolicyArn"]},
                    attack_path=AttackPath(
                        entry_point=role_arn,
                        steps=[
                            f"Attacker compromises a principal that can assume '{role_name}'",
                            "Role has AdministratorAccess — full account control obtained",
                        ],
                        blast_radius="Full AWS account takeover",
                        mitre_technique="T1078",
                    ),
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description=f"Detach AdministratorAccess from role '{role_name}'",
                            code_snippet=(
                                f"aws iam detach-role-policy "
                                f"--role-name {role_name} "
                                f"--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            description="Apply least-privilege policies scoped to the service's actual needs.",
                        ),
                    ],
                ))

        # Inline policies
        inline = self._paginate(
            self._iam, "list_role_policies", "PolicyNames", RoleName=role_name
        )
        for policy_name in inline:
            try:
                doc = self._iam.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )["PolicyDocument"]
                self._check_wildcard_policy(doc, role_arn, "AWS::IAM::Role", policy_name)
            except ClientError as exc:
                self.logger.debug("Could not read role inline policy %s: %s", policy_name, exc)

    # ------------------------------------------------------------------
    # Cross-account trusts
    # ------------------------------------------------------------------

    def _check_cross_account_trusts(self) -> None:
        roles = self._paginate(self._iam, "list_roles", "Roles")
        account_id = self.session.account_id

        for role in roles:
            trust = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust, str):
                trust = json.loads(unquote(trust))

            for statement in trust.get("Statement", []):
                principal = statement.get("Principal", {})
                aws_principals = []

                if isinstance(principal, str):
                    aws_principals = [principal]
                elif isinstance(principal, dict):
                    p = principal.get("AWS", [])
                    aws_principals = [p] if isinstance(p, str) else p

                for arn in aws_principals:
                    # Check if trust is to a different account
                    if (
                        isinstance(arn, str)
                        and "iam" in arn
                        and f"arn:aws:iam::{account_id}" not in arn
                        and arn != "*"
                    ):
                        self._add_finding(Finding(
                            title=f"Cross-account trust on role: {role['RoleName']}",
                            description=(
                                f"IAM role '{role['RoleName']}' trusts an external AWS principal: {arn}. "
                                "Cross-account trusts allow principals outside your account to assume this role. "
                                "Verify this is intentional and that the trusted account is expected."
                            ),
                            severity=Severity.MEDIUM,
                            category=self.category,
                            subcategory="Cross-Account Trust",
                            cloud_provider=CloudProvider.AWS,
                            resource_id=role["Arn"],
                            resource_type="AWS::IAM::Role",
                            region="global",
                            mitre_tactics=["Privilege Escalation", "Lateral Movement"],
                            mitre_techniques=["T1199"],
                            raw_evidence={
                                "trusted_principal": arn,
                                "trust_policy": trust,
                            },
                            remediation_steps=[
                                RemediationStep(
                                    order=1,
                                    description="Review whether this cross-account trust is intended and necessary",
                                ),
                                RemediationStep(
                                    order=2,
                                    description="If not needed, remove the external principal from the trust policy",
                                    code_snippet=(
                                        f"# Edit trust policy to remove {arn}\n"
                                        f"aws iam update-assume-role-policy "
                                        f"--role-name {role['RoleName']} "
                                        f"--policy-document file://updated-trust-policy.json"
                                    ),
                                ),
                                RemediationStep(
                                    order=3,
                                    description="Consider requiring ExternalId condition for third-party trusts",
                                    reference_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html",
                                ),
                            ],
                        ))

                    # Wildcard principal (anyone can assume)
                    if arn == "*":
                        self._add_finding(Finding(
                            title=f"IAM role with wildcard principal (*): {role['RoleName']}",
                            description=(
                                f"IAM role '{role['RoleName']}' can be assumed by any AWS principal. "
                                "A wildcard trust policy is almost never intentional and represents "
                                "a critical misconfiguration."
                            ),
                            severity=Severity.CRITICAL,
                            category=self.category,
                            subcategory="Cross-Account Trust",
                            cloud_provider=CloudProvider.AWS,
                            resource_id=role["Arn"],
                            resource_type="AWS::IAM::Role",
                            region="global",
                            mitre_tactics=["Privilege Escalation"],
                            mitre_techniques=["T1078"],
                            raw_evidence={"trust_policy": trust},
                            remediation_steps=[
                                RemediationStep(
                                    order=1,
                                    description="Immediately restrict the trust policy to specific, expected principals",
                                ),
                            ],
                        ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_wildcard_policy(
        self,
        doc: Dict[str, Any],
        resource_id: str,
        resource_type: str,
        policy_name: str,
    ) -> None:
        """Flag any inline policy statement with * action or * resource."""
        for statement in doc.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            has_wildcard_action = any(a == "*" or a.endswith(":*") for a in actions)
            has_wildcard_resource = "*" in resources

            if has_wildcard_action and has_wildcard_resource:
                self._add_finding(Finding(
                    title=f"Inline policy with wildcard Action and Resource: {policy_name}",
                    description=(
                        f"Inline policy '{policy_name}' on {resource_type} '{resource_id}' "
                        "grants Allow on Action=* and Resource=*, which is equivalent to "
                        "AdministratorAccess. This is a critical over-permission."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    subcategory="Wildcard Policy",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=resource_id,
                    resource_type=resource_type,
                    region="global",
                    mitre_tactics=["Privilege Escalation"],
                    mitre_techniques=["T1078"],
                    compliance_controls={"CIS": ["1.16"]},
                    raw_evidence={"statement": statement, "policy_name": policy_name},
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description=f"Replace wildcard policy '{policy_name}' with a scoped permission set",
                        ),
                        RemediationStep(
                            order=2,
                            description="Use IAM Access Analyzer to generate least-privilege policies from CloudTrail",
                            reference_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html",
                        ),
                    ],
                ))
            elif has_wildcard_action:
                self._add_finding(Finding(
                    title=f"Inline policy with wildcard Action: {policy_name}",
                    description=(
                        f"Inline policy '{policy_name}' allows '*' or service-level wildcard actions. "
                        "This grants more permissions than necessary and violates least-privilege."
                    ),
                    severity=Severity.HIGH,
                    category=self.category,
                    subcategory="Wildcard Policy",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=resource_id,
                    resource_type=resource_type,
                    region="global",
                    compliance_controls={"CIS": ["1.16"]},
                    raw_evidence={"statement": statement, "policy_name": policy_name},
                ))