"""
AWS session management — wraps boto3 session with account context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


@dataclass
class AWSSession:
    """
    Wraps a boto3 Session with account metadata.

    Usage::

        session = AWSSession.from_profile("my-profile")
        session = AWSSession.from_role("arn:aws:iam::123456789012:role/AuditRole")
        session = AWSSession()   # uses ambient credentials / env vars
    """

    profile_name: Optional[str] = None
    region_name: str = "us-east-1"
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    session_name: str = "cloudsec-audit"

    _boto_session: Optional[boto3.Session] = field(default=None, repr=False, compare=False)
    _account_id: Optional[str] = field(default=None, repr=False, compare=False)
    _account_aliases: list = field(default_factory=list, repr=False, compare=False)

    @classmethod
    def from_profile(cls, profile_name: str, region: str = "us-east-1") -> "AWSSession":
        """Create a session using a named AWS CLI profile."""
        return cls(profile_name=profile_name, region_name=region)

    @classmethod
    def from_role(
        cls,
        role_arn: str,
        region: str = "us-east-1",
        external_id: Optional[str] = None,
        session_name: str = "cloudsec-audit",
    ) -> "AWSSession":
        """Create a session by assuming an IAM role."""
        return cls(
            role_arn=role_arn,
            region_name=region,
            external_id=external_id,
            session_name=session_name,
        )

    @classmethod
    def from_boto_session(cls, session: boto3.Session) -> "AWSSession":
        """Wrap an existing boto3 session."""
        obj = cls(region_name=session.region_name or "us-east-1")
        obj._boto_session = session
        return obj

    def _build_session(self) -> boto3.Session:
        """Construct the underlying boto3 session."""
        base = boto3.Session(
            profile_name=self.profile_name,
            region_name=self.region_name,
        )

        if self.role_arn:
            # Use Any-typed client to avoid boto3-stubs overload resolution issues
            # with a dynamically-built kwargs dict.
            sts: Any = base.client("sts")
            assume_kwargs: dict[str, str] = {
                "RoleArn": self.role_arn,
                "RoleSessionName": self.session_name,
            }
            if self.external_id:
                assume_kwargs["ExternalId"] = self.external_id

            creds = sts.assume_role(**assume_kwargs)["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region_name,
            )

        return base

    @property
    def boto_session(self) -> boto3.Session:
        """Return the underlying boto3 session, building it if necessary."""
        if self._boto_session is None:
            self._boto_session = self._build_session()
        return self._boto_session

    @property
    def account_id(self) -> str:
        """Return the AWS account ID for the current session."""
        if self._account_id is None:
            sts: Any = self.boto_session.client("sts")
            self._account_id = str(sts.get_caller_identity()["Account"])
        return str(self._account_id)

    @property
    def account_aliases(self) -> list:
        """Return IAM account aliases (friendly names)."""
        if not self._account_aliases:
            iam: Any = self.boto_session.client("iam")
            try:
                resp = iam.list_account_aliases()
                self._account_aliases = resp.get("AccountAliases", [])
            except ClientError:
                self._account_aliases = []
        return self._account_aliases

    def client(self, service: str, region: Optional[str] = None) -> Any:
        """Return a boto3 service client, optionally in a specific region.

        Typed as Any because boto3-stubs uses Literal overloads per service name
        and cannot resolve a dynamic string — callers get full Any flexibility.
        """
        # Cast session to Any to bypass boto3-stubs Literal[service_name] overloads
        session: Any = self.boto_session
        return session.client(
            service,
            region_name=region or self.region_name,
        )

    def resource(self, service: str, region: Optional[str] = None) -> Any:
        """Return a boto3 service resource."""
        session: Any = self.boto_session
        return session.resource(
            service,
            region_name=region or self.region_name,
        )

    def validate(self) -> bool:
        """
        Verify that the session credentials are valid.

        Returns True if credentials work, raises on failure.
        """
        try:
            sts: Any = self.boto_session.client("sts")
            sts.get_caller_identity()
            return True
        except NoCredentialsError as exc:
            raise RuntimeError(
                "No AWS credentials found. Configure via environment variables, "
                "~/.aws/credentials, or pass a profile/role to AWSSession."
            ) from exc
        except ClientError as exc:
            raise RuntimeError(f"AWS credential validation failed: {exc}") from exc

    def __repr__(self) -> str:
        acct = self._account_id or "unknown"
        return f"AWSSession(account={acct}, region={self.region_name})"