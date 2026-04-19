"""
AWS-specific helper utilities shared across analyzers.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


def is_internet_cidr(cidr: str) -> bool:
    """Return True if the CIDR represents unrestricted internet access."""
    return cidr in INTERNET_CIDRS


def get_all_regions(
    session: boto3.Session,
    service: str = "ec2",
) -> List[str]:
    """
    Return all enabled AWS regions for a given service.

    Args:
        session: boto3 Session.
        service: AWS service name (default: ``"ec2"``).

    Returns:
        List of region name strings.
    """
    try:
        client = session.client("ec2", region_name="us-east-1")
        response = client.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
        return [r["RegionName"] for r in response.get("Regions", []) if "RegionName" in r]
    except ClientError:
        # Fallback to standard regions
        return [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
            "eu-north-1", "ap-southeast-1", "ap-southeast-2",
            "ap-northeast-1", "ap-northeast-2", "ap-south-1",
            "sa-east-1", "ca-central-1",
        ]


def parse_arn(arn: str) -> Dict[str, str]:
    """
    Parse an AWS ARN into its components.

    Returns a dict with keys:
        partition, service, region, account_id, resource_type, resource_id

    Example::

        >>> parse_arn("arn:aws:iam::123456789012:role/MyRole")
        {
            "partition": "aws",
            "service": "iam",
            "region": "",
            "account_id": "123456789012",
            "resource_type": "role",
            "resource_id": "MyRole",
        }
    """
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return {"raw": arn}

    resource = parts[5]
    if "/" in resource:
        resource_type, _, resource_id = resource.partition("/")
    elif ":" in resource:
        resource_type, _, resource_id = resource.partition(":")
    else:
        resource_type = ""
        resource_id = resource

    return {
        "partition": parts[1],
        "service": parts[2],
        "region": parts[3],
        "account_id": parts[4],
        "resource_type": resource_type,
        "resource_id": resource_id,
    }


def account_id_from_arn(arn: str) -> Optional[str]:
    """Extract account ID from an ARN string."""
    parsed = parse_arn(arn)
    return parsed.get("account_id")


def truncate(value: str, max_len: int = 80) -> str:
    """Truncate a string with an ellipsis if it exceeds max_len."""
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."