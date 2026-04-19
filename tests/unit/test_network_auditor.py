"""
Unit tests for NetworkExposureAuditor using moto.
"""

from __future__ import annotations

import pytest
import boto3

from tests.conftest import MOTO_AVAILABLE, mock_aws

from cloudsec_audit.analyzers.network import NetworkExposureAuditor
from cloudsec_audit.models.finding import Severity
from cloudsec_audit.models.session import AWSSession


def requires_moto(fn):  # type: ignore[no-untyped-def]
    return pytest.mark.skipif(not MOTO_AVAILABLE, reason="moto not installed")(fn)


@requires_moto
class TestNetworkExposureAuditor:

    @mock_aws
    def test_detects_ssh_open_to_internet(self) -> None:
        """Security group with SSH open to 0.0.0.0/0 should be flagged HIGH or CRITICAL."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        sg = ec2.create_security_group(GroupName="ssh-open", Description="SSH open to internet")
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = NetworkExposureAuditor(
            session, regions=["us-east-1"], check_nacls=False, check_flow_logs=False,
        )
        findings = auditor.run()

        ssh_findings = [f for f in findings if "SSH" in f.title and sg_id in f.resource_id]
        assert len(ssh_findings) >= 1
        assert ssh_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    @mock_aws
    def test_detects_database_port_open_to_internet(self) -> None:
        """PostgreSQL port open to 0.0.0.0/0 should be CRITICAL."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        sg = ec2.create_security_group(GroupName="db-open", Description="DB open to internet")
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = NetworkExposureAuditor(
            session, regions=["us-east-1"], check_nacls=False, check_flow_logs=False,
        )
        findings = auditor.run()

        db_findings = [f for f in findings if "PostgreSQL" in f.title and sg_id in f.resource_id]
        assert len(db_findings) >= 1
        assert db_findings[0].severity == Severity.CRITICAL

    @mock_aws
    def test_detects_all_traffic_open(self) -> None:
        """Security group allowing all traffic from 0.0.0.0/0 should be CRITICAL."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        sg = ec2.create_security_group(GroupName="all-open", Description="All traffic open")
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = NetworkExposureAuditor(
            session, regions=["us-east-1"], check_nacls=False, check_flow_logs=False,
        )
        findings = auditor.run()

        all_traffic_findings = [
            f for f in findings if "all traffic" in f.title.lower() and sg_id in f.resource_id
        ]
        assert len(all_traffic_findings) >= 1
        assert all_traffic_findings[0].severity == Severity.CRITICAL

    @mock_aws
    def test_no_findings_for_restricted_sg(self) -> None:
        """Security group only allowing internal traffic should produce no findings."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        sg = ec2.create_security_group(GroupName="internal-only", Description="Internal only")
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }],
        )

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = NetworkExposureAuditor(
            session, regions=["us-east-1"], check_nacls=False, check_flow_logs=False,
        )
        findings = auditor.run()

        sg_findings = [f for f in findings if sg_id in f.resource_id]
        assert len(sg_findings) == 0

    @mock_aws
    def test_detects_vpc_without_flow_logs(self) -> None:
        """VPC without flow logs should produce a MEDIUM finding."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        resp = ec2.create_vpc(CidrBlock="172.16.0.0/16")
        # VpcId is always present on a freshly created VPC response
        vpc_id: str = resp["Vpc"]["VpcId"]  # type: ignore[index]

        session = AWSSession.from_boto_session(boto3.Session(region_name="us-east-1"))
        auditor = NetworkExposureAuditor(
            session, regions=["us-east-1"], check_nacls=False, check_flow_logs=True,
        )
        findings = auditor.run()

        flow_log_findings = [
            f for f in findings if "flow log" in f.title.lower() and vpc_id in f.resource_id
        ]
        assert len(flow_log_findings) >= 1
        assert flow_log_findings[0].severity == Severity.MEDIUM