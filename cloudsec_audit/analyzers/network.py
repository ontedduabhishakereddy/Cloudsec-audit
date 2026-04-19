"""
NetworkExposureAuditor — audits security groups, NACLs, and network exposure.

Detects:
  - Security groups allowing 0.0.0.0/0 or ::/0 on sensitive ports
  - Unrestricted ingress (all traffic from anywhere)
  - Databases exposed to the internet (RDS, ElasticSearch, Redis)
  - SSH/RDP open to the internet
  - Overly permissive NACLs
  - VPC flow logs disabled
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

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

# Ports considered sensitive if exposed to the internet
SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    135: "RPC",
    137: "NetBIOS",
    139: "NetBIOS",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    512: "rexec",
    513: "rlogin",
    514: "RSH",
    636: "LDAPS",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker daemon (unencrypted)",
    2376: "Docker daemon (TLS)",
    2379: "etcd",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    4333: "MySQL alt",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    7000: "Cassandra",
    8080: "HTTP alt",
    8443: "HTTPS alt",
    8888: "Jupyter Notebook",
    9042: "Cassandra",
    9200: "Elasticsearch",
    9300: "Elasticsearch cluster",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
}

# Internet CIDR ranges
INTERNET_CIDRS: Set[str] = {"0.0.0.0/0", "::/0"}

# Ports that are almost never acceptable from the internet
CRITICAL_INTERNET_PORTS: Set[int] = {
    1433, 1521, 3306, 5432, 6379, 9200, 27017,  # databases
    22, 3389,                                     # admin
    2375, 2379,                                   # infra
}


class NetworkExposureAuditor(BaseAnalyzer):
    """
    Audits network-level security configurations across AWS regions.

    Usage::

        from cloudsec_audit import NetworkExposureAuditor, AWSSession

        session = AWSSession()
        auditor = NetworkExposureAuditor(session, regions=["us-east-1", "eu-west-1"])
        findings = auditor.run()

    Args:
        session: Authenticated :class:`~cloudsec_audit.models.session.AWSSession`.
        regions: AWS regions to audit. Defaults to ``["us-east-1"]``.
        check_nacls: Whether to audit Network ACLs.
        check_flow_logs: Whether to check VPC flow log configuration.
    """

    name = "NetworkExposureAuditor"
    category = "Network"

    def __init__(
        self,
        session: AWSSession,
        regions: Optional[List[str]] = None,
        check_nacls: bool = True,
        check_flow_logs: bool = True,
        max_workers: int = 10,
    ) -> None:
        super().__init__(session, regions=regions or ["us-east-1"], max_workers=max_workers)
        self.check_nacls = check_nacls
        self.check_flow_logs = check_flow_logs

    def run(self) -> List[Finding]:
        """Run all network exposure checks across configured regions."""
        self.logger.info(
            "Starting network audit across %d region(s)", len(self.regions)
        )

        with ThreadPoolExecutor(max_workers=min(len(self.regions), self.max_workers)) as pool:
            futures = {
                pool.submit(self._audit_region, region): region
                for region in self.regions
            }
            for future in as_completed(futures):
                region = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.logger.error("Region %s audit failed: %s", region, exc)

        self.logger.info("Network audit complete — %d findings", len(self._findings))
        return self._findings

    def _audit_region(self, region: str) -> None:
        ec2 = self.session.client("ec2", region=region)

        self._check_security_groups(ec2, region)

        if self.check_nacls:
            self._check_nacls(ec2, region)

        if self.check_flow_logs:
            self._check_vpc_flow_logs(ec2, region)

    # ------------------------------------------------------------------
    # Security Groups
    # ------------------------------------------------------------------

    def _check_security_groups(self, ec2, region: str) -> None:
        sgs = self._paginate(ec2, "describe_security_groups", "SecurityGroups")
        self.logger.info("Region %s: auditing %d security groups", region, len(sgs))

        for sg in sgs:
            self._audit_sg(sg, region)

    def _audit_sg(self, sg: Dict[str, Any], region: str) -> None:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        vpc_id = sg.get("VpcId", "unknown")
        sg_arn = f"arn:aws:ec2:{region}:{self.session.account_id}:security-group/{sg_id}"

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            protocol = rule.get("IpProtocol", "-1")

            # Collect internet CIDRs in this rule
            internet_ipv4 = [
                r["CidrIp"]
                for r in rule.get("IpRanges", [])
                if r.get("CidrIp") in INTERNET_CIDRS
            ]
            internet_ipv6 = [
                r["CidrIpv6"]
                for r in rule.get("Ipv6Ranges", [])
                if r.get("CidrIpv6") in INTERNET_CIDRS
            ]
            open_cidrs = internet_ipv4 + internet_ipv6

            if not open_cidrs:
                continue

            # Protocol -1 means all traffic
            if protocol == "-1":
                self._add_finding(Finding(
                    title=f"Security group allows all traffic from internet: {sg_name}",
                    description=(
                        f"Security group '{sg_name}' ({sg_id}) in VPC {vpc_id} (region {region}) "
                        f"has an inbound rule allowing ALL traffic from {', '.join(open_cidrs)}. "
                        "This exposes all instances using this group to the entire internet."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    subcategory="Unrestricted Ingress",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=sg_arn,
                    resource_type="AWS::EC2::SecurityGroup",
                    region=region,
                    mitre_tactics=["Initial Access", "Discovery"],
                    mitre_techniques=["T1190", "T1046"],
                    compliance_controls={"CIS": ["5.2"], "SOC2": ["CC6.6"], "PCI-DSS": ["1.3"]},
                    raw_evidence={"rule": rule, "open_cidrs": open_cidrs, "vpc_id": vpc_id},
                    attack_path=AttackPath(
                        entry_point=sg_arn,
                        steps=[
                            f"Security group {sg_id} allows all ports from 0.0.0.0/0",
                            "Attacker scans all open ports on associated instances",
                            "Any exposed service becomes an entry point",
                        ],
                        blast_radius="All instances associated with this security group",
                    ),
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description="Remove the allow-all ingress rule",
                            code_snippet=(
                                f"aws ec2 revoke-security-group-ingress "
                                f"--group-id {sg_id} "
                                f"--protocol -1 "
                                f"--cidr 0.0.0.0/0"
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            description="Replace with rules scoped to specific ports and source IP ranges or security group IDs",
                        ),
                    ],
                ))
                continue  # Don't double-report per-port findings for the same SG

            # Check specific sensitive ports in the range
            for port, service in SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    is_critical = port in CRITICAL_INTERNET_PORTS
                    severity = Severity.CRITICAL if is_critical else Severity.HIGH

                    self._add_finding(Finding(
                        title=f"Security group exposes {service} (port {port}) to internet: {sg_name}",
                        description=(
                            f"Security group '{sg_name}' ({sg_id}) allows inbound {service} "
                            f"(TCP/{port}) from {', '.join(open_cidrs)} in region {region}. "
                            f"{'This is a database port — public exposure is almost never intentional.' if is_critical else 'Restrict this port to known source IPs or VPN.'}"
                        ),
                        severity=severity,
                        category=self.category,
                        subcategory="Public Port Exposure",
                        cloud_provider=CloudProvider.AWS,
                        resource_id=sg_arn,
                        resource_type="AWS::EC2::SecurityGroup",
                        region=region,
                        mitre_tactics=["Initial Access", "Discovery"],
                        mitre_techniques=["T1190", "T1046"],
                        compliance_controls={
                            "CIS": ["5.2", "5.3"],
                            "SOC2": ["CC6.6"],
                            "PCI-DSS": ["1.3"],
                        },
                        raw_evidence={
                            "port": port,
                            "service": service,
                            "protocol": protocol,
                            "open_cidrs": open_cidrs,
                            "vpc_id": vpc_id,
                            "sg_name": sg_name,
                        },
                        attack_path=AttackPath(
                            entry_point=sg_arn,
                            steps=[
                                f"Port {port} ({service}) is accessible from 0.0.0.0/0",
                                f"Attacker connects directly to {service}",
                                "Brute force, exploit, or data exfiltration possible",
                            ],
                            blast_radius=f"All {service} instances in SG {sg_id}",
                        ),
                        remediation_steps=[
                            RemediationStep(
                                order=1,
                                description=f"Revoke public access to port {port}",
                                code_snippet=(
                                    f"aws ec2 revoke-security-group-ingress "
                                    f"--group-id {sg_id} "
                                    f"--protocol tcp "
                                    f"--port {port} "
                                    f"--cidr 0.0.0.0/0"
                                ),
                            ),
                            RemediationStep(
                                order=2,
                                description=f"If {service} access is needed, restrict to specific IP ranges or use VPN/bastion",
                            ),
                        ],
                    ))

    # ------------------------------------------------------------------
    # Network ACLs
    # ------------------------------------------------------------------

    def _check_nacls(self, ec2, region: str) -> None:
        nacls = self._paginate(ec2, "describe_network_acls", "NetworkAcls")

        for nacl in nacls:
            nacl_id = nacl["NetworkAclId"]
            nacl_arn = f"arn:aws:ec2:{region}:{self.session.account_id}:network-acl/{nacl_id}"

            for entry in nacl.get("Entries", []):
                # Only check ingress rules (Egress=False)
                if entry.get("Egress", True):
                    continue

                cidr = entry.get("CidrBlock", "") or entry.get("Ipv6CidrBlock", "")
                action = entry.get("RuleAction", "")
                rule_number = entry.get("RuleNumber", 0)

                # Skip default deny rules
                if rule_number == 32767:
                    continue

                if cidr in INTERNET_CIDRS and action == "allow":
                    port_range = entry.get("PortRange", {})
                    from_p = port_range.get("From", 0)
                    to_p = port_range.get("To", 65535)
                    protocol = entry.get("Protocol", "-1")

                    if protocol == "-1" or (from_p == 0 and to_p == 65535):
                        self._add_finding(Finding(
                            title=f"NACL allows all traffic from internet: {nacl_id}",
                            description=(
                                f"Network ACL '{nacl_id}' (rule #{rule_number}) in region {region} "
                                f"allows all inbound traffic from {cidr}. "
                                "NACLs are a secondary defense — an overly permissive NACL removes a key security layer."
                            ),
                            severity=Severity.MEDIUM,
                            category=self.category,
                            subcategory="Permissive NACL",
                            cloud_provider=CloudProvider.AWS,
                            resource_id=nacl_arn,
                            resource_type="AWS::EC2::NetworkAcl",
                            region=region,
                            compliance_controls={"CIS": ["5.1"]},
                            raw_evidence={"entry": entry, "cidr": cidr},
                            remediation_steps=[
                                RemediationStep(
                                    order=1,
                                    description=f"Review NACL rule #{rule_number} and restrict the source CIDR to known ranges",
                                ),
                            ],
                        ))

    # ------------------------------------------------------------------
    # VPC Flow Logs
    # ------------------------------------------------------------------

    def _check_vpc_flow_logs(self, ec2, region: str) -> None:
        vpcs = self._paginate(ec2, "describe_vpcs", "Vpcs")

        try:
            flow_logs = self._paginate(ec2, "describe_flow_logs", "FlowLogs")
            vpc_ids_with_logs: Set[str] = {
                fl["ResourceId"]
                for fl in flow_logs
                if fl.get("FlowLogStatus") == "ACTIVE"
            }
        except ClientError as exc:
            self.logger.warning("Could not describe flow logs in %s: %s", region, exc)
            return

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            vpc_arn = f"arn:aws:ec2:{region}:{self.session.account_id}:vpc/{vpc_id}"

            if vpc_id not in vpc_ids_with_logs:
                self._add_finding(Finding(
                    title=f"VPC flow logs disabled: {vpc_id}",
                    description=(
                        f"VPC '{vpc_id}' in region {region} does not have active flow logs. "
                        "Flow logs are essential for detecting network intrusions, data exfiltration, "
                        "and responding to incidents. Without them, network-level forensics are impossible."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.category,
                    subcategory="Logging",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=vpc_arn,
                    resource_type="AWS::EC2::VPC",
                    region=region,
                    compliance_controls={
                        "CIS": ["3.9"],
                        "SOC2": ["CC7.2"],
                        "HIPAA": ["164.312(b)"],
                    },
                    raw_evidence={"vpc_id": vpc_id, "is_default": vpc.get("IsDefault", False)},
                    remediation_steps=[
                        RemediationStep(
                            order=1,
                            description=f"Enable flow logs for VPC {vpc_id}",
                            code_snippet=(
                                f"aws ec2 create-flow-logs "
                                f"--resource-type VPC "
                                f"--resource-ids {vpc_id} "
                                f"--traffic-type ALL "
                                f"--log-destination-type cloud-watch-logs "
                                f"--log-group-name /aws/vpc/flowlogs/{vpc_id} "
                                f"--deliver-logs-permission-arn arn:aws:iam::<ACCOUNT>:role/FlowLogsRole"
                            ),
                        ),
                    ],
                ))