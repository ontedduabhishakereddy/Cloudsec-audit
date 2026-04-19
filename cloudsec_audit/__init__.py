"""
cloudsec-audit — Continuous cloud security posture auditing for AWS, GCP, and Azure.
Currently supports AWS. GCP and Azure coming soon.
"""

__version__ = "0.1.0"
__author__ = "cloudsec-audit contributors"
__license__ = "MIT"

from cloudsec_audit.analyzers.iam import IAMAnalyzer
from cloudsec_audit.analyzers.network import NetworkExposureAuditor
from cloudsec_audit.analyzers.storage import StorageAuditor
from cloudsec_audit.reporters.compliance import ComplianceReporter
from cloudsec_audit.reporters.report import AuditReport
from cloudsec_audit.models.finding import Finding, Severity, FindingStatus
from cloudsec_audit.models.session import AWSSession
from cloudsec_audit.orchestrator import CloudSecAudit

__all__ = [
    "CloudSecAudit",
    "IAMAnalyzer",
    "NetworkExposureAuditor",
    "StorageAuditor",
    "ComplianceReporter",
    "AuditReport",
    "Finding",
    "Severity",
    "FindingStatus",
    "AWSSession",
]