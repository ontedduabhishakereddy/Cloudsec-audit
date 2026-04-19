"""
Data models for audit findings.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Finding severity levels aligned with CVSS/cloud security conventions."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @property
    def score(self) -> int:
        """Numeric score for sorting and prioritization."""
        return {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFORMATIONAL": 1,
        }[self.value]

    def __lt__(self, other: "Severity") -> bool:
        return self.score < other.score

    def __gt__(self, other: "Severity") -> bool:
        return self.score > other.score


class FindingStatus(str, Enum):
    """Lifecycle status of a finding."""

    OPEN = "OPEN"
    SUPPRESSED = "SUPPRESSED"
    RESOLVED = "RESOLVED"
    IN_PROGRESS = "IN_PROGRESS"


class CloudProvider(str, Enum):
    """Supported cloud providers."""

    AWS = "AWS"
    GCP = "GCP"
    AZURE = "AZURE"


@dataclass
class RemediationStep:
    """A single remediation action."""

    order: int
    description: str
    code_snippet: Optional[str] = None
    reference_url: Optional[str] = None


@dataclass
class AttackPath:
    """Describes a privilege escalation or lateral movement path."""

    steps: List[str] = field(default_factory=list)
    entry_point: Optional[str] = None
    blast_radius: Optional[str] = None  # e.g., "Full account takeover"
    mitre_technique: Optional[str] = None


@dataclass
class Finding:
    """
    Represents a single security finding from a cloud audit.

    Findings are the core output of every analyzer. Each finding maps
    to a specific misconfiguration, exposure, or risk in the audited
    cloud environment.
    """

    # Identity
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""

    # Classification
    severity: Severity = Severity.INFORMATIONAL
    category: str = ""           # e.g., "IAM", "Network", "Storage"
    subcategory: str = ""        # e.g., "Privilege Escalation", "Public Exposure"
    cloud_provider: CloudProvider = CloudProvider.AWS

    # Resource context
    resource_id: str = ""        # ARN, resource name, etc.
    resource_type: str = ""      # e.g., "AWS::IAM::Role"
    region: str = ""
    account_id: str = ""

    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Compliance framework mapping
    compliance_controls: Dict[str, List[str]] = field(default_factory=dict)
    # e.g., {"CIS": ["1.3", "1.4"], "SOC2": ["CC6.1"]}

    # Detail
    raw_evidence: Dict[str, Any] = field(default_factory=dict)
    attack_path: Optional[AttackPath] = None
    remediation_steps: List[RemediationStep] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    # Lifecycle
    status: FindingStatus = FindingStatus.OPEN
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    suppression_reason: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize finding to a plain dictionary."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "subcategory": self.subcategory,
            "cloud_provider": self.cloud_provider.value,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "region": self.region,
            "account_id": self.account_id,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "compliance_controls": self.compliance_controls,
            "raw_evidence": self.raw_evidence,
            "attack_path": {
                "steps": self.attack_path.steps,
                "entry_point": self.attack_path.entry_point,
                "blast_radius": self.attack_path.blast_radius,
                "mitre_technique": self.attack_path.mitre_technique,
            } if self.attack_path else None,
            "remediation_steps": [
                {
                    "order": s.order,
                    "description": s.description,
                    "code_snippet": s.code_snippet,
                    "reference_url": s.reference_url,
                }
                for s in self.remediation_steps
            ],
            "references": self.references,
            "status": self.status.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "suppression_reason": self.suppression_reason,
            "tags": self.tags,
        }

    def suppress(self, reason: str) -> None:
        """Mark this finding as suppressed with a given reason."""
        self.status = FindingStatus.SUPPRESSED
        self.suppression_reason = reason

    def resolve(self) -> None:
        """Mark this finding as resolved."""
        self.status = FindingStatus.RESOLVED

    def __repr__(self) -> str:
        return (
            f"Finding(id={self.finding_id[:8]}, "
            f"severity={self.severity.value}, "
            f"title={self.title!r}, "
            f"resource={self.resource_id!r})"
        )