"""
Base class for all cloud security analyzers.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List, Optional

from cloudsec_audit.models.finding import Finding
from cloudsec_audit.models.session import AWSSession

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """
    Abstract base for all analyzers.

    Subclasses implement ``run()`` and return a list of :class:`Finding` objects.
    The base class handles session wiring, logging, and error aggregation.
    """

    #: Human-readable name shown in reports and logs.
    name: str = "BaseAnalyzer"

    #: Category label applied to all findings produced by this analyzer.
    category: str = "General"

    def __init__(
        self,
        session: AWSSession,
        regions: Optional[List[str]] = None,
        max_workers: int = 5,
    ) -> None:
        self.session = session
        self.regions = regions or ["us-east-1"]
        self.max_workers = max_workers
        self._findings: List[Finding] = []
        self.logger = logging.getLogger(
            f"cloudsec_audit.{self.__class__.__name__}"
        )

    @abstractmethod
    def run(self) -> List[Finding]:
        """
        Execute the audit and return all findings.

        Implementations should call ``self._add_finding()`` for each
        discovered issue and return ``self._findings`` at the end.
        """

    def _add_finding(self, finding: Finding) -> None:
        """Add a validated finding to the internal list."""
        finding.account_id = self.session.account_id
        self._findings.append(finding)
        self.logger.debug(
            "Finding added: [%s] %s — %s",
            finding.severity.value,
            finding.title,
            finding.resource_id,
        )

    def _paginate(self, client, method: str, result_key: str, **kwargs) -> list:
        """
        Generic boto3 paginator helper.

        Args:
            client: boto3 client instance
            method: paginator method name (e.g., ``"list_users"``)
            result_key: key in each page response that holds the list of items
            **kwargs: extra arguments forwarded to the paginator

        Returns:
            Flat list of all items across all pages.
        """
        items = []
        try:
            paginator = client.get_paginator(method)
            for page in paginator.paginate(**kwargs):
                items.extend(page.get(result_key, []))
        except Exception as exc:
            self.logger.warning(
                "Pagination failed for %s.%s: %s", client.meta.service_model.service_name, method, exc
            )
        return items

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(account={self.session.account_id}, regions={self.regions})"