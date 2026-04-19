"""
CloudSecAudit — top-level orchestrator.

Runs all configured analyzers and returns a unified AuditReport.
"""

from __future__ import annotations

import logging
import time
from typing import List, Optional

from cloudsec_audit.analyzers.iam import IAMAnalyzer
from cloudsec_audit.analyzers.network import NetworkExposureAuditor
from cloudsec_audit.analyzers.storage import StorageAuditor
from cloudsec_audit.models.finding import Finding
from cloudsec_audit.models.session import AWSSession
from cloudsec_audit.reporters.compliance import ComplianceReporter
from cloudsec_audit.reporters.report import AuditReport

logger = logging.getLogger(__name__)


class CloudSecAudit:
    """
    Orchestrates a full AWS security posture audit.

    Runs IAM, network, and storage checks then wraps results in a
    unified :class:`~cloudsec_audit.reporters.report.AuditReport`.

    Usage::

        from cloudsec_audit import CloudSecAudit, AWSSession

        audit = CloudSecAudit(
            session=AWSSession(),
            regions=["us-east-1", "eu-west-1"],
        )
        report = audit.run()
        print(report.summary())
        report.to_json("results.json")

        compliance = audit.compliance_report(frameworks=["CIS", "SOC2"])
        print(compliance.summary())

    Args:
        session: Authenticated :class:`~cloudsec_audit.models.session.AWSSession`.
        regions: AWS regions to audit.
        run_iam: Include IAM checks.
        run_network: Include network exposure checks.
        run_storage: Include S3 storage checks.
        iam_kwargs: Extra keyword arguments forwarded to :class:`IAMAnalyzer`.
        network_kwargs: Extra keyword arguments forwarded to :class:`NetworkExposureAuditor`.
        storage_kwargs: Extra keyword arguments forwarded to :class:`StorageAuditor`.
    """

    def __init__(
        self,
        session: Optional[AWSSession] = None,
        regions: Optional[List[str]] = None,
        run_iam: bool = True,
        run_network: bool = True,
        run_storage: bool = True,
        iam_kwargs: Optional[dict] = None,
        network_kwargs: Optional[dict] = None,
        storage_kwargs: Optional[dict] = None,
    ) -> None:
        self.session = session or AWSSession()
        self.regions = regions or ["us-east-1"]
        self.run_iam = run_iam
        self.run_network = run_network
        self.run_storage = run_storage
        self.iam_kwargs = iam_kwargs or {}
        self.network_kwargs = network_kwargs or {}
        self.storage_kwargs = storage_kwargs or {}

        self._findings: List[Finding] = []
        self._report: Optional[AuditReport] = None
        self._duration: Optional[float] = None

    def run(self) -> AuditReport:
        """
        Execute all configured audit checks.

        Returns:
            :class:`~cloudsec_audit.reporters.report.AuditReport`
        """
        logger.info(
            "Starting cloudsec-audit for account %s across regions %s",
            self.session.account_id,
            self.regions,
        )

        self._findings = []
        start = time.monotonic()

        if self.run_iam:
            self._run_analyzer(
                IAMAnalyzer,
                {"regions": self.regions, **self.iam_kwargs},
            )

        if self.run_network:
            self._run_analyzer(
                NetworkExposureAuditor,
                {"regions": self.regions, **self.network_kwargs},
            )

        if self.run_storage:
            self._run_analyzer(
                StorageAuditor,
                {"regions": self.regions, **self.storage_kwargs},
            )

        self._duration = time.monotonic() - start
        self._report = AuditReport(
            findings=self._findings,
            account_id=self.session.account_id,
            scan_duration_seconds=self._duration,
        )

        logger.info(
            "Audit complete in %.1fs — %d findings total",
            self._duration,
            len(self._findings),
        )
        return self._report

    def compliance_report(
        self,
        frameworks: Optional[List[str]] = None,
    ) -> ComplianceReporter:
        """
        Generate a compliance report from the last audit run.

        Args:
            frameworks: Compliance frameworks to evaluate.
                        Defaults to all supported frameworks.

        Returns:
            :class:`~cloudsec_audit.reporters.compliance.ComplianceReporter`
        """
        if not self._findings and self._report is None:
            raise RuntimeError("Call run() before generating a compliance report.")

        reporter = ComplianceReporter(
            findings=self._findings,
            frameworks=frameworks,
            account_id=self.session.account_id,
        )
        reporter.generate()
        return reporter

    def _run_analyzer(self, analyzer_class, kwargs: dict) -> None:
        name = analyzer_class.name
        logger.info("Running %s ...", name)
        try:
            analyzer = analyzer_class(session=self.session, **kwargs)
            findings = analyzer.run()
            self._findings.extend(findings)
            logger.info("%s: %d findings", name, len(findings))
        except Exception as exc:
            logger.error("%s failed: %s", name, exc, exc_info=True)