"""
Logging configuration for cloudsec-audit.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional


def configure_logging(
    level: str = "WARNING",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
) -> None:
    """
    Configure root logger for cloudsec-audit.

    Args:
        level: Logging level name (DEBUG, INFO, WARNING, ERROR).
        log_file: Optional path to write logs to a file in addition to stdout.
        format_string: Optional custom log format string.
    """
    fmt = format_string or "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    handlers = [logging.StreamHandler(sys.stderr)]

    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.WARNING),
        format=fmt,
        datefmt=datefmt,
        handlers=handlers,
    )

    # Suppress noisy boto3/botocore logs unless debugging
    if level.upper() != "DEBUG":
        logging.getLogger("boto3").setLevel(logging.WARNING)
        logging.getLogger("botocore").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)