"""
Base scanner.

Every domain scanner (compute, network, data, identity) extends BaseScanner
and implements `_scan_region`. The base class handles:
  - Multi-region orchestration
  - Per-region error isolation (one region failing doesn't kill the scan)
  - Logging and timing
  - Result aggregation

Subclass contract:
  - Implement `_scan_region(region: str) -> list[Resource]`
  - Implement `domain: str` class attribute (used for logging)
  - Set `is_global: bool` to True for global services (IAM, S3, CloudFront)
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from breakbot.models import Resource
from breakbot.utils import AWSSession

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    domain: str = "base"
    is_global: bool = False  # If True, only scan once (e.g., IAM)

    def __init__(self, session: AWSSession):
        self.session = session
        self.errors: list[dict] = []

    @abstractmethod
    def _scan_region(self, region: str) -> list[Resource]:
        """Implement per-domain scan logic. Must not raise — log and continue."""
        raise NotImplementedError

    def scan(self, regions: list[str] | None = None) -> list[Resource]:
        """
        Orchestrates the scan across regions.

        Returns the aggregated list of resources. Errors are collected in
        self.errors rather than raised — partial results beat no results.
        """
        if self.is_global:
            target_regions = [regions[0] if regions else "us-east-1"]
        else:
            target_regions = regions or self.session.enabled_regions()

        all_resources: list[Resource] = []
        for region in target_regions:
            logger.info("[%s] scanning region=%s", self.domain, region)
            t0 = time.monotonic()
            try:
                resources = self._scan_region(region)
                elapsed = time.monotonic() - t0
                logger.info(
                    "[%s] region=%s found=%d in %.2fs",
                    self.domain, region, len(resources), elapsed,
                )
                all_resources.extend(resources)
            except Exception as e:
                # Catch-all is intentional. A single region's failure
                # (permissions, transient errors, opt-in regions) must not
                # take down the whole scan.
                logger.exception("[%s] region=%s failed", self.domain, region)
                self.errors.append({
                    "domain": self.domain,
                    "region": region,
                    "error": str(e),
                    "error_type": type(e).__name__,
                })
        return all_resources
