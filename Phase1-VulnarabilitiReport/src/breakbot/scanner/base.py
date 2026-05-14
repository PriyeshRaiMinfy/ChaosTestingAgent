"""
Base scanner.

Every domain scanner (compute, network, data, identity) extends BaseScanner
and implements `_scan_region`. The base class handles:
  - Multi-region orchestration
  - Per-region error isolation (one region failing doesn't kill the scan)
  - Per-API-call error isolation via `_safe_scan_call` (one service failing
    in a region doesn't kill the others in that region)
  - Structured error reporting (categorized AWS error codes via ScanError)
  - Logging and timing
  - Result aggregation

Subclass contract:
  - Implement `_scan_region(region: str) -> list[Resource]`
  - Implement `domain: str` class attribute (used for logging)
  - Set `is_global: bool` to True for global services (IAM, S3, CloudFront)
  - Wrap each top-level AWS service call in `self._safe_scan_call(...)` so
    failures of one service don't cascade into others
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Callable

from botocore.exceptions import ClientError

from breakbot.models import Resource
from breakbot.scanner.errors import ScanError, categorize
from breakbot.utils import AWSSession

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    domain: str = "base"
    is_global: bool = False  # If True, only scan once (e.g., IAM)

    def __init__(self, session: AWSSession):
        self.session = session
        # Errors stay as list[dict] (not list[ScanError]) so the CLI's
        # downstream consumption pattern keeps working unchanged.
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
                # take down the whole scan. The structured per-call errors
                # captured inside _safe_scan_call are richer than this
                # fallback — this only fires for bugs in scanner code itself.
                logger.exception("[%s] region=%s failed", self.domain, region)
                self.errors.append(ScanError(
                    domain=self.domain,
                    account_id=self.session.account_id,
                    region=region,
                    service="unknown",
                    operation="_scan_region",
                    error_code="Exception",
                    error_type=type(e).__name__,
                    message=str(e),
                    request_id=None,
                    category="unknown",
                ).to_dict())
        return all_resources

    def _safe_scan_call(
        self,
        service: str,
        operation: str,
        region: str,
        fn: Callable[[], list[Resource]],
    ) -> list[Resource]:
        """
        Wrap one AWS-service-level scan call.

        Catches ClientError (boto3-originated) and any other exception,
        records a structured ScanError, and returns []. Crucially, does NOT
        re-raise — so other services in the same _scan_region call still run.

        Usage in subclasses:
            def _scan_region(self, region):
                return [
                    *self._safe_scan_call("ec2", "describe_instances", region,
                                          lambda: self._scan_ec2(region)),
                    *self._safe_scan_call("lambda", "list_functions", region,
                                          lambda: self._scan_lambda(region)),
                ]
        """
        try:
            return fn()
        except ClientError as e:
            err = e.response.get("Error", {}) or {}
            code = err.get("Code", "Unknown")
            message = err.get("Message", str(e))
            request_id = (e.response.get("ResponseMetadata") or {}).get("RequestId")
            category = categorize(code)

            scan_err = ScanError(
                domain=self.domain,
                account_id=self.session.account_id,
                region=region,
                service=service,
                operation=operation,
                error_code=code,
                error_type="ClientError",
                message=message,
                request_id=request_id,
                category=category,
            )
            self.errors.append(scan_err.to_dict())
            self._log_categorized(category, service, operation, region, code, message)
            return []
        except Exception as e:
            logger.exception(
                "[%s] %s:%s in %s raised unexpected error",
                self.domain, service, operation, region,
            )
            self.errors.append(ScanError(
                domain=self.domain,
                account_id=self.session.account_id,
                region=region,
                service=service,
                operation=operation,
                error_code="Exception",
                error_type=type(e).__name__,
                message=str(e),
                request_id=None,
                category="unknown",
            ).to_dict())
            return []

    def _log_categorized(
        self, category: str, service: str, operation: str, region: str, code: str, msg: str,
    ) -> None:
        """Log at the right level based on what kind of error we got."""
        if category == "permission_denied":
            logger.warning(
                "[%s] AccessDenied on %s:%s in %s — role lacks permission",
                self.domain, service, operation, region,
            )
        elif category == "not_available":
            logger.info(
                "[%s] %s not available in %s (%s) — skipping",
                self.domain, service, region, code,
            )
        elif category == "retriable":
            logger.warning(
                "[%s] retries exhausted on %s:%s in %s (%s)",
                self.domain, service, operation, region, code,
            )
        else:
            logger.warning(
                "[%s] %s:%s in %s failed (%s): %s",
                self.domain, service, operation, region, code, msg,
            )
