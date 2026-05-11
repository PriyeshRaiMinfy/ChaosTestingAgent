"""
AWS session and client management.

Centralizes:
  - Boto3 session creation (profile-aware)
  - Per-region client caching (don't recreate clients on every call)
  - Retry/backoff config baked into every client
  - Account ID resolution via STS

Why this matters: boto3's default retry behavior is too gentle for scanning
large accounts. We override with adaptive mode + higher max attempts.
"""
from __future__ import annotations

import logging
from functools import lru_cache

import boto3
from boto3.session import Session
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Adaptive retry handles throttling intelligently — increasing backoff
# when AWS pushes back. 10 attempts is generous but scanners are read-only
# so it's safe.
_BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
)


class AWSSession:
    """
    Wraps a boto3.Session with caching, account discovery, and region enumeration.

    Usage:
        sess = AWSSession(profile="breakbot", region="us-east-1")
        ec2 = sess.client("ec2", region="us-west-2")
        regions = sess.enabled_regions()
    """

    def __init__(self, profile: str | None = None, region: str = "us-east-1"):
        self._session = Session(profile_name=profile, region_name=region)
        self._default_region = region
        self._client_cache: dict[tuple[str, str], object] = {}
        self._account_id: str | None = None

    @property
    def account_id(self) -> str:
        """Resolves the account ID via STS. Cached after first call."""
        if self._account_id is None:
            sts = self._session.client("sts", config=_BOTO_CONFIG)
            self._account_id = sts.get_caller_identity()["Account"]
            logger.info("Resolved account_id=%s", self._account_id)
        return self._account_id

    def client(self, service: str, region: str | None = None):
        """
        Returns a cached boto3 client for (service, region).
        Caching matters — creating clients is expensive when scanning
        15+ regions across 6+ services.
        """
        region = region or self._default_region
        key = (service, region)
        if key not in self._client_cache:
            self._client_cache[key] = self._session.client(
                service, region_name=region, config=_BOTO_CONFIG
            )
        return self._client_cache[key]

    @lru_cache(maxsize=1)
    def enabled_regions(self) -> list[str]:
        """
        Returns all regions enabled for this account.
        Cached because it's slow and never changes mid-scan.
        """
        ec2 = self.client("ec2", region=self._default_region)
        try:
            response = ec2.describe_regions(AllRegions=False)
            regions = sorted(r["RegionName"] for r in response["Regions"])
            logger.info("Discovered %d enabled regions", len(regions))
            return regions
        except ClientError as e:
            logger.error("Failed to enumerate regions: %s", e)
            # Fallback to the default region only — scan can still proceed
            return [self._default_region]
