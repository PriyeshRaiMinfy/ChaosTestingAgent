"""
AWS session and client management.

Centralizes:
  - Boto3 session creation (profile-aware or assumed-role-aware)
  - Per-region client caching (don't recreate clients on every call)
  - Retry/backoff config baked into every client
  - Account ID resolution via STS

Why this matters: boto3's default retry behavior is too gentle for scanning
large accounts. We override with adaptive mode + higher max attempts.

Two construction paths:
  1. Profile-based: AWSSession(profile="breakbot")
        Used for single-account scans, or as the "master" session in an
        Audit account before assuming into members.
  2. Assumed-role: AWSSession.from_assumed_role(source, role_arn=...)
        Used for org-wide scans. The master session assumes BreakBotReadOnly
        in each member account, producing one AWSSession per account.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from boto3.session import Session
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from typing import Any

logger = logging.getLogger(__name__)

# Adaptive retry handles throttling intelligently — increasing backoff
# when AWS pushes back. 10 attempts is generous but scanners are read-only
# so it's safe.
_BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
)

# Assumed-role sessions live for at most 1 hour by default. Most scans
# complete well within this, but we expose a knob for very large orgs.
_DEFAULT_SESSION_DURATION = 3600


class AWSSession:
    """
    Wraps a boto3.Session with caching, account discovery, and region enumeration.

    Construction:
        # Profile-based (single-account or master session)
        sess = AWSSession(profile="breakbot", region="us-east-1")

        # Assumed-role (cross-account from a master session)
        member_sess = AWSSession.from_assumed_role(
            source=sess,
            role_arn="arn:aws:iam::444455556666:role/BreakBotReadOnly",
        )
    """

    def __init__(
        self,
        profile: str | None = None,
        region: str = "us-east-1",
        *,
        credentials: dict[str, str] | None = None,
        account_id: str | None = None,
    ):
        if credentials is not None:
            self._session = Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials.get("SessionToken"),
                region_name=region,
            )
        else:
            self._session = Session(profile_name=profile, region_name=region)

        self._default_region = region
        self._client_cache: dict[tuple[str, str], Any] = {}
        self._account_id: str | None = account_id  # pre-set when assumed
        self._regions_cache: list[str] | None = None

    @classmethod
    def from_assumed_role(
        cls,
        source: AWSSession,
        role_arn: str,
        region: str = "us-east-1",
        session_name: str = "BreakBot",
        external_id: str | None = None,
        duration_seconds: int = _DEFAULT_SESSION_DURATION,
    ) -> AWSSession:
        """
        Assume `role_arn` from `source` and return a new AWSSession backed
        by the temporary credentials.

        The account_id is parsed from the role ARN, saving one STS call.
        """
        sts = source.client("sts", region=region)
        kwargs: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": duration_seconds,
        }
        if external_id:
            kwargs["ExternalId"] = external_id

        response = sts.assume_role(**kwargs)
        creds = response["Credentials"]

        # ARN format: arn:aws:iam::ACCOUNT_ID:role/RoleName
        account_id = role_arn.split(":")[4]

        logger.info("Assumed %s as session %s", role_arn, session_name)

        return cls(
            region=region,
            credentials={
                "AccessKeyId": creds["AccessKeyId"],
                "SecretAccessKey": creds["SecretAccessKey"],
                "SessionToken": creds["SessionToken"],
            },
            account_id=account_id,
        )

    @property
    def default_region(self) -> str:
        """Region used when callers don't pass one explicitly."""
        return self._default_region

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

    def enabled_regions(self) -> list[str]:
        """
        Returns all regions enabled for this account.
        Cached on the instance — never changes mid-scan.
        """
        if self._regions_cache is not None:
            return self._regions_cache

        ec2 = self.client("ec2", region=self._default_region)
        try:
            response = ec2.describe_regions(AllRegions=False)
            self._regions_cache = sorted(r["RegionName"] for r in response["Regions"])
            logger.info("Discovered %d enabled regions", len(self._regions_cache))
        except ClientError as e:
            logger.error("Failed to enumerate regions: %s", e)
            self._regions_cache = [self._default_region]

        return self._regions_cache
