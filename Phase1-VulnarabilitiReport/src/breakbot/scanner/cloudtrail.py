"""
CloudTrail behavioral scanner.

Unlike every other scanner, this does NOT produce Resource objects.
It produces TrailEvent objects — evidence that specific API calls
actually happened — which get applied as behavioral edges on the
static graph by TrailOverlay.

Free events (management plane — always captured by CloudTrail):
  AssumeRole         → actually_assumed   (Principal → IAM Role)
  GetSecretValue     → actually_accessed  (Role → Secrets Manager secret)
  Decrypt            → actually_accessed  (Role → KMS key)
  GenerateDataKey    → actually_accessed  (Role → KMS key)
  GetParameter       → actually_accessed  (Role → SSM parameter)
  GetParameters      → actually_accessed  (Role → SSM parameters)

NOT free — require CloudTrail data event logging (extra AWS cost):
  S3 GetObject / PutObject
  Lambda Invoke
  DynamoDB GetItem / PutItem

LookupEvents rate limit: 2 requests/second per region.
We pause 0.6s between pages to stay safely under the limit.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_EVENTS_OF_INTEREST = [
    "AssumeRole",
    "GetSecretValue",
    "Decrypt",
    "GenerateDataKey",
    "GetParameter",
    "GetParameters",
]


@dataclass
class TrailEvent:
    """
    A condensed CloudTrail management event.

    actor_arn  — normalized IAM ARN of the caller (assumed-role ARNs are
                 resolved back to the underlying role ARN)
    target_arn — the AWS resource that was the subject of the call, or
                 None if we can't resolve it to an ARN statically
    """
    event_id: str
    event_name: str
    event_time: str       # ISO 8601 string
    actor_arn: str
    target_arn: str | None
    region: str
    account_id: str
    source_ip: str | None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> TrailEvent:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class CloudTrailScanner:
    """
    Fetches CloudTrail management events for the last N days.

    Usage:
        scanner = CloudTrailScanner()
        events = scanner.scan(session, regions, lookback_days=90)
    """

    def scan(
        self,
        session,
        regions: list[str],
        lookback_days: int = 90,
    ) -> list[TrailEvent]:
        all_events: list[TrailEvent] = []
        start_time = datetime.utcnow() - timedelta(days=lookback_days)

        for region in regions:
            try:
                events = self._scan_region(session, region, start_time)
                all_events.extend(events)
                logger.info(
                    "CloudTrail: %d events in %s", len(events), region
                )
            except Exception as e:
                logger.warning("CloudTrail scan failed in %s: %s", region, e)

        logger.info(
            "CloudTrail total: %d behavioral events across %d region(s)",
            len(all_events),
            len(regions),
        )
        return all_events

    def _scan_region(
        self,
        session,
        region: str,
        start_time: datetime,
    ) -> list[TrailEvent]:
        ct = session.client("cloudtrail", region=region)
        events: list[TrailEvent] = []

        for event_name in _EVENTS_OF_INTEREST:
            try:
                events.extend(
                    self._lookup(ct, event_name, start_time, region, session.account_id)
                )
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("AccessDeniedException", "UnsupportedOperationException"):
                    logger.warning(
                        "CloudTrail LookupEvents %s denied in %s: %s",
                        event_name, region, code,
                    )
                else:
                    logger.warning(
                        "CloudTrail LookupEvents %s failed in %s: %s",
                        event_name, region, code,
                    )

        return events

    def _lookup(
        self,
        ct,
        event_name: str,
        start_time: datetime,
        region: str,
        account_id: str,
    ) -> list[TrailEvent]:
        results: list[TrailEvent] = []
        kwargs: dict = {
            "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": event_name}
            ],
            "StartTime": start_time,
            "MaxResults": 50,
        }

        while True:
            resp = ct.lookup_events(**kwargs)

            for raw in resp.get("Events", []):
                event = _parse_event(raw, region, account_id)
                if event:
                    results.append(event)

            next_token = resp.get("NextToken")
            if not next_token:
                break

            kwargs["NextToken"] = next_token
            time.sleep(0.6)  # stay under 2 TPS rate limit

        return results


# ─────────────────────────── Parsing helpers ──────────────────────────────


def _parse_event(raw: dict, region: str, account_id: str) -> TrailEvent | None:
    event_name = raw.get("EventName", "")
    event_id = raw.get("EventId", "")
    raw_time = raw.get("EventTime")
    event_time = (
        raw_time.isoformat() if isinstance(raw_time, datetime) else str(raw_time or "")
    )

    ct_json = raw.get("CloudTrailEvent", "")
    if not ct_json:
        return None
    try:
        ct_event = json.loads(ct_json)
    except (json.JSONDecodeError, TypeError):
        return None

    user_identity = ct_event.get("userIdentity") or {}
    actor_arn = _normalize_actor_arn(
        user_identity.get("arn", ""),
        user_identity.get("accountId") or account_id,
    )
    if not actor_arn:
        return None

    target_arn = _extract_target_arn(event_name, ct_event, region, account_id)
    source_ip = ct_event.get("sourceIPAddress")

    return TrailEvent(
        event_id=event_id,
        event_name=event_name,
        event_time=event_time,
        actor_arn=actor_arn,
        target_arn=target_arn,
        region=region,
        account_id=account_id,
        source_ip=source_ip,
    )


def _normalize_actor_arn(arn: str, account_id: str) -> str | None:
    """
    Convert an STS assumed-role session ARN to the underlying IAM role ARN.

    arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
    → arn:aws:iam::123456789012:role/RoleName
    """
    if not arn:
        return None
    if ":assumed-role/" in arn:
        # format: arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION
        parts = arn.split(":")
        acct = parts[4] if len(parts) > 4 else account_id
        role_segment = parts[-1]                  # "assumed-role/RoleName/Session"
        role_name = role_segment.split("/")[1]    # "RoleName"
        return f"arn:aws:iam::{acct}:role/{role_name}"
    if ":user/" in arn or ":role/" in arn or ":root" in arn:
        return arn
    return None


def _extract_target_arn(
    event_name: str, ct_event: dict, region: str, account_id: str
) -> str | None:
    params = ct_event.get("requestParameters") or {}

    if event_name == "AssumeRole":
        return params.get("roleArn")

    if event_name == "GetSecretValue":
        secret_id = params.get("secretId", "")
        return secret_id if secret_id.startswith("arn:") else None

    if event_name in ("Decrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext"):
        key_id = params.get("keyId", "")
        if not key_id:
            return None
        if key_id.startswith("arn:"):
            return key_id
        # Bare UUID key ID → reconstruct ARN
        if len(key_id) == 36 and key_id.count("-") == 4:
            return f"arn:aws:kms:{region}:{account_id}:key/{key_id}"
        return None

    if event_name == "GetParameter":
        name = params.get("name", "")
        return (
            f"arn:aws:ssm:{region}:{account_id}:parameter/{name.lstrip('/')}"
            if name else None
        )

    if event_name == "GetParameters":
        names = params.get("names") or []
        if names:
            return f"arn:aws:ssm:{region}:{account_id}:parameter/{names[0].lstrip('/')}"
        return None

    return None
