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
    "GenerateDataKeyWithoutPlaintext",
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
        lookback_days: int = 14,
        max_pages: int = 20,
    ) -> list[TrailEvent]:
        all_events: list[TrailEvent] = []
        start_time = datetime.utcnow() - timedelta(days=lookback_days)

        for region in regions:
            try:
                events = self._scan_region(session, region, start_time, max_pages)
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
        max_pages: int = 20,
    ) -> list[TrailEvent]:
        ct = session.client("cloudtrail", region=region)
        events: list[TrailEvent] = []

        for i, event_name in enumerate(_EVENTS_OF_INTEREST):
            if i > 0:
                time.sleep(0.6)  # rate limit: 2 TPS per region
            try:
                events.extend(
                    self._lookup(ct, event_name, start_time, region, session.account_id, max_pages)
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

    _MAX_PAGES = 100  # absolute safety cap

    def _lookup(
        self,
        ct,
        event_name: str,
        start_time: datetime,
        region: str,
        account_id: str,
        max_pages: int = 20,
    ) -> list[TrailEvent]:
        results: list[TrailEvent] = []
        kwargs: dict = {
            "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": event_name}
            ],
            "StartTime": start_time,
            "MaxResults": 50,
        }
        page_limit = min(max_pages, self._MAX_PAGES)

        for _ in range(page_limit):
            resp = ct.lookup_events(**kwargs)

            for raw in resp.get("Events", []):
                event = _parse_event(raw, region, account_id)
                if event:
                    results.append(event)
                    ct_json = raw.get("CloudTrailEvent", "")
                    if ct_json:
                        try:
                            ct_event = json.loads(ct_json)
                            for extra_arn in _extract_additional_targets(
                                event_name, ct_event, region, account_id
                            ):
                                results.append(TrailEvent(
                                    event_id=event.event_id,
                                    event_name=event.event_name,
                                    event_time=event.event_time,
                                    actor_arn=event.actor_arn,
                                    target_arn=extra_arn,
                                    region=region,
                                    account_id=account_id,
                                    source_ip=event.source_ip,
                                ))
                        except (json.JSONDecodeError, TypeError):
                            pass

            next_token = resp.get("NextToken")
            if not next_token:
                break

            kwargs["NextToken"] = next_token
            time.sleep(0.6)  # stay under 2 TPS rate limit
        else:
            logger.warning(
                "CloudTrail %s in %s: hit %d page limit, results may be incomplete",
                event_name, region, page_limit,
            )

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
        # Handled specially in _parse_event — returns first param here,
        # additional params expanded by caller via _expand_multi_target_events
        names = params.get("names") or []
        if names:
            return f"arn:aws:ssm:{region}:{account_id}:parameter/{names[0].lstrip('/')}"
        return None

    return None


def _extract_additional_targets(
    event_name: str, ct_event: dict, region: str, account_id: str
) -> list[str]:
    """For multi-target events (GetParameters), return ARNs beyond the first."""
    if event_name != "GetParameters":
        return []
    params = ct_event.get("requestParameters") or {}
    names = params.get("names") or []
    return [
        f"arn:aws:ssm:{region}:{account_id}:parameter/{n.lstrip('/')}"
        for n in names[1:]
    ]


# ──────────────────── S3-based Org Trail Reader ──────────────────────────────


class OrgTrailS3Reader:
    """
    Reads CloudTrail logs directly from the Organization Trail S3 bucket.

    Advantages over LookupEvents:
      - No 90-day limit (reads as far back as logs exist)
      - Covers ALL accounts in the org from a single bucket
      - No per-account AssumeRole needed for trail data
      - Higher throughput (S3 pagination vs. 2 TPS rate limit)

    S3 key structure (with org):
      {prefix}/AWSLogs/{org_id}/{account_id}/CloudTrail/{region}/YYYY/MM/DD/*.json.gz
    S3 key structure (without org):
      AWSLogs/{account_id}/CloudTrail/{region}/YYYY/MM/DD/*.json.gz

    The `prefix` param is the CloudTrail S3KeyPrefix configured on the trail
    (the part BEFORE "AWSLogs"). Pass None or "" if the trail has no custom prefix.

    Usage:
        reader = OrgTrailS3Reader(session, bucket="org-trail-bucket", prefix="my-prefix")
        events = reader.read(lookback_days=90, account_ids=["123...", "456..."])
    """

    def __init__(
        self,
        session,
        bucket: str,
        prefix: str | None = None,
        org_id: str | None = None,
    ):
        self._session = session
        self._bucket = bucket
        self._prefix = prefix or ""
        self._org_id = org_id

    def read(
        self,
        lookback_days: int = 90,
        account_ids: list[str] | None = None,
        regions: list[str] | None = None,
    ) -> list[TrailEvent]:
        """
        Read and parse CloudTrail logs from S3.

        Args:
            lookback_days: how far back to read
            account_ids: filter to specific accounts (None = all found)
            regions: filter to specific regions (None = all found)
        """
        import gzip
        from datetime import date

        s3 = self._session.client("s3", region="us-east-1")
        all_events: list[TrailEvent] = []
        start_date = date.today() - timedelta(days=lookback_days)

        # Build date range prefixes to list
        prefixes_to_scan = self._build_s3_prefixes(
            start_date, account_ids, regions
        )

        for s3_prefix in prefixes_to_scan:
            try:
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(
                    Bucket=self._bucket, Prefix=s3_prefix
                ):
                    for obj in page.get("Contents", []):
                        key = obj["Key"]
                        if not key.endswith(".json.gz"):
                            continue
                        try:
                            resp = s3.get_object(Bucket=self._bucket, Key=key)
                            raw_bytes = gzip.decompress(resp["Body"].read())
                            log_data = json.loads(raw_bytes)
                            for record in log_data.get("Records", []):
                                all_events.extend(self._parse_s3_record(record))
                        except Exception as e:
                            logger.debug("Failed to parse %s: %s", key, e)
            except Exception as e:
                logger.warning("Failed to list S3 prefix %s: %s", s3_prefix, e)

        logger.info(
            "Org trail S3: %d behavioral events from bucket %s",
            len(all_events), self._bucket,
        )
        return all_events

    def _build_s3_prefixes(
        self,
        start_date,
        account_ids: list[str] | None,
        regions: list[str] | None,
    ) -> list[str]:
        """Build S3 key prefixes for the date range we want to scan."""
        from datetime import date, timedelta as td

        prefixes: list[str] = []
        # Build root: "{prefix}/AWSLogs" or just "AWSLogs" if no custom prefix
        base = self._prefix.strip("/") if self._prefix else ""
        root = f"{base}/AWSLogs" if base else "AWSLogs"

        # CloudTrail S3 structure:
        #   {root}/{org_id}/{acct}/CloudTrail/{region}/YYYY/MM/DD/*.json.gz
        # or without org:
        #   {root}/{acct}/CloudTrail/{region}/YYYY/MM/DD/*.json.gz
        current = start_date
        today = date.today()

        while current <= today:
            year = current.strftime("%Y")
            month = current.strftime("%m")
            day = current.strftime("%d")

            if account_ids:
                for acct in account_ids:
                    if regions:
                        for reg in regions:
                            if self._org_id:
                                prefixes.append(
                                    f"{root}/{self._org_id}/{acct}/CloudTrail/{reg}/{year}/{month}/{day}/"
                                )
                            else:
                                prefixes.append(
                                    f"{root}/{acct}/CloudTrail/{reg}/{year}/{month}/{day}/"
                                )
                    else:
                        if self._org_id:
                            prefixes.append(
                                f"{root}/{self._org_id}/{acct}/CloudTrail/"
                            )
                        else:
                            prefixes.append(
                                f"{root}/{acct}/CloudTrail/"
                            )
                        break  # only need one prefix per account if no region filter
            else:
                # Broad scan — prefix by date across all accounts
                if self._org_id:
                    prefixes.append(f"{root}/{self._org_id}/")
                else:
                    prefixes.append(f"{root}/")
                break  # single broad prefix is enough

            current += td(days=1)

        return prefixes

    def _parse_s3_record(self, record: dict) -> list[TrailEvent]:
        """Parse a single CloudTrail record from S3 JSON log. Expands multi-target events."""
        event_name = record.get("eventName", "")
        if event_name not in _EVENTS_OF_INTEREST:
            return []

        user_identity = record.get("userIdentity") or {}
        account_id = record.get("recipientAccountId") or user_identity.get("accountId", "")
        region = record.get("awsRegion", "")

        actor_arn = _normalize_actor_arn(
            user_identity.get("arn", ""), account_id
        )
        if not actor_arn:
            return []

        target_arn = _extract_target_arn(
            event_name, record, region, account_id
        )
        source_ip = record.get("sourceIPAddress")
        event_time = record.get("eventTime", "")
        event_id = record.get("eventID", "")

        event = TrailEvent(
            event_id=event_id,
            event_name=event_name,
            event_time=event_time,
            actor_arn=actor_arn,
            target_arn=target_arn,
            region=region,
            account_id=account_id,
            source_ip=source_ip,
        )
        results = [event]

        for extra_arn in _extract_additional_targets(event_name, record, region, account_id):
            results.append(TrailEvent(
                event_id=event_id,
                event_name=event_name,
                event_time=event_time,
                actor_arn=actor_arn,
                target_arn=extra_arn,
                region=region,
                account_id=account_id,
                source_ip=source_ip,
            ))

        return results
