"""
Unit tests for CloudTrail scanner helpers and OrgTrailS3Reader.

Tests parsing logic without real AWS calls.
"""
from __future__ import annotations

import gzip
import json
from unittest.mock import MagicMock

import pytest

from breakbot.scanner.cloudtrail import (
    CloudTrailScanner,
    OrgTrailS3Reader,
    TrailEvent,
    _extract_additional_targets,
    _extract_target_arn,
    _normalize_actor_arn,
)


class TestNormalizeActorArn:
    def test_assumed_role(self):
        arn = "arn:aws:sts::123456789012:assumed-role/MyRole/session-name"
        assert _normalize_actor_arn(arn, "123456789012") == "arn:aws:iam::123456789012:role/MyRole"

    def test_iam_user(self):
        arn = "arn:aws:iam::123456789012:user/admin"
        assert _normalize_actor_arn(arn, "123456789012") == arn

    def test_iam_role(self):
        arn = "arn:aws:iam::123456789012:role/LambdaExec"
        assert _normalize_actor_arn(arn, "123456789012") == arn

    def test_root(self):
        arn = "arn:aws:iam::123456789012:root"
        assert _normalize_actor_arn(arn, "123456789012") == arn

    def test_empty(self):
        assert _normalize_actor_arn("", "123") is None

    def test_unrecognized(self):
        assert _normalize_actor_arn("arn:aws:sts::123:federated-user/Bob", "123") is None


class TestExtractTargetArn:
    def test_assume_role(self):
        ct_event = {"requestParameters": {"roleArn": "arn:aws:iam::222:role/Target"}}
        assert _extract_target_arn("AssumeRole", ct_event, "us-east-1", "111") == "arn:aws:iam::222:role/Target"

    def test_get_secret_value_with_arn(self):
        ct_event = {"requestParameters": {"secretId": "arn:aws:secretsmanager:us-east-1:111:secret:my-secret-abc123"}}
        result = _extract_target_arn("GetSecretValue", ct_event, "us-east-1", "111")
        assert result == "arn:aws:secretsmanager:us-east-1:111:secret:my-secret-abc123"

    def test_get_secret_value_without_arn(self):
        ct_event = {"requestParameters": {"secretId": "my-secret"}}
        assert _extract_target_arn("GetSecretValue", ct_event, "us-east-1", "111") is None

    def test_decrypt_with_key_arn(self):
        key_arn = "arn:aws:kms:us-east-1:111:key/12345678-1234-1234-1234-123456789012"
        ct_event = {"requestParameters": {"keyId": key_arn}}
        assert _extract_target_arn("Decrypt", ct_event, "us-east-1", "111") == key_arn

    def test_decrypt_with_bare_uuid(self):
        key_id = "12345678-1234-1234-1234-123456789012"
        ct_event = {"requestParameters": {"keyId": key_id}}
        result = _extract_target_arn("Decrypt", ct_event, "us-east-1", "111")
        assert result == f"arn:aws:kms:us-east-1:111:key/{key_id}"

    def test_get_parameter(self):
        ct_event = {"requestParameters": {"name": "/app/db-password"}}
        result = _extract_target_arn("GetParameter", ct_event, "us-east-1", "111")
        assert result == "arn:aws:ssm:us-east-1:111:parameter/app/db-password"

    def test_get_parameters_returns_first(self):
        ct_event = {"requestParameters": {"names": ["/param/a", "/param/b", "/param/c"]}}
        result = _extract_target_arn("GetParameters", ct_event, "us-east-1", "111")
        assert result == "arn:aws:ssm:us-east-1:111:parameter/param/a"


class TestExtractAdditionalTargets:
    def test_get_parameters_returns_rest(self):
        ct_event = {"requestParameters": {"names": ["/param/a", "/param/b", "/param/c"]}}
        extras = _extract_additional_targets("GetParameters", ct_event, "us-east-1", "111")
        assert len(extras) == 2
        assert "parameter/param/b" in extras[0]
        assert "parameter/param/c" in extras[1]

    def test_non_get_parameters_returns_empty(self):
        ct_event = {"requestParameters": {"name": "/param/a"}}
        assert _extract_additional_targets("GetParameter", ct_event, "us-east-1", "111") == []

    def test_single_parameter_no_extras(self):
        ct_event = {"requestParameters": {"names": ["/param/only"]}}
        assert _extract_additional_targets("GetParameters", ct_event, "us-east-1", "111") == []


class TestTrailEventSerde:
    def test_roundtrip(self):
        event = TrailEvent(
            event_id="evt-1",
            event_name="AssumeRole",
            event_time="2025-01-01T00:00:00Z",
            actor_arn="arn:aws:iam::111:role/Caller",
            target_arn="arn:aws:iam::222:role/Target",
            region="us-east-1",
            account_id="111",
            source_ip="1.2.3.4",
        )
        d = event.to_dict()
        restored = TrailEvent.from_dict(d)
        assert restored == event

    def test_from_dict_ignores_extra_keys(self):
        d = {
            "event_id": "x",
            "event_name": "Decrypt",
            "event_time": "t",
            "actor_arn": "a",
            "target_arn": None,
            "region": "r",
            "account_id": "111",
            "source_ip": None,
            "extra_field": "ignored",
        }
        event = TrailEvent.from_dict(d)
        assert event.event_id == "x"


class TestOrgTrailS3ReaderParsing:
    """Test _parse_s3_record via the reader class."""

    def _make_reader(self):
        sess = MagicMock()
        return OrgTrailS3Reader(sess, bucket="test-bucket", prefix="AWSLogs", org_id="o-abc")

    def test_parses_assume_role(self):
        reader = self._make_reader()
        record = {
            "eventName": "AssumeRole",
            "eventID": "evt-1",
            "eventTime": "2025-03-01T12:00:00Z",
            "awsRegion": "us-east-1",
            "recipientAccountId": "111111111111",
            "userIdentity": {
                "arn": "arn:aws:sts::111111111111:assumed-role/Admin/session",
                "accountId": "111111111111",
            },
            "requestParameters": {
                "roleArn": "arn:aws:iam::222222222222:role/Target",
            },
            "sourceIPAddress": "10.0.0.1",
        }
        events = reader._parse_s3_record(record)
        assert len(events) == 1
        assert events[0].event_name == "AssumeRole"
        assert events[0].actor_arn == "arn:aws:iam::111111111111:role/Admin"
        assert events[0].target_arn == "arn:aws:iam::222222222222:role/Target"

    def test_expands_get_parameters(self):
        reader = self._make_reader()
        record = {
            "eventName": "GetParameters",
            "eventID": "evt-2",
            "eventTime": "2025-03-01T12:00:00Z",
            "awsRegion": "us-east-1",
            "recipientAccountId": "111111111111",
            "userIdentity": {
                "arn": "arn:aws:iam::111111111111:role/AppRole",
                "accountId": "111111111111",
            },
            "requestParameters": {
                "names": ["/db/host", "/db/password", "/db/port"],
            },
            "sourceIPAddress": "10.0.0.5",
        }
        events = reader._parse_s3_record(record)
        assert len(events) == 3
        assert "parameter/db/host" in events[0].target_arn
        assert "parameter/db/password" in events[1].target_arn
        assert "parameter/db/port" in events[2].target_arn

    def test_skips_uninteresting_events(self):
        reader = self._make_reader()
        record = {
            "eventName": "DescribeInstances",
            "eventID": "evt-3",
            "userIdentity": {"arn": "arn:aws:iam::111:role/X", "accountId": "111"},
            "awsRegion": "us-east-1",
            "recipientAccountId": "111",
        }
        assert reader._parse_s3_record(record) == []

    def test_skips_unresolvable_actor(self):
        reader = self._make_reader()
        record = {
            "eventName": "AssumeRole",
            "eventID": "evt-4",
            "eventTime": "2025-03-01T12:00:00Z",
            "awsRegion": "us-east-1",
            "recipientAccountId": "111",
            "userIdentity": {"arn": "", "accountId": "111"},
            "requestParameters": {"roleArn": "arn:aws:iam::222:role/X"},
        }
        assert reader._parse_s3_record(record) == []


class TestOrgTrailS3Prefixes:
    def test_with_org_id_and_accounts_and_regions(self):
        from datetime import date
        sess = MagicMock()
        reader = OrgTrailS3Reader(sess, bucket="b", prefix="logs", org_id="o-123")
        prefixes = reader._build_s3_prefixes(
            start_date=date(2025, 3, 1),
            account_ids=["111", "222"],
            regions=["us-east-1"],
        )
        assert any("o-123" in p for p in prefixes)
        assert any("111" in p for p in prefixes)
        assert any("us-east-1" in p for p in prefixes)
        # Custom prefix should appear before AWSLogs
        assert all(p.startswith("logs/AWSLogs/") for p in prefixes)

    def test_without_org_id(self):
        from datetime import date
        sess = MagicMock()
        reader = OrgTrailS3Reader(sess, bucket="b", prefix="logs", org_id=None)
        prefixes = reader._build_s3_prefixes(
            start_date=date(2025, 3, 1),
            account_ids=["111"],
            regions=["us-east-1"],
        )
        assert all("o-" not in p for p in prefixes)
        assert any("111" in p for p in prefixes)
        assert all(p.startswith("logs/AWSLogs/") for p in prefixes)

    def test_empty_prefix_no_leading_slash(self):
        """No custom prefix: keys start with AWSLogs/ directly, no leading /."""
        from datetime import date
        sess = MagicMock()
        reader = OrgTrailS3Reader(sess, bucket="b", prefix=None, org_id="o-abc")
        prefixes = reader._build_s3_prefixes(
            start_date=date(2025, 3, 1),
            account_ids=["111"],
            regions=["us-east-1"],
        )
        for p in prefixes:
            assert not p.startswith("/"), f"Prefix has leading slash: {p}"
            assert p.startswith("AWSLogs/"), f"Expected AWSLogs/ start: {p}"
            assert "AWSLogs/AWSLogs" not in p, f"Double AWSLogs: {p}"

    def test_empty_string_prefix_no_leading_slash(self):
        """Empty string prefix behaves same as None."""
        from datetime import date
        sess = MagicMock()
        reader = OrgTrailS3Reader(sess, bucket="b", prefix="", org_id=None)
        prefixes = reader._build_s3_prefixes(
            start_date=date(2025, 3, 1),
            account_ids=["222"],
            regions=["eu-west-1"],
        )
        for p in prefixes:
            assert not p.startswith("/")
            assert p.startswith("AWSLogs/")

    def test_prefix_with_trailing_slash_normalized(self):
        """Trailing slash on prefix is stripped."""
        from datetime import date
        sess = MagicMock()
        reader = OrgTrailS3Reader(sess, bucket="b", prefix="my-prefix/", org_id="o-x")
        prefixes = reader._build_s3_prefixes(
            start_date=date(2025, 3, 1),
            account_ids=["111"],
            regions=["us-east-1"],
        )
        for p in prefixes:
            assert p.startswith("my-prefix/AWSLogs/")
            assert "my-prefix//AWSLogs" not in p

    def test_broad_scan_no_accounts(self):
        """No account_ids = broad prefix for entire org."""
        from datetime import date
        sess = MagicMock()
        reader = OrgTrailS3Reader(sess, bucket="b", prefix=None, org_id="o-123")
        prefixes = reader._build_s3_prefixes(
            start_date=date(2025, 3, 1),
            account_ids=None,
            regions=None,
        )
        assert len(prefixes) == 1
        assert prefixes[0] == "AWSLogs/o-123/"
