"""
Unit tests for BaseScanner — focused on the new _safe_scan_call helper
and the ScanError categorization.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from breakbot.scanner.base import BaseScanner
from breakbot.scanner.errors import (
    NOT_AVAILABLE_CODES,
    PERMISSION_DENIED_CODES,
    RETRIABLE_CODES,
    ScanError,
    categorize,
)


# ─────────────────────── Categorization function ──────────────────────────

@pytest.mark.parametrize("code", sorted(PERMISSION_DENIED_CODES))
def test_categorize_permission_denied(code: str):
    assert categorize(code) == "permission_denied"


@pytest.mark.parametrize("code", sorted(NOT_AVAILABLE_CODES))
def test_categorize_not_available(code: str):
    assert categorize(code) == "not_available"


@pytest.mark.parametrize("code", sorted(RETRIABLE_CODES))
def test_categorize_retriable(code: str):
    assert categorize(code) == "retriable"


def test_categorize_unknown_falls_through():
    assert categorize("SomeNeverSeenCode") == "unknown"
    assert categorize("") == "unknown"


# ─────────────────────────── ScanError model ──────────────────────────────

def test_scan_error_to_dict_round_trip():
    err = ScanError(
        domain="compute",
        account_id="111122223333",
        region="us-east-1",
        service="ec2",
        operation="describe_instances",
        error_code="AccessDenied",
        error_type="ClientError",
        message="missing perm",
        request_id="req-abc",
        category="permission_denied",
    )
    d = err.to_dict()
    assert d["domain"] == "compute"
    assert d["error_code"] == "AccessDenied"
    assert d["category"] == "permission_denied"
    assert d["request_id"] == "req-abc"


# ───────────────────────── _safe_scan_call ────────────────────────────────

class _StubScanner(BaseScanner):
    """Minimal BaseScanner subclass for testing the helper directly."""
    domain = "test"

    def _scan_region(self, region: str) -> list:
        return []


def _scanner() -> _StubScanner:
    session = MagicMock()
    session.account_id = "111122223333"
    return _StubScanner(session)


def _client_error(code: str, message: str = "test", request_id: str | None = "req-123") -> ClientError:
    response: dict[str, Any] = {
        "Error": {"Code": code, "Message": message},
    }
    if request_id is not None:
        response["ResponseMetadata"] = {"RequestId": request_id}
    return ClientError(error_response=response, operation_name="Test")


def test_safe_scan_call_returns_result_on_success():
    s = _scanner()
    out = s._safe_scan_call("ec2", "describe_instances", "us-east-1",
                            lambda: ["a", "b", "c"])
    assert out == ["a", "b", "c"]
    assert s.errors == []


def test_safe_scan_call_records_access_denied():
    s = _scanner()
    out = s._safe_scan_call(
        "ec2", "describe_instances", "us-east-1",
        lambda: (_ for _ in ()).throw(_client_error("AccessDenied", "missing perm")),
    )
    assert out == []
    assert len(s.errors) == 1
    err = s.errors[0]
    assert err["error_code"] == "AccessDenied"
    assert err["category"] == "permission_denied"
    assert err["service"] == "ec2"
    assert err["operation"] == "describe_instances"
    assert err["region"] == "us-east-1"
    assert err["account_id"] == "111122223333"
    assert err["request_id"] == "req-123"
    assert err["error_type"] == "ClientError"


def test_safe_scan_call_records_opt_in_required_as_not_available():
    s = _scanner()
    s._safe_scan_call(
        "ec2", "describe_instances", "ap-south-2",
        lambda: (_ for _ in ()).throw(_client_error("OptInRequired")),
    )
    assert len(s.errors) == 1
    assert s.errors[0]["category"] == "not_available"


def test_safe_scan_call_records_throttling_as_retriable():
    s = _scanner()
    s._safe_scan_call(
        "ec2", "describe_instances", "us-east-1",
        lambda: (_ for _ in ()).throw(_client_error("Throttling")),
    )
    assert len(s.errors) == 1
    assert s.errors[0]["category"] == "retriable"


def test_safe_scan_call_records_unknown_client_error():
    s = _scanner()
    s._safe_scan_call(
        "ec2", "describe_instances", "us-east-1",
        lambda: (_ for _ in ()).throw(_client_error("WeirdNeverSeenError")),
    )
    assert len(s.errors) == 1
    assert s.errors[0]["category"] == "unknown"
    assert s.errors[0]["error_code"] == "WeirdNeverSeenError"


def test_safe_scan_call_catches_non_client_exceptions():
    """A KeyError in a sub-call should be recorded, not re-raised."""
    s = _scanner()

    def boom() -> list:
        raise KeyError("missing-field")

    out = s._safe_scan_call("ec2", "describe_instances", "us-east-1", boom)
    assert out == []
    assert len(s.errors) == 1
    err = s.errors[0]
    assert err["error_code"] == "Exception"
    assert err["error_type"] == "KeyError"
    assert err["category"] == "unknown"


def test_safe_scan_call_isolates_services_in_same_region():
    """
    The core reliability claim: if one service call fails, the next service
    call in the same _scan_region run still executes.
    """
    s = _scanner()

    out1 = s._safe_scan_call(
        "ec2", "describe_instances", "us-east-1",
        lambda: (_ for _ in ()).throw(_client_error("AccessDenied")),
    )
    out2 = s._safe_scan_call(
        "lambda", "list_functions", "us-east-1",
        lambda: ["fn-1", "fn-2"],
    )

    assert out1 == []
    assert out2 == ["fn-1", "fn-2"]
    assert len(s.errors) == 1
    assert s.errors[0]["service"] == "ec2"
