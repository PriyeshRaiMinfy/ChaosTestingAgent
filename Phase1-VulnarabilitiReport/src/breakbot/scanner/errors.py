"""
Structured scanner errors.

Every scanner-level failure is captured as a ScanError and serialized to
the errors[] list in scan output. Categorization lets downstream code
distinguish actionable failures (the role is missing a permission — fix it)
from expected ones (region not opted-in — skip silently) from transient
ones (retries already handled it — log and move on).
"""
from __future__ import annotations

from dataclasses import dataclass

# Role is missing the permission. Not retriable — user must fix IAM policy.
PERMISSION_DENIED_CODES = frozenset({
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "Forbidden",
    "AuthFailure",
})

# Service or region isn't accessible. Not a config bug; skip the call.
NOT_AVAILABLE_CODES = frozenset({
    "OptInRequired",
    "EndpointConnectionError",
    "UnknownEndpoint",
    "InvalidEndpoint",
    "ServiceUnavailable",
})

# Boto3's adaptive retries already tried these. If we see them here,
# retries were exhausted — log without alarm.
RETRIABLE_CODES = frozenset({
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "RequestThrottled",
})


def categorize(error_code: str) -> str:
    """Map an AWS error code to one of four categories."""
    if error_code in PERMISSION_DENIED_CODES:
        return "permission_denied"
    if error_code in NOT_AVAILABLE_CODES:
        return "not_available"
    if error_code in RETRIABLE_CODES:
        return "retriable"
    return "unknown"


@dataclass
class ScanError:
    """Structured error captured by BaseScanner._safe_scan_call."""

    domain: str          # scanner.domain ("compute", "identity", etc.)
    account_id: str
    region: str
    service: str         # AWS service: "ec2", "lambda", "iam"
    operation: str       # AWS API: "describe_instances", "list_functions"
    error_code: str      # AWS error code, or "Exception" for non-ClientError
    error_type: str      # Python class: "ClientError", "KeyError", etc.
    message: str
    request_id: str | None = None
    category: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "account_id": self.account_id,
            "region": self.region,
            "service": self.service,
            "operation": self.operation,
            "error_code": self.error_code,
            "error_type": self.error_type,
            "message": self.message,
            "request_id": self.request_id,
            "category": self.category,
        }
