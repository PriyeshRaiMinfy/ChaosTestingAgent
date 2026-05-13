"""
Posture finding data model.

A PostureFinding is a deterministic, flag-based observation derived from
already-scanned resource properties — no additional AWS API calls required.
Findings are sorted by severity (CRITICAL first) and written to posture.json
alongside scan.json in the scan output directory.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


_SEVERITY_ORDER = {s.value: i for i, s in enumerate(Severity)}


@dataclass
class PostureFinding:
    check_id: str       # e.g. "SG_OPEN_SSH"
    severity: Severity
    category: str       # "network", "encryption", "identity", "compute", "data", "waf"
    resource_arn: str
    resource_type: str  # ResourceType.value string
    resource_name: str
    region: str
    account_id: str
    title: str          # Short human label
    detail: str         # One-line context (the exact property value that triggered it)
    remediation: str    # What to change

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "category": self.category,
            "resource_arn": self.resource_arn,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "region": self.region,
            "account_id": self.account_id,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }

    @property
    def severity_order(self) -> int:
        return _SEVERITY_ORDER[self.severity.value]
