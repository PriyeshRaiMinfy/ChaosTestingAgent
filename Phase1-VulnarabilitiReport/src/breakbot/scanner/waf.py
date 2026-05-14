"""
WAF scanner — WAFv2 web ACLs (REGIONAL and CLOUDFRONT scope).

CLOUDFRONT-scoped WAFs must be fetched from us-east-1 regardless of the
scan region. We scan them once using the `_cloudfront_scanned` flag.
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class WafScanner(BaseScanner):
    domain = "waf"

    def __init__(self, session):
        super().__init__(session)
        self._cloudfront_scanned = False

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        resources.extend(self._safe_scan_call(
            "wafv2", "list_web_acls(REGIONAL)", region,
            lambda: self._scan_scope(region, "REGIONAL"),
        ))
        # CLOUDFRONT scope must be fetched from us-east-1 exactly once
        if region == "us-east-1" and not self._cloudfront_scanned:
            self._cloudfront_scanned = True
            resources.extend(self._safe_scan_call(
                "wafv2", "list_web_acls(CLOUDFRONT)", region,
                lambda: self._scan_scope(region, "CLOUDFRONT"),
            ))
        return resources

    def _scan_scope(self, region: str, scope: str) -> list[Resource]:
        wafv2 = self.session.client("wafv2", region=region)
        resources: list[Resource] = []
        acl_summaries: list[dict] = []

        # WAFv2 uses NextMarker pagination (no boto3 paginator)
        resp = wafv2.list_web_acls(Scope=scope, Limit=100)
        acl_summaries.extend(resp.get("WebACLs", []))
        while resp.get("NextMarker"):
            resp = wafv2.list_web_acls(
                Scope=scope, Limit=100, NextMarker=resp["NextMarker"]
            )
            acl_summaries.extend(resp.get("WebACLs", []))

        for summary in acl_summaries:
            try:
                resp = wafv2.get_web_acl(
                    Name=summary["Name"], Scope=scope, Id=summary["Id"]
                )
                resources.append(self._normalize_web_acl(resp["WebACL"], region, scope))
            except ClientError as e:
                logger.warning(
                    "WAF GetWebACL %s failed: %s",
                    summary["Name"], e.response["Error"]["Code"],
                )
            except Exception as e:
                logger.warning(
                    "[waf] failed to normalize web ACL %s: %s",
                    summary.get("Name", "?"), e,
                )

        return resources

    def _normalize_web_acl(self, acl: dict, region: str, scope: str) -> Resource:
        arn = acl["ARN"]
        name = acl["Name"]

        default_action = "Allow" if "Allow" in acl.get("DefaultAction", {}) else "Block"
        rules = acl.get("Rules", [])
        managed_rule_groups = [
            r["Statement"]["ManagedRuleGroupStatement"]["Name"]
            for r in rules
            if "ManagedRuleGroupStatement" in r.get("Statement", {})
        ]
        visibility = acl.get("VisibilityConfig", {}) or {}

        properties = {
            "web_acl_id": acl["Id"],
            "name": name,
            "scope": scope,
            "default_action": default_action,
            "rule_count": len(rules),
            "managed_rule_groups": managed_rule_groups,
            "cloudwatch_metrics_enabled": visibility.get("CloudWatchMetricsEnabled", False),
            "sampled_requests_enabled": visibility.get("SampledRequestsEnabled", False),
            "capacity_units": acl.get("Capacity", 0),
        }

        resource_region = region if scope == "REGIONAL" else "global"

        return Resource(
            arn=arn,
            resource_type=ResourceType.WAF_WEB_ACL,
            name=name,
            region=resource_region,
            account_id=self.session.account_id,
            properties=properties,
        )
