"""
CloudFront scanner — distributions (global, scanned from us-east-1).
"""
from __future__ import annotations

import logging

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class CloudFrontScanner(BaseScanner):
    domain = "cdn"
    is_global = True  # CloudFront is global — scan once

    def _scan_region(self, region: str) -> list[Resource]:
        return self._safe_scan_call(
            "cloudfront", "list_distributions", region,
            lambda: self._scan_distributions(),
        )

    def _scan_distributions(self) -> list[Resource]:
        cf = self.session.client("cloudfront", region="us-east-1")
        resources: list[Resource] = []

        paginator = cf.get_paginator("list_distributions")
        for page in paginator.paginate():
            dist_list = page.get("DistributionList", {})
            for item in dist_list.get("Items", []):
                try:
                    resources.append(self._normalize_distribution(item))
                except Exception as e:
                    logger.warning(
                        "[cdn] failed to normalize distribution %s: %s",
                        item.get("Id", "?"), e,
                    )

        return resources

    def _normalize_distribution(self, dist: dict) -> Resource:
        dist_id = dist["Id"]
        arn = f"arn:aws:cloudfront::{self.session.account_id}:distribution/{dist_id}"

        default_cb = dist.get("DefaultCacheBehavior") or {}
        viewer_proto = default_cb.get("ViewerProtocolPolicy", "allow-all")
        https_only = viewer_proto in ("https-only", "redirect-to-https")

        origins: list[dict] = []
        for origin in (dist.get("Origins") or {}).get("Items", []):
            s3_origin = origin.get("S3OriginConfig") or {}
            custom_origin = origin.get("CustomOriginConfig") or {}
            origins.append({
                "id": origin.get("Id"),
                "domain_name": origin.get("DomainName"),
                "is_s3_origin": bool(s3_origin),
                "oai": s3_origin.get("OriginAccessIdentity", ""),
                "custom_protocol": custom_origin.get("OriginProtocolPolicy"),
            })

        s3_origins_without_oai = [
            o for o in origins
            if o["is_s3_origin"] and not o["oai"]
        ]

        geo = (dist.get("Restrictions") or {}).get("GeoRestriction") or {}
        geo_type = geo.get("RestrictionType", "none")
        geo_locations = (geo.get("Items") or [])

        logging_cfg = dist.get("Logging") or {}
        has_logging = bool(logging_cfg.get("Enabled"))

        aliases = (dist.get("Aliases") or {}).get("Items", [])

        properties = {
            "distribution_id": dist_id,
            "domain_name": dist.get("DomainName"),
            "aliases": aliases,
            "enabled": dist.get("Enabled", False),
            "status": dist.get("Status"),
            "price_class": dist.get("PriceClass"),
            "is_ipv6_enabled": dist.get("IsIPV6Enabled", False),
            "web_acl_id": dist.get("WebACLId") or "",
            "has_waf": bool(dist.get("WebACLId")),
            "viewer_protocol_policy": viewer_proto,
            "https_only": https_only,
            "origin_count": len(origins),
            "origins": origins,
            "s3_origins_without_oai": [o["domain_name"] for o in s3_origins_without_oai],
            "geo_restriction_type": geo_type,
            "geo_restricted_locations": geo_locations,
            "has_logging": has_logging,
            "logging_bucket": logging_cfg.get("Bucket"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.CLOUDFRONT_DISTRIBUTION,
            name=dist.get("DomainName", dist_id),
            region="global",
            account_id=self.session.account_id,
            properties=properties,
        )
