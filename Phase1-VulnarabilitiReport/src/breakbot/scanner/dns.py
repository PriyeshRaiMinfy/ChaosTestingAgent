"""
Route53 scanner — hosted zones.

Route53 is a global service; we scan it once from us-east-1.

Key properties:
  - is_private = False  → public zone: records are visible from the internet
  - is_private = True   → private zone: only resolvable from associated VPCs
  - vpc_ids             → which VPCs can resolve this private zone
  - record_count        → large counts often mean dangling records are lurking

Dangling record detection (CNAME/A pointing to deleted resources) requires
live DNS resolution, which is out of scope for a read-only static scanner.
Record count is captured as a proxy signal for manual review.
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class DnsScanner(BaseScanner):
    domain = "dns"
    is_global = True  # Route53 is global — scan once

    def _scan_region(self, region: str) -> list[Resource]:
        # Route53 endpoint is always us-east-1 regardless of scan region
        route53 = self.session.client("route53", region="us-east-1")
        resources: list[Resource] = []

        try:
            paginator = route53.get_paginator("list_hosted_zones")
            for page in paginator.paginate():
                for zone in page.get("HostedZones", []):
                    zone_id = zone["Id"].split("/")[-1]
                    is_private = zone.get("Config", {}).get("PrivateZone", False)

                    # For private zones, get the associated VPCs
                    vpc_ids: list[str] = []
                    if is_private:
                        try:
                            detail = route53.get_hosted_zone(Id=zone_id)
                            vpc_ids = [v["VPCId"] for v in detail.get("VPCs", [])]
                        except ClientError as e:
                            logger.warning(
                                "GetHostedZone %s failed: %s",
                                zone_id,
                                e.response["Error"]["Code"],
                            )

                    arn = f"arn:aws:route53:::hostedzone/{zone_id}"
                    zone_name = zone.get("Name", zone_id).rstrip(".")

                    properties = {
                        "zone_id": zone_id,
                        "fqdn": zone.get("Name", ""),
                        "is_private": is_private,
                        "record_count": zone.get("ResourceRecordSetCount", 0),
                        "comment": zone.get("Config", {}).get("Comment", ""),
                        "vpc_ids": vpc_ids,
                    }

                    resources.append(
                        Resource(
                            arn=arn,
                            resource_type=ResourceType.ROUTE53_HOSTED_ZONE,
                            name=zone_name,
                            region="global",
                            account_id=self.session.account_id,
                            properties=properties,
                        )
                    )
        except ClientError as e:
            logger.warning(
                "Route53 ListHostedZones failed: %s", e.response["Error"]["Code"]
            )
            raise

        return resources
