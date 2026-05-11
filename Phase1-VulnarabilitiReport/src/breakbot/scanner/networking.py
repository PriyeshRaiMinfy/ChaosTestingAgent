"""
Networking scanner — VPCs, subnets, security groups, ALBs.

Security group ingress rules are the most important output here. They become
`network_can_reach` edges in the graph. We capture them as structured rule
objects so the LLM can reason about port ranges, CIDR exposure, and SG-to-SG
references without re-parsing AWS-shaped JSON.

ALBs matter because they're the most common internet-facing entry point.
A public ALB pointing at a Lambda or EC2 target is the start of many attack
chains.
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)

# A CIDR like 0.0.0.0/0 in an ingress rule = open to the public internet.
INTERNET_CIDR = "0.0.0.0/0"


class NetworkingScanner(BaseScanner):
    domain = "networking"

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        resources.extend(self._scan_vpcs(region))
        resources.extend(self._scan_security_groups(region))
        resources.extend(self._scan_albs(region))
        return resources

    # ──────────────────────────── VPCs ──────────────────────────────────

    def _scan_vpcs(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region=region)
        try:
            response = ec2.describe_vpcs()
        except ClientError as e:
            logger.warning("VPC scan failed in %s: %s", region, e.response["Error"]["Code"])
            raise

        resources = []
        for vpc in response["Vpcs"]:
            vpc_id = vpc["VpcId"]
            arn = f"arn:aws:ec2:{region}:{self.session.account_id}:vpc/{vpc_id}"
            tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
            resources.append(Resource(
                arn=arn,
                resource_type=ResourceType.VPC,
                name=tags.get("Name", vpc_id),
                region=region,
                account_id=self.session.account_id,
                tags=tags,
                properties={
                    "vpc_id": vpc_id,
                    "cidr_block": vpc.get("CidrBlock"),
                    "is_default": vpc.get("IsDefault", False),
                    "state": vpc.get("State"),
                },
            ))
        return resources

    # ──────────────────────── Security Groups ───────────────────────────

    def _scan_security_groups(self, region: str) -> list[Resource]:
        """
        Capture ingress rules in a structured form. Each rule will become a
        graph edge in Phase 4. We flag `internet_exposed` here so the graph
        builder can quickly find entry points without reparsing rules.
        """
        ec2 = self.session.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_security_groups")

        resources = []
        try:
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    resources.append(self._normalize_sg(sg, region))
        except ClientError as e:
            logger.warning("SG scan failed in %s: %s", region, e.response["Error"]["Code"])
            raise
        return resources

    def _normalize_sg(self, sg: dict, region: str) -> Resource:
        sg_id = sg["GroupId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:security-group/{sg_id}"

        ingress_rules = [self._parse_rule(r) for r in sg.get("IpPermissions", [])]
        egress_rules = [self._parse_rule(r) for r in sg.get("IpPermissionsEgress", [])]

        # Flag: any ingress rule open to 0.0.0.0/0
        internet_exposed = any(
            INTERNET_CIDR in r["cidrs"] for r in ingress_rules
        )

        properties = {
            "group_id": sg_id,
            "group_name": sg.get("GroupName"),
            "description": sg.get("Description"),
            "vpc_id": sg.get("VpcId"),
            "ingress_rules": ingress_rules,
            "egress_rules": egress_rules,
            "internet_exposed": internet_exposed,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.SECURITY_GROUP,
            name=sg.get("GroupName", sg_id),
            region=region,
            account_id=self.session.account_id,
            tags={t["Key"]: t["Value"] for t in sg.get("Tags", [])},
            properties=properties,
        )

    @staticmethod
    def _parse_rule(rule: dict) -> dict:
        """Flatten an AWS IpPermission into a clean rule dict."""
        return {
            "protocol": rule.get("IpProtocol"),
            "from_port": rule.get("FromPort"),
            "to_port": rule.get("ToPort"),
            "cidrs": [r["CidrIp"] for r in rule.get("IpRanges", [])],
            "ipv6_cidrs": [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])],
            "referenced_sgs": [
                ref["GroupId"] for ref in rule.get("UserIdGroupPairs", [])
            ],
        }

    # ───────────────────────────── ALBs ──────────────────────────────────

    def _scan_albs(self, region: str) -> list[Resource]:
        elbv2 = self.session.client("elbv2", region=region)
        paginator = elbv2.get_paginator("describe_load_balancers")

        resources = []
        try:
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    resources.append(self._normalize_alb(lb, region))
        except ClientError as e:
            logger.warning("ALB scan failed in %s: %s", region, e.response["Error"]["Code"])
            raise
        return resources

    def _normalize_alb(self, lb: dict, region: str) -> Resource:
        arn = lb["LoadBalancerArn"]
        name = lb["LoadBalancerName"]
        is_internet_facing = lb.get("Scheme") == "internet-facing"

        properties = {
            "lb_type": lb.get("Type"),
            "scheme": lb.get("Scheme"),
            "is_internet_facing": is_internet_facing,
            "vpc_id": lb.get("VpcId"),
            "dns_name": lb.get("DNSName"),
            "availability_zones": [az["ZoneName"] for az in lb.get("AvailabilityZones", [])],
            "security_group_ids": lb.get("SecurityGroups", []),
            "state": lb.get("State", {}).get("Code"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.ALB,
            name=name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )
