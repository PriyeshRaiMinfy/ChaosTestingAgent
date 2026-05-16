"""
Networking scanner — VPCs, security groups, ALBs, NAT Gateways, Internet Gateways.

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

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)

INTERNET_CIDR = "0.0.0.0/0"


class NetworkingScanner(BaseScanner):
    domain = "networking"

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        resources.extend(self._safe_scan_call(
            "ec2", "describe_vpcs", region, lambda: self._scan_vpcs(region),
        ))
        resources.extend(self._safe_scan_call(
            "ec2", "describe_security_groups", region, lambda: self._scan_security_groups(region),
        ))
        resources.extend(self._safe_scan_call(
            "elbv2", "describe_load_balancers", region, lambda: self._scan_albs(region),
        ))
        resources.extend(self._safe_scan_call(
            "elbv2", "describe_target_groups", region, lambda: self._scan_target_groups(region),
        ))
        resources.extend(self._safe_scan_call(
            "ec2", "describe_nat_gateways", region, lambda: self._scan_nat_gateways(region),
        ))
        resources.extend(self._safe_scan_call(
            "ec2", "describe_internet_gateways", region, lambda: self._scan_internet_gateways(region),
        ))
        return resources

    # ──────────────────────────── VPCs ──────────────────────────────────

    def _scan_vpcs(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region=region)
        response = ec2.describe_vpcs()

        resources = []
        for vpc in response["Vpcs"]:
            try:
                resources.append(self._normalize_vpc(vpc, region))
            except Exception as e:
                logger.warning(
                    "[networking] failed to normalize VPC %s: %s",
                    vpc.get("VpcId", "?"), e,
                )
        return resources

    def _normalize_vpc(self, vpc: dict, region: str) -> Resource:
        vpc_id = vpc["VpcId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:vpc/{vpc_id}"
        tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
        return Resource(
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
        )

    # ──────────────────────── Security Groups ───────────────────────────

    def _scan_security_groups(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_security_groups")

        resources = []
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                try:
                    resources.append(self._normalize_sg(sg, region))
                except Exception as e:
                    logger.warning(
                        "[networking] failed to normalize SG %s: %s",
                        sg.get("GroupId", "?"), e,
                    )
        return resources

    def _normalize_sg(self, sg: dict, region: str) -> Resource:
        sg_id = sg["GroupId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:security-group/{sg_id}"

        ingress_rules = [self._parse_rule(r) for r in sg.get("IpPermissions", [])]
        egress_rules = [self._parse_rule(r) for r in sg.get("IpPermissionsEgress", [])]

        internet_exposed = any(INTERNET_CIDR in r["cidrs"] for r in ingress_rules)

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
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                try:
                    resources.append(self._normalize_alb(lb, region))
                except Exception as e:
                    logger.warning(
                        "[networking] failed to normalize LB %s: %s",
                        lb.get("LoadBalancerName", "?"), e,
                    )
        return resources

    def _normalize_alb(self, lb: dict, region: str) -> Resource:
        arn = lb["LoadBalancerArn"]
        name = lb["LoadBalancerName"]
        lb_type = lb.get("Type", "application")
        is_internet_facing = lb.get("Scheme") == "internet-facing"

        properties = {
            "lb_type": lb_type,
            "scheme": lb.get("Scheme"),
            "is_internet_facing": is_internet_facing,
            "is_nlb": lb_type == "network",
            "is_alb": lb_type == "application",
            "is_gwlb": lb_type == "gateway",
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

    # ─────────────────────── Target Groups ────────────────────────────────

    def _scan_target_groups(self, region: str) -> list[Resource]:
        elbv2 = self.session.client("elbv2", region=region)
        paginator = elbv2.get_paginator("describe_target_groups")
        resources: list[Resource] = []
        for page in paginator.paginate():
            for tg in page.get("TargetGroups", []):
                try:
                    resources.append(
                        self._normalize_target_group(tg, region, elbv2)
                    )
                except Exception as e:
                    logger.warning(
                        "[networking] failed to normalize target group %s: %s",
                        tg.get("TargetGroupName", "?"), e,
                    )
        return resources

    def _normalize_target_group(
        self, tg: dict, region: str, elbv2
    ) -> Resource:
        arn = tg["TargetGroupArn"]
        name = tg["TargetGroupName"]

        registered_targets = self._fetch_registered_targets(elbv2, arn)

        properties = {
            "target_group_name": name,
            "protocol": tg.get("Protocol"),
            "port": tg.get("Port"),
            "vpc_id": tg.get("VpcId"),
            "target_type": tg.get("TargetType"),
            "health_check_enabled": tg.get("HealthCheckEnabled", True),
            "health_check_protocol": tg.get("HealthCheckProtocol"),
            "health_check_port": tg.get("HealthCheckPort"),
            "lb_arns": tg.get("LoadBalancerArns", []),
            "registered_targets": registered_targets,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.LOAD_BALANCER_TARGET_GROUP,
            name=name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )

    def _fetch_registered_targets(self, elbv2, tg_arn: str) -> list[dict]:
        """Fetch compute targets registered to a target group."""
        try:
            resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
            return [
                {"id": t["Target"]["Id"], "port": t["Target"].get("Port")}
                for t in resp.get("TargetHealthDescriptions", [])
            ]
        except Exception as e:
            logger.debug(
                "[networking] describe_target_health failed for %s: %s",
                tg_arn, e,
            )
            return []

    # ─────────────────────── NAT Gateways ─────────────────────────────────

    def _scan_nat_gateways(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_nat_gateways")
        resources: list[Resource] = []
        for page in paginator.paginate(
            Filter=[{"Name": "state", "Values": ["available", "pending"]}]
        ):
            for ngw in page.get("NatGateways", []):
                try:
                    resources.append(self._normalize_nat_gateway(ngw, region))
                except Exception as e:
                    logger.warning(
                        "[networking] failed to normalize NAT gateway %s: %s",
                        ngw.get("NatGatewayId", "?"), e,
                    )
        return resources

    def _normalize_nat_gateway(self, ngw: dict, region: str) -> Resource:
        ngw_id = ngw["NatGatewayId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:natgateway/{ngw_id}"
        tags = {t["Key"]: t["Value"] for t in ngw.get("Tags", [])}
        public_ips = [
            addr["PublicIp"]
            for addr in ngw.get("NatGatewayAddresses", [])
            if addr.get("PublicIp")
        ]

        properties = {
            "nat_gateway_id": ngw_id,
            "state": ngw.get("State"),
            "connectivity_type": ngw.get("ConnectivityType", "public"),
            "vpc_id": ngw.get("VpcId"),
            "subnet_id": ngw.get("SubnetId"),
            "public_ips": public_ips,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.NAT_GATEWAY,
            name=tags.get("Name", ngw_id),
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    # ──────────────────── Internet Gateways ───────────────────────────────

    def _scan_internet_gateways(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_internet_gateways")
        resources: list[Resource] = []
        for page in paginator.paginate():
            for igw in page.get("InternetGateways", []):
                try:
                    resources.append(self._normalize_internet_gateway(igw, region))
                except Exception as e:
                    logger.warning(
                        "[networking] failed to normalize IGW %s: %s",
                        igw.get("InternetGatewayId", "?"), e,
                    )
        return resources

    def _normalize_internet_gateway(self, igw: dict, region: str) -> Resource:
        igw_id = igw["InternetGatewayId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:internet-gateway/{igw_id}"
        tags = {t["Key"]: t["Value"] for t in igw.get("Tags", [])}

        attachments = igw.get("Attachments", [])
        attached_vpc_ids = [a["VpcId"] for a in attachments if a.get("State") == "available"]

        properties = {
            "internet_gateway_id": igw_id,
            "attached_vpc_ids": attached_vpc_ids,
            "is_attached": bool(attached_vpc_ids),
            "vpc_id": attached_vpc_ids[0] if attached_vpc_ids else None,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.INTERNET_GATEWAY,
            name=tags.get("Name", igw_id),
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )
