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
            "ec2", "describe_subnets", region, lambda: self._scan_subnets(region),
        ))
        resources.extend(self._safe_scan_call(
            "ec2", "describe_route_tables", region, lambda: self._scan_route_tables(region),
        ))
        resources.extend(self._safe_scan_call(
            "ec2", "describe_network_acls", region, lambda: self._scan_nacls(region),
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
        resources.extend(self._safe_scan_call(
            "ec2", "describe_vpc_peering_connections", region, lambda: self._scan_vpc_peering(region),
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

    # ──────────────────────────── Subnets ─────────────────────────────────

    def _scan_subnets(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_subnets")
        resources: list[Resource] = []
        for page in paginator.paginate():
            for subnet in page.get("Subnets", []):
                try:
                    resources.append(self._normalize_subnet(subnet, region))
                except Exception as e:
                    logger.warning(
                        "[networking] failed to normalize subnet %s: %s",
                        subnet.get("SubnetId", "?"), e,
                    )
        return resources

    def _normalize_subnet(self, subnet: dict, region: str) -> Resource:
        subnet_id = subnet["SubnetId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:subnet/{subnet_id}"
        tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}

        properties = {
            "subnet_id": subnet_id,
            "vpc_id": subnet.get("VpcId"),
            "cidr_block": subnet.get("CidrBlock"),
            "availability_zone": subnet.get("AvailabilityZone"),
            "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch", False),
            "available_ip_count": subnet.get("AvailableIpAddressCount"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.SUBNET,
            name=tags.get("Name", subnet_id),
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    # ─────────────────────────── Route Tables ─────────────────────────────

    def _scan_route_tables(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_route_tables")
        resources: list[Resource] = []
        for page in paginator.paginate():
            for rt in page.get("RouteTables", []):
                try:
                    resources.append(self._normalize_route_table(rt, region))
                except Exception as e:
                    logger.warning(
                        "[networking] failed to normalize route table %s: %s",
                        rt.get("RouteTableId", "?"), e,
                    )
        return resources

    def _normalize_route_table(self, rt: dict, region: str) -> Resource:
        rt_id = rt["RouteTableId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:route-table/{rt_id}"
        tags = {t["Key"]: t["Value"] for t in rt.get("Tags", [])}

        associations = rt.get("Associations", [])
        associated_subnet_ids = [
            a["SubnetId"] for a in associations
            if a.get("SubnetId") and a.get("AssociationState", {}).get("State") != "disassociated"
        ]
        is_main = any(a.get("Main", False) for a in associations)

        routes = []
        has_igw_route = False
        has_nat_route = False
        has_tgw_route = False
        has_pcx_route = False

        for route in rt.get("Routes", []):
            dest = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock") or ""
            gw_id = route.get("GatewayId", "")
            nat_id = route.get("NatGatewayId", "")
            tgw_id = route.get("TransitGatewayId", "")
            pcx_id = route.get("VpcPeeringConnectionId", "")
            state = route.get("State", "active")

            if state != "active":
                continue

            target = gw_id or nat_id or tgw_id or pcx_id or route.get("NetworkInterfaceId", "")

            if dest in (INTERNET_CIDR, "::/0"):
                if gw_id.startswith("igw-"):
                    has_igw_route = True
                elif nat_id:
                    has_nat_route = True
                elif tgw_id:
                    has_tgw_route = True

            if pcx_id:
                has_pcx_route = True
            if tgw_id:
                has_tgw_route = True

            routes.append({
                "destination": dest,
                "target": target,
                "target_type": (
                    "igw" if gw_id.startswith("igw-") else
                    "nat" if nat_id else
                    "tgw" if tgw_id else
                    "pcx" if pcx_id else
                    "local" if gw_id == "local" else
                    "other"
                ),
            })

        properties = {
            "route_table_id": rt_id,
            "vpc_id": rt.get("VpcId"),
            "is_main": is_main,
            "associated_subnet_ids": associated_subnet_ids,
            "routes": routes,
            "has_igw_route": has_igw_route,
            "has_nat_route": has_nat_route,
            "has_tgw_route": has_tgw_route,
            "has_pcx_route": has_pcx_route,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.ROUTE_TABLE,
            name=tags.get("Name", rt_id),
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    # ──────────────────────────── NACLs ───────────────────────────────────

    def _scan_nacls(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_network_acls")
        resources: list[Resource] = []
        for page in paginator.paginate():
            for nacl in page.get("NetworkAcls", []):
                try:
                    resources.append(self._normalize_nacl(nacl, region))
                except Exception as e:
                    logger.warning(
                        "[networking] failed to normalize NACL %s: %s",
                        nacl.get("NetworkAclId", "?"), e,
                    )
        return resources

    def _normalize_nacl(self, nacl: dict, region: str) -> Resource:
        nacl_id = nacl["NetworkAclId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:network-acl/{nacl_id}"
        tags = {t["Key"]: t["Value"] for t in nacl.get("Tags", [])}

        associated_subnet_ids = [
            a["SubnetId"] for a in nacl.get("Associations", [])
            if a.get("SubnetId")
        ]

        inbound_rules = []
        outbound_rules = []
        blocks_all_inbound = False

        for entry in nacl.get("Entries", []):
            rule = {
                "rule_number": entry.get("RuleNumber"),
                "protocol": entry.get("Protocol"),
                "action": entry.get("RuleAction"),
                "cidr": entry.get("CidrBlock") or entry.get("Ipv6CidrBlock", ""),
                "from_port": entry.get("PortRange", {}).get("From"),
                "to_port": entry.get("PortRange", {}).get("To"),
            }
            if entry.get("Egress"):
                outbound_rules.append(rule)
            else:
                inbound_rules.append(rule)
                if (
                    rule["action"] == "deny"
                    and rule["cidr"] in (INTERNET_CIDR, "::/0")
                    and rule["protocol"] == "-1"
                    and rule["rule_number"] < 100
                ):
                    blocks_all_inbound = True

        properties = {
            "network_acl_id": nacl_id,
            "vpc_id": nacl.get("VpcId"),
            "is_default": nacl.get("IsDefault", False),
            "associated_subnet_ids": associated_subnet_ids,
            "inbound_rules": inbound_rules,
            "outbound_rules": outbound_rules,
            "blocks_all_inbound": blocks_all_inbound,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.NETWORK_ACL,
            name=tags.get("Name", nacl_id),
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    # ───────────────────── VPC Peering Connections ────────────────────────

    def _scan_vpc_peering(self, region: str) -> list[Resource]:
        ec2 = self.session.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_vpc_peering_connections")
        resources: list[Resource] = []
        for page in paginator.paginate(
            Filters=[{"Name": "status-code", "Values": ["active"]}]
        ):
            for pcx in page.get("VpcPeeringConnections", []):
                try:
                    resources.append(self._normalize_vpc_peering(pcx, region))
                except Exception as e:
                    logger.warning(
                        "[networking] failed to normalize VPC peering %s: %s",
                        pcx.get("VpcPeeringConnectionId", "?"), e,
                    )
        return resources

    def _normalize_vpc_peering(self, pcx: dict, region: str) -> Resource:
        pcx_id = pcx["VpcPeeringConnectionId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:vpc-peering-connection/{pcx_id}"
        tags = {t["Key"]: t["Value"] for t in pcx.get("Tags", [])}

        requester = pcx.get("RequesterVpcInfo", {})
        accepter = pcx.get("AccepterVpcInfo", {})

        properties = {
            "peering_connection_id": pcx_id,
            "requester_vpc_id": requester.get("VpcId"),
            "requester_account_id": requester.get("OwnerId"),
            "requester_cidr": requester.get("CidrBlock"),
            "accepter_vpc_id": accepter.get("VpcId"),
            "accepter_account_id": accepter.get("OwnerId"),
            "accepter_cidr": accepter.get("CidrBlock"),
            "is_cross_account": requester.get("OwnerId") != accepter.get("OwnerId"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.VPC_PEERING_CONNECTION,
            name=tags.get("Name", pcx_id),
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )
