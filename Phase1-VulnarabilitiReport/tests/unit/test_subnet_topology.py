"""
Unit tests for subnet topology edges and entry-point validation.

Covers:
  - IN_SUBNET edges (resource → subnet)
  - SUBNET_ROUTES_VIA (subnet → route table)
  - ROUTE_TO_IGW / ROUTE_TO_NAT / ROUTE_TO_TGW / ROUTE_TO_PEERING
  - NACL_PROTECTS (with blocks_all_inbound)
  - PEERS_WITH (VPC peering)
  - Serializer _subnet_confirms_public logic
"""
from __future__ import annotations

from datetime import datetime

import pytest

from breakbot.graph.builder import GraphBuilder
from breakbot.graph.edges import INTERNET_NODE_ID, EdgeType
from breakbot.graph.serializer import GraphSerializer
from breakbot.models import Resource, ResourceType, ScanResult


# ───────────────────────────── Fixtures ───────────────────────────────────

ACCT = "123456789012"
REGION = "us-east-1"


def _result(*resources: Resource) -> ScanResult:
    return ScanResult(
        scan_id="test-subnet",
        scanner_account_id=ACCT,
        accounts_scanned=[ACCT],
        started_at=datetime(2025, 1, 1),
        completed_at=datetime(2025, 1, 1),
        regions_scanned=[REGION],
        resources=list(resources),
    )


def _subnet(subnet_id: str, vpc_id: str = "vpc-1"):
    arn = f"arn:aws:ec2:{REGION}:{ACCT}:subnet/{subnet_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.SUBNET,
        name=subnet_id,
        region=REGION,
        account_id=ACCT,
        properties={
            "subnet_id": subnet_id,
            "vpc_id": vpc_id,
            "cidr_block": "10.0.1.0/24",
            "availability_zone": f"{REGION}a",
            "map_public_ip_on_launch": False,
        },
    )


def _route_table(rt_id: str, vpc_id: str = "vpc-1", is_main: bool = False,
                 associated_subnets: list[str] | None = None,
                 routes: list[dict] | None = None):
    arn = f"arn:aws:ec2:{REGION}:{ACCT}:route-table/{rt_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.ROUTE_TABLE,
        name=rt_id,
        region=REGION,
        account_id=ACCT,
        properties={
            "route_table_id": rt_id,
            "vpc_id": vpc_id,
            "is_main": is_main,
            "associated_subnet_ids": associated_subnets or [],
            "routes": routes or [],
        },
    )


def _nacl(nacl_id: str, subnet_ids: list[str], blocks_all: bool = False):
    arn = f"arn:aws:ec2:{REGION}:{ACCT}:network-acl/{nacl_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.NETWORK_ACL,
        name=nacl_id,
        region=REGION,
        account_id=ACCT,
        properties={
            "network_acl_id": nacl_id,
            "associated_subnet_ids": subnet_ids,
            "blocks_all_inbound": blocks_all,
        },
    )


def _ec2(instance_id: str, sg_ids: list[str] | None = None, public_ip: str | None = None,
          subnet_id: str | None = None):
    arn = f"arn:aws:ec2:{REGION}:{ACCT}:instance/{instance_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.EC2_INSTANCE,
        name=instance_id,
        region=REGION,
        account_id=ACCT,
        properties={
            "instance_id": instance_id,
            "security_group_ids": sg_ids or [],
            "public_ip": public_ip,
            "is_public": bool(public_ip),
            "subnet_id": subnet_id,
            "imds_v1_allowed": True,
        },
    )


def _sg(sg_id: str, internet_exposed: bool = False):
    arn = f"arn:aws:ec2:{REGION}:{ACCT}:security-group/{sg_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.SECURITY_GROUP,
        name=sg_id,
        region=REGION,
        account_id=ACCT,
        properties={
            "group_id": sg_id,
            "ingress_rules": [{
                "protocol": "tcp",
                "from_port": 443,
                "to_port": 443,
                "cidrs": ["0.0.0.0/0"] if internet_exposed else [],
                "ipv6_cidrs": [],
                "referenced_sgs": [],
            }] if internet_exposed else [],
            "egress_rules": [],
            "internet_exposed": internet_exposed,
        },
    )


def _vpc(vpc_id: str = "vpc-1"):
    arn = f"arn:aws:ec2:{REGION}:{ACCT}:vpc/{vpc_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.VPC,
        name=vpc_id,
        region=REGION,
        account_id=ACCT,
        properties={"vpc_id": vpc_id, "cidr_block": "10.0.0.0/16", "is_default": False},
    )


def _vpc_peering(pcx_id: str, requester_vpc: str, accepter_vpc: str, cross_account: bool = False):
    arn = f"arn:aws:ec2:{REGION}:{ACCT}:vpc-peering-connection/{pcx_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.VPC_PEERING_CONNECTION,
        name=pcx_id,
        region=REGION,
        account_id=ACCT,
        properties={
            "peering_connection_id": pcx_id,
            "requester_vpc_id": requester_vpc,
            "accepter_vpc_id": accepter_vpc,
            "is_cross_account": cross_account,
        },
    )


# ───────────────────────────── Tests: Edge creation ─────────────────────────


class TestSubnetTopologyEdges:
    def test_ec2_in_subnet_edge(self):
        sub = _subnet("subnet-pub")
        ec2 = _ec2("i-1", subnet_id="subnet-pub")
        g = GraphBuilder(_result(sub, ec2)).build()

        in_subnet = [(u, v) for u, v, d in g.edges(data=True)
                     if d.get("edge_type") == EdgeType.IN_SUBNET]
        assert (ec2.arn, sub.arn) in in_subnet

    def test_subnet_routes_via_explicit_association(self):
        sub = _subnet("subnet-1")
        rt = _route_table("rtb-1", associated_subnets=["subnet-1"])
        g = GraphBuilder(_result(sub, rt)).build()

        routes_via = [(u, v) for u, v, d in g.edges(data=True)
                      if d.get("edge_type") == EdgeType.SUBNET_ROUTES_VIA]
        assert (sub.arn, rt.arn) in routes_via

    def test_subnet_falls_back_to_main_route_table(self):
        sub = _subnet("subnet-orphan", vpc_id="vpc-1")
        main_rt = _route_table("rtb-main", vpc_id="vpc-1", is_main=True)
        g = GraphBuilder(_result(sub, main_rt)).build()

        routes_via = [(u, v) for u, v, d in g.edges(data=True)
                      if d.get("edge_type") == EdgeType.SUBNET_ROUTES_VIA]
        assert (sub.arn, main_rt.arn) in routes_via

    def test_route_to_igw(self):
        rt = _route_table("rtb-pub", routes=[
            {"target": "igw-1", "target_type": "igw", "destination": "0.0.0.0/0"}
        ])
        g = GraphBuilder(_result(rt)).build()

        igw_edges = [(u, v) for u, v, d in g.edges(data=True)
                     if d.get("edge_type") == EdgeType.ROUTE_TO_IGW]
        assert len(igw_edges) == 1
        assert igw_edges[0][0] == rt.arn

    def test_route_to_nat(self):
        rt = _route_table("rtb-priv", routes=[
            {"target": "nat-1", "target_type": "nat", "destination": "0.0.0.0/0"}
        ])
        g = GraphBuilder(_result(rt)).build()

        nat_edges = [(u, v) for u, v, d in g.edges(data=True)
                     if d.get("edge_type") == EdgeType.ROUTE_TO_NAT]
        assert len(nat_edges) == 1

    def test_route_to_tgw(self):
        rt = _route_table("rtb-tgw", routes=[
            {"target": "tgw-abc123", "target_type": "tgw", "destination": "0.0.0.0/0"}
        ])
        g = GraphBuilder(_result(rt)).build()

        tgw_edges = [(u, v) for u, v, d in g.edges(data=True)
                     if d.get("edge_type") == EdgeType.ROUTE_TO_TGW]
        assert len(tgw_edges) == 1
        assert "tgw:tgw-abc123" in tgw_edges[0][1]

    def test_route_to_peering(self):
        rt = _route_table("rtb-pcx", routes=[
            {"target": "pcx-111", "target_type": "pcx", "destination": "0.0.0.0/0"}
        ])
        g = GraphBuilder(_result(rt)).build()

        pcx_edges = [(u, v) for u, v, d in g.edges(data=True)
                     if d.get("edge_type") == EdgeType.ROUTE_TO_PEERING]
        assert len(pcx_edges) == 1

    def test_nacl_protects_subnet(self):
        sub = _subnet("subnet-x")
        nacl = _nacl("acl-1", subnet_ids=["subnet-x"], blocks_all=True)
        g = GraphBuilder(_result(sub, nacl)).build()

        nacl_edges = [(u, v, d) for u, v, d in g.edges(data=True)
                      if d.get("edge_type") == EdgeType.NACL_PROTECTS]
        assert len(nacl_edges) == 1
        assert nacl_edges[0][2].get("blocks_all_inbound") is True

    def test_vpc_peering_creates_peers_with_edges(self):
        vpc_a = _vpc("vpc-a")
        vpc_b = _vpc("vpc-b")
        pcx = _vpc_peering("pcx-1", "vpc-a", "vpc-b")
        g = GraphBuilder(_result(vpc_a, vpc_b, pcx)).build()

        peers = [(u, v) for u, v, d in g.edges(data=True)
                 if d.get("edge_type") == EdgeType.PEERS_WITH]
        assert len(peers) == 2  # bidirectional


# ───────────────────────────── Tests: Entry point validation ────────────────


class TestSubnetConfirmsPublic:
    def _build_and_serialize(self, *resources):
        result = _result(*resources)
        builder = GraphBuilder(result)
        g = builder.build()
        return GraphSerializer(g, builder.arn_index, max_hops=3)

    def test_public_subnet_ec2_is_entry_point(self):
        """EC2 with public IP + IGW route = valid entry point."""
        vpc = _vpc()
        sub = _subnet("subnet-pub")
        rt = _route_table("rtb-pub", associated_subnets=["subnet-pub"], routes=[
            {"target": "igw-1", "target_type": "igw", "destination": "0.0.0.0/0"}
        ])
        sg = _sg("sg-web", internet_exposed=True)
        ec2 = _ec2("i-web", sg_ids=["sg-web"], public_ip="1.2.3.4", subnet_id="subnet-pub")

        serializer = self._build_and_serialize(vpc, sub, rt, sg, ec2)
        entry_points = serializer._find_entry_points()
        assert ec2.arn in entry_points

    def test_private_subnet_ec2_not_entry_point(self):
        """EC2 with public IP but NAT route (private subnet) = NOT entry point."""
        vpc = _vpc()
        sub = _subnet("subnet-priv")
        rt = _route_table("rtb-priv", associated_subnets=["subnet-priv"], routes=[
            {"target": "nat-1", "target_type": "nat", "destination": "0.0.0.0/0"}
        ])
        sg = _sg("sg-web", internet_exposed=True)
        ec2 = _ec2("i-internal", sg_ids=["sg-web"], public_ip="1.2.3.4", subnet_id="subnet-priv")

        serializer = self._build_and_serialize(vpc, sub, rt, sg, ec2)
        entry_points = serializer._find_entry_points()
        assert ec2.arn not in entry_points

    def test_nacl_blocking_prevents_entry_point(self):
        """EC2 in public subnet but NACL blocks all inbound = NOT entry point."""
        vpc = _vpc()
        sub = _subnet("subnet-blocked")
        rt = _route_table("rtb-pub", associated_subnets=["subnet-blocked"], routes=[
            {"target": "igw-1", "target_type": "igw", "destination": "0.0.0.0/0"}
        ])
        nacl = _nacl("acl-block", subnet_ids=["subnet-blocked"], blocks_all=True)
        sg = _sg("sg-web", internet_exposed=True)
        ec2 = _ec2("i-blocked", sg_ids=["sg-web"], public_ip="1.2.3.4", subnet_id="subnet-blocked")

        serializer = self._build_and_serialize(vpc, sub, rt, nacl, sg, ec2)
        entry_points = serializer._find_entry_points()
        assert ec2.arn not in entry_points

    def test_no_subnet_data_falls_back_to_flag(self):
        """EC2 with public IP but no subnet resources in scan = treated as entry point."""
        sg = _sg("sg-web", internet_exposed=True)
        ec2 = _ec2("i-nosubnet", sg_ids=["sg-web"], public_ip="1.2.3.4")

        serializer = self._build_and_serialize(sg, ec2)
        entry_points = serializer._find_entry_points()
        assert ec2.arn in entry_points

    def test_non_default_route_ignored(self):
        """Route table with only 10.0.0.0/16 local route (no 0.0.0.0/0) = no IGW route."""
        vpc = _vpc()
        sub = _subnet("subnet-local")
        rt = _route_table("rtb-local", associated_subnets=["subnet-local"], routes=[
            {"target": "local", "target_type": "local", "destination": "10.0.0.0/16"}
        ])
        sg = _sg("sg-web", internet_exposed=True)
        ec2 = _ec2("i-local", sg_ids=["sg-web"], public_ip="1.2.3.4", subnet_id="subnet-local")

        serializer = self._build_and_serialize(vpc, sub, rt, sg, ec2)
        entry_points = serializer._find_entry_points()
        assert ec2.arn not in entry_points
