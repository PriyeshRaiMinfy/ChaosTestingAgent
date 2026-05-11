"""
Unit tests for GraphBuilder.

We construct minimal ScanResult fixtures by hand — no AWS calls, no moto.
Each test verifies one class of edge inference.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from breakbot.graph.builder import GraphBuilder, _normalize_principals
from breakbot.graph.edges import INTERNET_NODE_ID, EdgeType
from breakbot.models import Resource, ResourceType, ScanResult


# ───────────────────────────── Fixtures ───────────────────────────────────

def _result(*resources: Resource) -> ScanResult:
    return ScanResult(
        scan_id="test-scan",
        account_id="123456789012",
        started_at=datetime(2025, 1, 1),
        completed_at=datetime(2025, 1, 1),
        regions_scanned=["us-east-1"],
        resources=list(resources),
    )


def _ec2(instance_id: str, sg_ids: list[str], profile_arn: str | None = None, public_ip: str | None = None):
    arn = f"arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.EC2_INSTANCE,
        name=instance_id,
        region="us-east-1",
        account_id="123456789012",
        properties={
            "instance_id": instance_id,
            "security_group_ids": sg_ids,
            "iam_instance_profile_arn": profile_arn,
            "public_ip": public_ip,
            "is_public": bool(public_ip),
            "imds_v1_allowed": True,
        },
    )


def _lambda_fn(name: str, role_arn: str, sg_ids: list[str] | None = None, vpc_id: str | None = None):
    arn = f"arn:aws:lambda:us-east-1:123456789012:function:{name}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.LAMBDA_FUNCTION,
        name=name,
        region="us-east-1",
        account_id="123456789012",
        properties={
            "function_name": name,
            "role_arn": role_arn,
            "security_group_ids": sg_ids or [],
            "vpc_id": vpc_id,
            "in_vpc": bool(vpc_id),
            "env_var_count": 0,
            "env_var_keys": [],
        },
    )


def _iam_role(
    name: str,
    trust_policy: dict | None = None,
    inline_policies: list[dict] | None = None,
    managed_policies: list[dict] | None = None,
):
    arn = f"arn:aws:iam::123456789012:role/{name}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.IAM_ROLE,
        name=name,
        region="global",
        account_id="123456789012",
        properties={
            "role_name": name,
            "trust_policy": trust_policy or {},
            "inline_policies": inline_policies or [],
            "managed_policies": managed_policies or [],
        },
    )


def _sg(sg_id: str, ingress_rules: list[dict] | None = None, internet_exposed: bool = False):
    arn = f"arn:aws:ec2:us-east-1:123456789012:security-group/{sg_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.SECURITY_GROUP,
        name=sg_id,
        region="us-east-1",
        account_id="123456789012",
        properties={
            "group_id": sg_id,
            "ingress_rules": ingress_rules or [],
            "egress_rules": [],
            "internet_exposed": internet_exposed,
        },
    )


def _vpc(vpc_id: str):
    arn = f"arn:aws:ec2:us-east-1:123456789012:vpc/{vpc_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.VPC,
        name=vpc_id,
        region="us-east-1",
        account_id="123456789012",
        properties={"vpc_id": vpc_id, "cidr_block": "10.0.0.0/16", "is_default": False},
    )


def _s3(name: str, block_all: bool = True):
    arn = f"arn:aws:s3:::{name}"
    pab = {
        "block_public_acls": block_all,
        "ignore_public_acls": block_all,
        "block_public_policy": block_all,
        "restrict_public_buckets": block_all,
    }
    return Resource(
        arn=arn,
        resource_type=ResourceType.S3_BUCKET,
        name=name,
        region="us-east-1",
        account_id="123456789012",
        properties={
            "bucket_name": name,
            "public_access_block": pab,
            "has_bucket_policy": False,
            "is_encrypted": True,
        },
    )


# ───────────────────────────── Tests ──────────────────────────────────────


def test_basic_graph_has_internet_node():
    result = _result(_ec2("i-aaa", []))
    g = GraphBuilder(result).build()
    assert INTERNET_NODE_ID in g.nodes


def test_lambda_has_execution_role_edge():
    role = _iam_role("LambdaRole")
    fn = _lambda_fn("my-fn", role_arn=role.arn)
    g = GraphBuilder(_result(fn, role)).build()

    edges = [(u, v, d) for u, v, d in g.edges(data=True)
             if d.get("edge_type") == EdgeType.HAS_EXECUTION_ROLE]
    assert len(edges) == 1
    u, v, _ = edges[0]
    assert u == fn.arn
    assert v == role.arn


def test_ec2_instance_profile_resolves_to_role_by_name():
    role = _iam_role("MyAppRole")
    instance = _ec2(
        "i-bbb",
        sg_ids=[],
        profile_arn="arn:aws:iam::123456789012:instance-profile/MyAppRole",
    )
    g = GraphBuilder(_result(instance, role)).build()

    edges = [(u, v, d) for u, v, d in g.edges(data=True)
             if d.get("edge_type") == EdgeType.HAS_INSTANCE_PROFILE]
    assert len(edges) == 1
    _, v, _ = edges[0]
    assert v == role.arn


def test_ec2_attached_to_sg():
    sg = _sg("sg-111")
    instance = _ec2("i-ccc", sg_ids=["sg-111"])
    g = GraphBuilder(_result(instance, sg)).build()

    edges = [(u, v, d) for u, v, d in g.edges(data=True)
             if d.get("edge_type") == EdgeType.ATTACHED_TO_SG]
    assert any(u == instance.arn and v == sg.arn for u, v, _ in edges)


def test_internet_exposes_sg():
    sg = _sg(
        "sg-internet",
        ingress_rules=[{
            "protocol": "tcp",
            "from_port": 443,
            "to_port": 443,
            "cidrs": ["0.0.0.0/0"],
            "ipv6_cidrs": [],
            "referenced_sgs": [],
        }],
        internet_exposed=True,
    )
    g = GraphBuilder(_result(sg)).build()

    edges = [(u, v, d) for u, v, d in g.edges(data=True)
             if d.get("edge_type") == EdgeType.INTERNET_EXPOSES]
    assert len(edges) == 1
    u, v, d = edges[0]
    assert u == INTERNET_NODE_ID
    assert v == sg.arn
    assert d["from_port"] == 443


def test_sg_to_sg_network_can_reach():
    sg_a = _sg("sg-aaa")
    sg_b = _sg(
        "sg-bbb",
        ingress_rules=[{
            "protocol": "tcp",
            "from_port": 5432,
            "to_port": 5432,
            "cidrs": [],
            "ipv6_cidrs": [],
            "referenced_sgs": ["sg-aaa"],
        }],
    )
    g = GraphBuilder(_result(sg_a, sg_b)).build()

    edges = [(u, v, d) for u, v, d in g.edges(data=True)
             if d.get("edge_type") == EdgeType.NETWORK_CAN_REACH]
    assert len(edges) == 1
    u, v, d = edges[0]
    assert u == sg_a.arn
    assert v == sg_b.arn
    assert d["from_port"] == 5432


def test_iam_can_assume_from_service():
    role = _iam_role(
        "LambdaExec",
        trust_policy={
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        },
    )
    g = GraphBuilder(_result(role)).build()

    edges = [(u, v, d) for u, v, d in g.edges(data=True)
             if d.get("edge_type") == EdgeType.IAM_CAN_ASSUME]
    assert len(edges) == 1
    u, v, _ = edges[0]
    assert u == "lambda.amazonaws.com"
    assert v == role.arn


def test_iam_can_access_from_inline_policy():
    s3 = _s3("my-bucket")
    role = _iam_role(
        "AppRole",
        inline_policies=[{
            "name": "s3-access",
            "document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": [f"{s3.arn}/*"],
                }],
            },
        }],
    )
    g = GraphBuilder(_result(role, s3)).build()

    edges = [(u, v, d) for u, v, d in g.edges(data=True)
             if d.get("edge_type") == EdgeType.IAM_CAN_ACCESS]
    assert len(edges) >= 1
    assert any(v == s3.arn for _, v, _ in edges)


def test_wildcard_resource_sets_node_attribute():
    role = _iam_role(
        "AdminRole",
        managed_policies=[{
            "name": "AdministratorAccess",
            "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "is_aws_managed": True,
            "document": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            },
        }],
    )
    g = GraphBuilder(_result(role)).build()
    assert g.nodes[role.arn].get("has_wildcard_resource_access") is True


def test_lambda_in_vpc_edge():
    vpc = _vpc("vpc-111")
    fn = _lambda_fn("my-fn", role_arn="arn:aws:iam::123456789012:role/R", vpc_id="vpc-111")
    g = GraphBuilder(_result(fn, vpc)).build()

    edges = [(u, v, d) for u, v, d in g.edges(data=True)
             if d.get("edge_type") == EdgeType.IN_VPC]
    assert any(v == vpc.arn for _, v, _ in edges)


# ──────────────────── _normalize_principals helper ────────────────────────

def test_normalize_principals_star():
    assert _normalize_principals("*") == ["*"]


def test_normalize_principals_service():
    result = _normalize_principals({"Service": "lambda.amazonaws.com"})
    assert result == ["lambda.amazonaws.com"]


def test_normalize_principals_aws_list():
    arns = ["arn:aws:iam::123:role/A", "arn:aws:iam::123:role/B"]
    result = _normalize_principals({"AWS": arns})
    assert sorted(result) == sorted(arns)


def test_normalize_principals_federated():
    result = _normalize_principals({"Federated": "cognito-identity.amazonaws.com"})
    assert result == ["federated:cognito-identity.amazonaws.com"]
