"""
Unit tests for the networking scanner (VPC, SG, ALB).
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from breakbot.models import ResourceType
from breakbot.scanner import NetworkingScanner
from breakbot.utils import AWSSession


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_security_group_ingress_rules_are_structured(aws_credentials):
    """Ingress rules must be flattened from AWS's IpPermissions shape into our schema."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(
        GroupName="web-sg",
        Description="test",
        VpcId=vpc["VpcId"],
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    scanner = NetworkingScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    sgs = [r for r in resources if r.resource_type == ResourceType.SECURITY_GROUP]
    web_sg = next(s for s in sgs if s.properties.get("group_name") == "web-sg")
    rules = web_sg.properties["ingress_rules"]
    assert len(rules) == 1
    assert rules[0]["protocol"] == "tcp"
    assert rules[0]["from_port"] == 443
    assert rules[0]["to_port"] == 443
    assert "0.0.0.0/0" in rules[0]["cidrs"]
    # internet_exposed flag must be set
    assert web_sg.properties["internet_exposed"] is True


@mock_aws
def test_security_group_sg_to_sg_reference_captured(aws_credentials):
    """SG-to-SG ingress (no CIDR, just a referenced_sg) must round-trip."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    web_sg = ec2.create_security_group(
        GroupName="web-sg", Description="t", VpcId=vpc["VpcId"]
    )
    db_sg = ec2.create_security_group(
        GroupName="db-sg", Description="t", VpcId=vpc["VpcId"]
    )
    # Allow web-sg to talk to db-sg on 5432
    ec2.authorize_security_group_ingress(
        GroupId=db_sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 5432,
            "ToPort": 5432,
            "UserIdGroupPairs": [{"GroupId": web_sg["GroupId"]}],
        }],
    )

    scanner = NetworkingScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    sgs = [r for r in resources if r.resource_type == ResourceType.SECURITY_GROUP]
    db = next(s for s in sgs if s.properties.get("group_name") == "db-sg")
    rule = db.properties["ingress_rules"][0]
    assert rule["referenced_sgs"] == [web_sg["GroupId"]]
    # Not exposed to internet — only an SG reference
    assert db.properties["internet_exposed"] is False


@mock_aws
def test_vpc_default_flag(aws_credentials):
    """Moto creates a default VPC; we should capture is_default=True for it."""
    scanner = NetworkingScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])
    vpcs = [r for r in resources if r.resource_type == ResourceType.VPC]
    # moto auto-creates a default VPC per region
    assert any(v.properties.get("is_default") is True for v in vpcs)
