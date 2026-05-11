"""
Unit tests for the compute scanner.

Uses `moto` to mock AWS — no real AWS calls made. This is how we verify
scanner logic without burning AWS API budget or needing live credentials.

Run with:
    pytest tests/unit/test_compute_scanner.py -v
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from breakbot.models import ResourceType
from breakbot.scanner import ComputeScanner
from breakbot.utils import AWSSession


@pytest.fixture
def aws_credentials(monkeypatch):
    """Force boto3 to use fake creds so moto intercepts everything."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_ec2_scanner_finds_instance(aws_credentials):
    """A launched EC2 instance should be discovered with key properties."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    # Use a recent Amazon Linux 2 AMI ID (moto accepts any valid-format string)
    ec2.run_instances(
        ImageId="ami-0c55b159cbfafe1f0",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": "test-instance"}],
        }],
    )

    session = AWSSession(region="us-east-1")
    scanner = ComputeScanner(session)
    resources = scanner.scan(regions=["us-east-1"])

    instances = [r for r in resources if r.resource_type == ResourceType.EC2_INSTANCE]
    assert len(instances) == 1
    inst = instances[0]
    assert inst.name == "test-instance"
    assert inst.properties["instance_type"] == "t3.micro"
    assert inst.region == "us-east-1"
    assert inst.tags["Name"] == "test-instance"


@mock_aws
def test_lambda_scanner_captures_env_var_keys_not_values(aws_credentials):
    """Lambda env var keys should be captured; values are intentionally omitted at this layer."""
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(
        RoleName="test-lambda-role",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )

    lam = boto3.client("lambda", region_name="us-east-1")
    lam.create_function(
        FunctionName="test-fn",
        Runtime="python3.11",
        Role=role["Role"]["Arn"],
        Handler="index.handler",
        Code={"ZipFile": b"def handler(e,c): pass"},
        Environment={"Variables": {"DB_PASSWORD": "supersecret", "API_KEY": "key123"}},
    )

    session = AWSSession(region="us-east-1")
    scanner = ComputeScanner(session)
    resources = scanner.scan(regions=["us-east-1"])

    fns = [r for r in resources if r.resource_type == ResourceType.LAMBDA_FUNCTION]
    assert len(fns) == 1
    fn = fns[0]
    assert fn.name == "test-fn"
    assert set(fn.properties["env_var_keys"]) == {"DB_PASSWORD", "API_KEY"}
    # Critical: we record the KEYS but not the VALUES at this layer.
    # Values are only inspected by the dedicated secrets scanner later.
    assert "supersecret" not in str(fn.properties)


@mock_aws
def test_scanner_continues_on_region_failure(aws_credentials, caplog):
    """If one region 500s, the scan should still complete with the others."""
    # No instances launched in any region — scan should return [] not crash
    session = AWSSession(region="us-east-1")
    scanner = ComputeScanner(session)
    resources = scanner.scan(regions=["us-east-1", "us-west-2"])
    assert resources == []
    assert scanner.errors == []  # Empty regions ≠ errors
