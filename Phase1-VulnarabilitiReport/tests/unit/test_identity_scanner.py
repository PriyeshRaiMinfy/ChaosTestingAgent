"""
Unit tests for the identity scanner.

Uses `moto` to mock IAM. IAM is global, so we don't need multi-region setup.
"""
from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws

from breakbot.models import ResourceType
from breakbot.scanner import IdentityScanner
from breakbot.utils import AWSSession


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_role_scanner_captures_trust_policy(aws_credentials):
    """The trust policy must be captured as a parsed dict (not URL-encoded string)."""
    iam = boto3.client("iam", region_name="us-east-1")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName="lambda-exec-role",
        AssumeRolePolicyDocument=json.dumps(trust),
    )

    scanner = IdentityScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    roles = [r for r in resources if r.resource_type == ResourceType.IAM_ROLE]
    assert any(r.name == "lambda-exec-role" for r in roles)
    role = next(r for r in roles if r.name == "lambda-exec-role")
    # Trust policy must be a dict (not the URL-encoded string from AWS)
    assert isinstance(role.properties["trust_policy"], dict)
    assert role.properties["trust_policy"]["Statement"][0]["Principal"] == {
        "Service": "lambda.amazonaws.com"
    }


@mock_aws
def test_role_scanner_captures_inline_policy_document(aws_credentials):
    """Inline policies must be captured with their full policy document."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName="app-role",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )
    inline_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::my-bucket/*"],
        }],
    }
    iam.put_role_policy(
        RoleName="app-role",
        PolicyName="read-bucket",
        PolicyDocument=json.dumps(inline_doc),
    )

    scanner = IdentityScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    role = next(r for r in resources
                if r.resource_type == ResourceType.IAM_ROLE and r.name == "app-role")
    inlines = role.properties["inline_policies"]
    assert len(inlines) == 1
    assert inlines[0]["name"] == "read-bucket"
    assert isinstance(inlines[0]["document"], dict)
    assert inlines[0]["document"]["Statement"][0]["Action"] == ["s3:GetObject"]


@mock_aws
def test_user_scanner_captures_access_key_metadata(aws_credentials):
    """User scanner must record access key metadata but never the secret value."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    create_key = iam.create_access_key(UserName="alice")

    scanner = IdentityScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    user = next(r for r in resources
                if r.resource_type == ResourceType.IAM_USER and r.name == "alice")
    keys = user.properties["access_keys"]
    assert len(keys) == 1
    assert keys[0]["status"] == "Active"
    # The actual secret access key must not appear anywhere in the scan output
    secret = create_key["AccessKey"]["SecretAccessKey"]
    assert secret not in str(user.properties)


@mock_aws
def test_scanner_isolates_role_inspection_failures(aws_credentials):
    """If one role inspection fails, the others should still be returned."""
    iam = boto3.client("iam", region_name="us-east-1")
    for name in ("role-a", "role-b", "role-c"):
        iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
        )

    scanner = IdentityScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    role_names = {r.name for r in resources if r.resource_type == ResourceType.IAM_ROLE}
    assert {"role-a", "role-b", "role-c"} <= role_names
