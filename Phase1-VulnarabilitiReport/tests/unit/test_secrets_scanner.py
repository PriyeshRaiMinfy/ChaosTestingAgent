"""
Unit tests for the secrets scanner (Secrets Manager + SSM + KMS).
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from breakbot.models import ResourceType
from breakbot.scanner import SecretsScanner
from breakbot.utils import AWSSession


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_secrets_manager_scanner_finds_secret(aws_credentials):
    """A created secret must be discovered with rotation_enabled=False."""
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="db-creds", SecretString="not-the-real-password")

    scanner = SecretsScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    secret = next(r for r in resources
                  if r.resource_type == ResourceType.SECRETS_MANAGER_SECRET
                  and r.name == "db-creds")
    # Newly created secrets default to RotationEnabled=False
    assert secret.properties["rotation_enabled"] is False
    # Critical: the actual secret value must never appear in scan output
    assert "not-the-real-password" not in str(secret.properties)


@mock_aws
def test_ssm_parameter_securestring_type_captured(aws_credentials):
    """SecureString type must round-trip and is_encrypted set accordingly."""
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(Name="/app/db_password", Value="x", Type="SecureString")
    ssm.put_parameter(Name="/app/log_level", Value="INFO", Type="String")

    scanner = SecretsScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    params = {r.name: r for r in resources
              if r.resource_type == ResourceType.SSM_PARAMETER}
    assert params["/app/db_password"].properties["is_encrypted"] is True
    assert params["/app/db_password"].properties["type"] == "SecureString"
    assert params["/app/log_level"].properties["is_encrypted"] is False


@mock_aws
def test_kms_scanner_distinguishes_customer_managed_keys(aws_credentials):
    """Customer-managed CMKs must be flagged distinct from AWS-managed."""
    kms = boto3.client("kms", region_name="us-east-1")
    customer_key = kms.create_key(
        Description="customer-managed key",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]

    scanner = SecretsScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    keys = [r for r in resources if r.resource_type == ResourceType.KMS_KEY]
    cust = next(k for k in keys if k.properties.get("key_id") == customer_key["KeyId"])
    assert cust.properties["is_customer_managed"] is True
    assert cust.properties["key_manager"] == "CUSTOMER"
