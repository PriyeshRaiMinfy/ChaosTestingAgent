"""
Unit tests for the data scanner (S3, RDS, DynamoDB).

ElastiCache is not tested here — moto's elasticache support is incomplete
in some areas (replication groups), and the scanner's per-paginator
isolation already has coverage in test_base_scanner.py.
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from breakbot.models import ResourceType
from breakbot.scanner import DataScanner
from breakbot.utils import AWSSession


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_s3_scanner_captures_public_access_block(aws_credentials):
    """The four PAB settings must round-trip into the Resource properties."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="my-test-bucket")
    s3.put_public_access_block(
        Bucket="my-test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,    # partial — should surface as a finding
            "RestrictPublicBuckets": True,
        },
    )

    scanner = DataScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    bucket = next(r for r in resources
                  if r.resource_type == ResourceType.S3_BUCKET and r.name == "my-test-bucket")
    pab = bucket.properties["public_access_block"]
    assert pab["block_public_acls"] is True
    assert pab["block_public_policy"] is False
    assert pab["restrict_public_buckets"] is True


@mock_aws
def test_s3_scanner_handles_bucket_with_no_policy(aws_credentials):
    """NoSuchBucketPolicy must be treated as 'no policy', not as an error."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="empty-bucket")
    # Deliberately do not put a bucket policy

    scanner = DataScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    bucket = next(r for r in resources
                  if r.resource_type == ResourceType.S3_BUCKET and r.name == "empty-bucket")
    assert bucket.properties["has_bucket_policy"] is False
    assert bucket.properties["bucket_policy"] is None
    # No error should have been recorded for this expected case
    assert not any(e.get("service") == "s3" and "NoSuchBucketPolicy" in e.get("error_code", "")
                   for e in scanner.errors)


@mock_aws
def test_rds_scanner_captures_public_and_encryption_flags(aws_credentials):
    """Both publicly_accessible and storage_encrypted must round-trip."""
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="prod-db",
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="admin",
        MasterUserPassword="not-the-real-password",
        PubliclyAccessible=True,
        StorageEncrypted=False,
    )

    scanner = DataScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    db = next(r for r in resources
              if r.resource_type == ResourceType.RDS_INSTANCE and r.name == "prod-db")
    assert db.properties["publicly_accessible"] is True
    assert db.properties["storage_encrypted"] is False
    assert db.properties["engine"] == "postgres"


@mock_aws
def test_dynamodb_scanner_captures_table_metadata(aws_credentials):
    """Basic table discovery + encryption + deletion protection round-trip."""
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    ddb.create_table(
        TableName="users",
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        DeletionProtectionEnabled=True,
    )

    scanner = DataScanner(AWSSession(region="us-east-1"))
    resources = scanner.scan(regions=["us-east-1"])

    table = next(r for r in resources
                 if r.resource_type == ResourceType.DYNAMODB_TABLE and r.name == "users")
    assert table.properties["deletion_protection"] is True
    assert table.properties["billing_mode"] == "PAY_PER_REQUEST"
