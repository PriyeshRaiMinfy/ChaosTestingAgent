"""
Unit tests for VaultAccountStack.

Uses CDK assertions to verify the synthesized CloudFormation template
contains the correct resources BEFORE deploying to AWS.

Fixtures (dev_template, prod_template) come from conftest.py.
"""
from aws_cdk import assertions


class TestVaultBucket:
    """Verify WORM bucket properties."""

    def test_bucket_has_object_lock_enabled(self, dev_template):
        dev_template.has_resource_properties(
            "AWS::S3::Bucket",
            assertions.Match.object_like({"ObjectLockEnabled": True}),
        )

    def test_bucket_has_compliance_retention_dev(self, dev_template):
        dev_template.has_resource_properties(
            "AWS::S3::Bucket",
            assertions.Match.object_like(
                {
                    "ObjectLockConfiguration": {
                        "ObjectLockEnabled": "Enabled",
                        "Rule": {
                            "DefaultRetention": {
                                "Mode": "COMPLIANCE",
                                "Days": 1,
                            }
                        },
                    }
                }
            ),
        )

    def test_bucket_has_compliance_retention_prod(self, prod_template):
        prod_template.has_resource_properties(
            "AWS::S3::Bucket",
            assertions.Match.object_like(
                {
                    "ObjectLockConfiguration": {
                        "Rule": {
                            "DefaultRetention": {
                                "Mode": "COMPLIANCE",
                                "Days": 2555,
                            }
                        }
                    }
                }
            ),
        )

    def test_bucket_versioning_enabled(self, dev_template):
        dev_template.has_resource_properties(
            "AWS::S3::Bucket",
            assertions.Match.object_like(
                {"VersioningConfiguration": {"Status": "Enabled"}}
            ),
        )

    def test_bucket_encryption_is_kms(self, dev_template):
        dev_template.has_resource_properties(
            "AWS::S3::Bucket",
            assertions.Match.object_like(
                {
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": assertions.Match.array_with(
                            [
                                assertions.Match.object_like(
                                    {
                                        "ServerSideEncryptionByDefault": {
                                            "SSEAlgorithm": "aws:kms"
                                        }
                                    }
                                )
                            ]
                        )
                    }
                }
            ),
        )

    def test_bucket_blocks_public_access(self, dev_template):
        dev_template.has_resource_properties(
            "AWS::S3::Bucket",
            assertions.Match.object_like(
                {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    }
                }
            ),
        )


class TestBucketPolicy:
    """Verify deny policies from Appendix A."""

    def test_deny_shorten_retention_statement(self, dev_template):
        dev_template.has_resource_properties(
            "AWS::S3::BucketPolicy",
            assertions.Match.object_like(
                {
                    "PolicyDocument": {
                        "Statement": assertions.Match.array_with(
                            [
                                assertions.Match.object_like(
                                    {
                                        "Sid": "DenyShortenRetentionOrLegalHoldRemoval",
                                        "Effect": "Deny",
                                    }
                                )
                            ]
                        )
                    }
                }
            ),
        )

    def test_deny_unencrypted_write_statement(self, dev_template):
        dev_template.has_resource_properties(
            "AWS::S3::BucketPolicy",
            assertions.Match.object_like(
                {
                    "PolicyDocument": {
                        "Statement": assertions.Match.array_with(
                            [
                                assertions.Match.object_like(
                                    {
                                        "Sid": "DenyUnencryptedWrite",
                                        "Effect": "Deny",
                                    }
                                )
                            ]
                        )
                    }
                }
            ),
        )


class TestKMSKey:
    """Verify CMK configuration."""

    def test_kms_key_has_rotation_enabled(self, dev_template):
        dev_template.has_resource_properties(
            "AWS::KMS::Key",
            assertions.Match.object_like({"EnableKeyRotation": True}),
        )

    def test_kms_key_count(self, dev_template):
        dev_template.resource_count_is("AWS::KMS::Key", 1)
