"""
Unit tests for SecurityLakeStack.

Verifies:
  - Security Lake data lake resource exists
  - Native sources are configured
  - Athena workgroup with KMS encryption
  - Copy Lane Lambda with correct environment vars
  - Auditor read-only role
"""
import json
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import assertions

from stacks.vault_account_stack import VaultAccountStack
from stacks.security_lake_stack import SecurityLakeStack


def _synth() -> assertions.Template:
    app = cdk.App()
    config_path = Path(__file__).parent.parent.parent / "config" / "dev.json"
    config = json.loads(config_path.read_text())

    vault_stack = VaultAccountStack(app, "TestVault", config=config)
    lake_stack = SecurityLakeStack(
        app,
        "TestSecurityLake",
        config=config,
        vault_bucket_arn=vault_stack.vault.bucket_arn,
        vault_kms_key_arn=vault_stack.vault_key.key_arn,
    )
    return assertions.Template.from_stack(lake_stack)


class TestSecurityLake:

    def test_data_lake_exists(self):
        template = _synth()
        template.resource_count_is("AWS::SecurityLake::DataLake", 1)

    def test_native_sources_configured(self):
        template = _synth()
        # 5 native sources: CLOUD_TRAIL_MGMT, VPC_FLOW, ROUTE53, SH_FINDINGS, LAMBDA_EXECUTION
        template.resource_count_is("AWS::SecurityLake::AwsLogSource", 5)


class TestAthenaWorkgroup:

    def test_workgroup_exists(self):
        template = _synth()
        template.has_resource_properties(
            "AWS::Athena::WorkGroup",
            assertions.Match.object_like(
                {"Name": "security-lake-queries", "State": "ENABLED"}
            ),
        )

    def test_workgroup_has_kms_encryption(self):
        template = _synth()
        template.has_resource_properties(
            "AWS::Athena::WorkGroup",
            assertions.Match.object_like(
                {
                    "WorkGroupConfiguration": {
                        "ResultConfiguration": {
                            "EncryptionConfiguration": {
                                "EncryptionOption": "SSE_KMS"
                            }
                        }
                    }
                }
            ),
        )


class TestCopyLane:

    def test_lambda_exists(self):
        template = _synth()
        template.has_resource_properties(
            "AWS::Lambda::Function",
            assertions.Match.object_like(
                {
                    "FunctionName": "security-lake-copy-to-vault",
                    "Runtime": "python3.12",
                    "Timeout": 300,
                }
            ),
        )

    def test_lambda_has_vault_env_vars(self):
        template = _synth()
        template.has_resource_properties(
            "AWS::Lambda::Function",
            assertions.Match.object_like(
                {
                    "Environment": {
                        "Variables": {
                            "RETENTION_DAYS": "1",
                        }
                    }
                }
            ),
        )


class TestAuditorRole:

    def test_auditor_role_exists(self):
        template = _synth()
        template.has_resource_properties(
            "AWS::IAM::Role",
            assertions.Match.object_like(
                {"RoleName": "SecurityLakeAuditorReadOnly"}
            ),
        )
