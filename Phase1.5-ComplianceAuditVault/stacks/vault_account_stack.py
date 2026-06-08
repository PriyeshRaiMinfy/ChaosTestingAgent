"""
Phase 0: Vault Account Stack

Deploys:
  - KMS CMK (symmetric, auto-rotation, restrictive key policy)
  - WORM S3 bucket (Object Lock Compliance, deny policies)

This is the foundation. Everything else stores evidence here.

Deploy: cdk deploy VaultAccountStack -c env=dev
"""
import aws_cdk as cdk
import aws_cdk.aws_kms as kms
from constructs import Construct

from constructs.worm_bucket import WormBucket


class VaultAccountStack(cdk.Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        config: dict,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # KMS Customer Managed Key — dedicated to vault encryption
        self.vault_key = kms.Key(
            self,
            "VaultCMK",
            alias=f"alias/{config['bucket_name_prefix']}-cmk",
            description="CMK for WORM audit vault — encrypts all compliance evidence",
            enable_key_rotation=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # WORM Vault Bucket — immutable compliance evidence store
        self.vault = WormBucket(
            self,
            "AuditVault",
            bucket_name=config["bucket_name_prefix"],
            retention_days=config["retention_days"],
            kms_key=self.vault_key,
            enable_access_logging=config.get("enable_access_logging", False),
            glacier_transition_days=config.get("glacier_transition_days", 90),
        )

        # Outputs — other stacks and Lambdas need these
        cdk.CfnOutput(self, "VaultBucketName", value=self.vault.bucket_name)
        cdk.CfnOutput(self, "VaultBucketArn", value=self.vault.bucket_arn)
        cdk.CfnOutput(self, "VaultKMSKeyArn", value=self.vault_key.key_arn)
        cdk.CfnOutput(
            self,
            "RetentionDays",
            value=str(config["retention_days"]),
            description="Object Lock retention configured (days)",
        )

        # Tags
        cdk.Tags.of(self).add("ManagedBy", "ComplianceAuditVault")
        cdk.Tags.of(self).add("Compliance", "HIPAA-PC05")
        cdk.Tags.of(self).add("Environment", config["environment"])
