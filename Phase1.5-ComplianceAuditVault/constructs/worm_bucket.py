"""
Reusable L3 construct: S3 bucket with Object Lock in COMPLIANCE mode.

Any stack that needs an immutable bucket calls:
    WormBucket(self, "Vault", retention_days=2555, kms_key=my_key)

Object Lock COMPLIANCE mode = nobody can delete or shorten retention.
Not even root. Not even AWS support. Until retention expires.
"""
from constructs import Construct
import aws_cdk as cdk
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_kms as kms
import aws_cdk.aws_iam as iam


class WormBucket(Construct):
    """S3 bucket with Object Lock Compliance, KMS encryption, and deny policies."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        bucket_name: str,
        retention_days: int,
        kms_key: kms.IKey,
        enable_access_logging: bool = False,
        glacier_transition_days: int = 90,
    ) -> None:
        super().__init__(scope, id)

        self._retention_days = retention_days
        self._kms_key = kms_key

        # Access log bucket (optional)
        self._access_log_bucket = None
        if enable_access_logging:
            self._access_log_bucket = s3.Bucket(
                self,
                "AccessLogs",
                bucket_name=f"{bucket_name}-access-logs",
                encryption=s3.BucketEncryption.S3_MANAGED,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                lifecycle_rules=[
                    s3.LifecycleRule(expiration=cdk.Duration.days(365))
                ],
                removal_policy=cdk.RemovalPolicy.RETAIN,
            )

        # The WORM vault bucket
        self.bucket = s3.Bucket(
            self,
            "Bucket",
            bucket_name=bucket_name,
            versioned=True,
            object_lock_enabled=True,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=kms_key,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            server_access_logs_bucket=self._access_log_bucket,
            removal_policy=cdk.RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
                            transition_after=cdk.Duration.days(glacier_transition_days),
                        )
                    ]
                )
            ],
        )

        # Object Lock default retention — COMPLIANCE mode
        # CDK doesn't expose ObjectLockConfiguration as L2, use CfnBucket override
        cfn_bucket = self.bucket.node.default_child
        cfn_bucket.add_property_override(
            "ObjectLockConfiguration",
            {
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "COMPLIANCE",
                        "Days": retention_days,
                    }
                },
            },
        )

        # Bucket policy: Appendix A from spec
        self._add_deny_policies()

    def _add_deny_policies(self) -> None:
        """Deny retention shortening and unencrypted writes (Appendix A)."""

        # Statement 1: Deny any attempt to shorten retention or remove legal hold
        self.bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyShortenRetentionOrLegalHoldRemoval",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=[
                    "s3:PutObjectRetention",
                    "s3:BypassGovernanceRetention",
                    "s3:PutBucketObjectLockConfiguration",
                ],
                resources=[
                    self.bucket.bucket_arn,
                    f"{self.bucket.bucket_arn}/*",
                ],
                conditions={
                    "NumericLessThan": {
                        "s3:object-lock-remaining-retention-days": str(
                            self._retention_days
                        )
                    }
                },
            )
        )

        # Statement 2: Deny writes without KMS encryption
        self.bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyUnencryptedWrite",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:PutObject"],
                resources=[f"{self.bucket.bucket_arn}/*"],
                conditions={
                    "StringNotEquals": {
                        "s3:x-amz-server-side-encryption": "aws:kms"
                    }
                },
            )
        )

    @property
    def bucket_arn(self) -> str:
        return self.bucket.bucket_arn

    @property
    def bucket_name(self) -> str:
        return self.bucket.bucket_name
