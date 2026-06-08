"""
Phase 1: Security Lake + Native Sources + Copy Lane

Deploys:
  - AWS Security Lake (data lake in OCSF format)
  - Native log sources: CloudTrail, VPC Flow, Route53, Config, GuardDuty, Security Hub
  - Athena workgroup + Glue catalog access for queries
  - Copy Lane Lambda: copies every new partition to WORM vault

Depends on: VaultAccountStack (vault bucket + KMS key)
Deploy: cdk deploy SecurityLakeStack -c env=dev
"""
import aws_cdk as cdk
import aws_cdk.aws_securitylake as securitylake
import aws_cdk.aws_athena as athena
import aws_cdk.aws_glue as glue
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as _lambda
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_s3_notifications as s3n
import aws_cdk.aws_kms as kms
from constructs import Construct


# Native sources Security Lake supports out of the box
NATIVE_SOURCES = [
    {"sourceName": "CLOUD_TRAIL_MGMT", "sourceVersion": "2.0"},
    {"sourceName": "VPC_FLOW", "sourceVersion": "2.0"},
    {"sourceName": "ROUTE53", "sourceVersion": "2.0"},
    {"sourceName": "SH_FINDINGS", "sourceVersion": "2.0"},
    {"sourceName": "LAMBDA_EXECUTION", "sourceVersion": "2.0"},
]


class SecurityLakeStack(cdk.Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        config: dict,
        vault_bucket_arn: str,
        vault_kms_key_arn: str,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        region = config.get("region", "ap-south-1")

        # ─── Security Lake Data Lake ────────────────────────────────────
        self.data_lake = securitylake.CfnDataLake(
            self,
            "DataLake",
            meta_store_manager_role_arn=self._create_meta_store_role().role_arn,
            lifecycle_configuration=securitylake.CfnDataLake.LifecycleConfigurationProperty(
                expiration=securitylake.CfnDataLake.ExpirationProperty(days=365),
                transitions=[
                    securitylake.CfnDataLake.TransitionsProperty(
                        days=90,
                        storage_class="STANDARD_IA",
                    )
                ],
            ),
        )

        # ─── Native Log Sources ─────────────────────────────────────────
        for source in NATIVE_SOURCES:
            securitylake.CfnAwsLogSource(
                self,
                f"Source{source['sourceName']}",
                data_lake_arn=self.data_lake.attr_arn,
                source_name=source["sourceName"],
                source_version=source["sourceVersion"],
                accounts=[config.get("account_id", cdk.Aws.ACCOUNT_ID)],
                regions=[region],
            )

        # ─── Athena Workgroup ────────────────────────────────────────────
        self.athena_workgroup = athena.CfnWorkGroup(
            self,
            "SecurityLakeWorkgroup",
            name="security-lake-queries",
            description="Workgroup for Security Lake OCSF queries",
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    output_location=f"s3://{config['bucket_name_prefix']}-athena-results/",
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="SSE_KMS",
                        kms_key=vault_kms_key_arn,
                    ),
                ),
                enforce_work_group_configuration=True,
                publish_cloud_watch_metrics_enabled=True,
                bytes_scanned_cutoff_per_query=10_737_418_240,  # 10 GB safety limit
            ),
            state="ENABLED",
        )

        # ─── Copy Lane Lambda ────────────────────────────────────────────
        vault_bucket = s3.Bucket.from_bucket_arn(self, "VaultBucket", vault_bucket_arn)
        vault_key = kms.Key.from_key_arn(self, "VaultKey", vault_kms_key_arn)

        copy_lane_role = self._create_copy_lane_role(vault_bucket, vault_key)

        self.copy_lane_fn = _lambda.Function(
            self,
            "CopyLaneFn",
            function_name="security-lake-copy-to-vault",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            code=_lambda.Code.from_asset("lambdas/copy_lane"),
            timeout=cdk.Duration.minutes(5),
            memory_size=512,
            environment={
                "VAULT_BUCKET_NAME": vault_bucket.bucket_name,
                "VAULT_KMS_KEY_ARN": vault_kms_key_arn,
                "RETENTION_DAYS": str(config["retention_days"]),
            },
            role=copy_lane_role,
        )

        # ─── Auditor Read-Only Role ─────────────────────────────────────
        self.auditor_role = iam.Role(
            self,
            "AuditorReadOnlyRole",
            role_name="SecurityLakeAuditorReadOnly",
            description="Read-only access to Security Lake for compliance auditors",
            assumed_by=iam.AccountPrincipal(cdk.Aws.ACCOUNT_ID),
            max_session_duration=cdk.Duration.hours(4),
        )

        self.auditor_role.add_to_policy(
            iam.PolicyStatement(
                sid="AthenaQueryAccess",
                actions=[
                    "athena:StartQueryExecution",
                    "athena:GetQueryExecution",
                    "athena:GetQueryResults",
                    "athena:ListQueryExecutions",
                ],
                resources=[
                    f"arn:aws:athena:{region}:{cdk.Aws.ACCOUNT_ID}:workgroup/security-lake-queries"
                ],
            )
        )

        self.auditor_role.add_to_policy(
            iam.PolicyStatement(
                sid="GlueCatalogReadOnly",
                actions=[
                    "glue:GetDatabase",
                    "glue:GetDatabases",
                    "glue:GetTable",
                    "glue:GetTables",
                    "glue:GetPartitions",
                ],
                resources=["*"],
            )
        )

        self.auditor_role.add_to_policy(
            iam.PolicyStatement(
                sid="S3ReadSecurityLake",
                actions=["s3:GetObject", "s3:ListBucket"],
                resources=[
                    f"arn:aws:s3:::aws-security-data-lake-{region}-*",
                    f"arn:aws:s3:::aws-security-data-lake-{region}-*/*",
                ],
            )
        )

        # ─── Outputs ────────────────────────────────────────────────────
        cdk.CfnOutput(self, "DataLakeArn", value=self.data_lake.attr_arn)
        cdk.CfnOutput(self, "AthenaWorkgroupName", value="security-lake-queries")
        cdk.CfnOutput(self, "CopyLaneFunctionArn", value=self.copy_lane_fn.function_arn)
        cdk.CfnOutput(self, "AuditorRoleArn", value=self.auditor_role.role_arn)

        cdk.Tags.of(self).add("ManagedBy", "ComplianceAuditVault")
        cdk.Tags.of(self).add("Phase", "1-SecurityLake")

    def _create_meta_store_role(self) -> iam.Role:
        """Role that Security Lake uses to manage its Glue catalog + S3."""
        return iam.Role(
            self,
            "SecurityLakeMetaStoreRole",
            role_name="SecurityLakeMetaStoreManager",
            assumed_by=iam.ServicePrincipal("securitylake.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonSecurityLakeMetastoreManager"
                )
            ],
        )

    def _create_copy_lane_role(self, vault_bucket: s3.IBucket, vault_key: kms.IKey) -> iam.Role:
        """IAM role for Copy Lane Lambda — read Security Lake, write to vault."""
        role = iam.Role(
            self,
            "CopyLaneRole",
            role_name="SecurityLakeCopyLaneRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )

        # Read from Security Lake S3
        role.add_to_policy(
            iam.PolicyStatement(
                sid="ReadSecurityLakeBucket",
                actions=["s3:GetObject", "s3:ListBucket"],
                resources=[
                    f"arn:aws:s3:::aws-security-data-lake-{cdk.Aws.REGION}-*",
                    f"arn:aws:s3:::aws-security-data-lake-{cdk.Aws.REGION}-*/*",
                ],
            )
        )

        # Write to vault bucket with Object Lock
        role.add_to_policy(
            iam.PolicyStatement(
                sid="WriteToVaultBucket",
                actions=[
                    "s3:PutObject",
                    "s3:PutObjectRetention",
                ],
                resources=[f"{vault_bucket.bucket_arn}/*"],
            )
        )

        # Use vault KMS key for encryption
        vault_key.grant_encrypt(role)

        return role
