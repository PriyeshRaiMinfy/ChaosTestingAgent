"""
Data store scanner — S3, RDS, DynamoDB, and ElastiCache.

S3 is global, so we scan once and resolve each bucket's actual region via
GetBucketLocation. The others are regional.

What we care about for graph reasoning:
  S3:            public access block, bucket policy presence, encryption
  RDS:           publicly_accessible, encryption, VPC placement
  DynamoDB:      encryption type (AES256 vs KMS), deletion protection, streams
  ElastiCache:   encryption at rest/in transit, auth token, security groups
"""
from __future__ import annotations

import json
import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class DataScanner(BaseScanner):
    domain = "data"
    is_global = False  # RDS is regional. S3 is handled specially below.

    def __init__(self, session):
        super().__init__(session)
        self._s3_scanned = False

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        # S3 is global — scan it exactly once regardless of which regions are targeted
        if not self._s3_scanned:
            self._s3_scanned = True
            resources.extend(self._scan_s3())
        resources.extend(self._scan_rds(region))
        resources.extend(self._scan_dynamodb(region))
        resources.extend(self._scan_elasticache(region))
        return resources

    # ───────────────────────────── S3 ────────────────────────────────────

    def _scan_s3(self) -> list[Resource]:
        """
        Enumerate all buckets in the account. For each:
          - resolve its actual region
          - read public access block, encryption, ACL, policy

        Each per-bucket call can fail independently (permissions, region
        weirdness). We log and skip — partial S3 inventory beats none.
        """
        s3 = self.session.client("s3", region="us-east-1")
        try:
            response = s3.list_buckets()
        except ClientError as e:
            logger.warning("list_buckets failed: %s", e.response["Error"]["Code"])
            raise

        resources = []
        for bucket in response["Buckets"]:
            bucket_name = bucket["Name"]
            try:
                resource = self._inspect_bucket(bucket_name)
                resources.append(resource)
            except ClientError as e:
                # AccessDenied on individual buckets is common in shared accounts
                logger.warning("Skipped bucket %s: %s", bucket_name, e.response["Error"]["Code"])
                self.errors.append({
                    "domain": self.domain,
                    "resource": bucket_name,
                    "error": str(e),
                    "error_type": "S3InspectFailed",
                })
        return resources

    def _inspect_bucket(self, bucket_name: str) -> Resource:
        # Bucket region — sometimes returns None for us-east-1, sometimes "EU"
        s3 = self.session.client("s3", region="us-east-1")
        loc_response = s3.get_bucket_location(Bucket=bucket_name)
        region = loc_response.get("LocationConstraint") or "us-east-1"
        if region == "EU":  # legacy alias
            region = "eu-west-1"

        arn = f"arn:aws:s3:::{bucket_name}"

        # Public access block (the modern safety net)
        public_access_block = self._safe_call(
            s3.get_public_access_block, Bucket=bucket_name
        )
        pab = public_access_block.get("PublicAccessBlockConfiguration", {}) if public_access_block else {}

        # Bucket policy (presence is more important than content for indexing)
        policy = self._safe_call(s3.get_bucket_policy, Bucket=bucket_name)
        bucket_policy = json.loads(policy["Policy"]) if policy and "Policy" in policy else None

        # Encryption
        encryption = self._safe_call(s3.get_bucket_encryption, Bucket=bucket_name)
        is_encrypted = bool(encryption)

        # Versioning
        versioning = self._safe_call(s3.get_bucket_versioning, Bucket=bucket_name)
        versioning_status = versioning.get("Status") if versioning else None

        properties = {
            "bucket_name": bucket_name,
            "public_access_block": {
                "block_public_acls": pab.get("BlockPublicAcls"),
                "ignore_public_acls": pab.get("IgnorePublicAcls"),
                "block_public_policy": pab.get("BlockPublicPolicy"),
                "restrict_public_buckets": pab.get("RestrictPublicBuckets"),
            },
            "has_bucket_policy": bucket_policy is not None,
            "bucket_policy": bucket_policy,
            "is_encrypted": is_encrypted,
            "versioning_status": versioning_status,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.S3_BUCKET,
            name=bucket_name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )

    @staticmethod
    def _safe_call(fn, **kwargs) -> dict | None:
        """
        Many S3 sub-API calls raise "NoSuch*" when the feature isn't configured
        (e.g., no bucket policy → NoSuchBucketPolicy). Treat those as "absent",
        not as errors.
        """
        try:
            return fn(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code.startswith("NoSuch") or code == "ServerSideEncryptionConfigurationNotFoundError":
                return None
            raise

    # ───────────────────────────── RDS ───────────────────────────────────

    def _scan_rds(self, region: str) -> list[Resource]:
        rds = self.session.client("rds", region=region)
        paginator = rds.get_paginator("describe_db_instances")

        resources = []
        try:
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    resources.append(self._normalize_rds(db, region))
        except ClientError as e:
            logger.warning("RDS scan failed in %s: %s", region, e.response["Error"]["Code"])
            raise
        return resources

    def _normalize_rds(self, db: dict, region: str) -> Resource:
        db_id = db["DBInstanceIdentifier"]
        arn = db["DBInstanceArn"]

        endpoint = db.get("Endpoint", {}) or {}
        vpc_security_groups = [
            sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])
        ]

        properties = {
            "db_instance_id": db_id,
            "engine": db.get("Engine"),
            "engine_version": db.get("EngineVersion"),
            "instance_class": db.get("DBInstanceClass"),
            "publicly_accessible": db.get("PubliclyAccessible", False),
            "storage_encrypted": db.get("StorageEncrypted", False),
            "master_username": db.get("MasterUsername"),
            "endpoint_address": endpoint.get("Address"),
            "endpoint_port": endpoint.get("Port"),
            "vpc_id": db.get("DBSubnetGroup", {}).get("VpcId"),
            "vpc_security_group_ids": vpc_security_groups,
            "iam_database_auth_enabled": db.get("IAMDatabaseAuthenticationEnabled", False),
            "deletion_protection": db.get("DeletionProtection", False),
            "status": db.get("DBInstanceStatus"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.RDS_INSTANCE,
            name=db_id,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )

    # ─────────────────────────── DynamoDB ────────────────────────────────

    def _scan_dynamodb(self, region: str) -> list[Resource]:
        ddb = self.session.client("dynamodb", region=region)
        paginator = ddb.get_paginator("list_tables")
        resources: list[Resource] = []
        try:
            for page in paginator.paginate():
                for table_name in page["TableNames"]:
                    try:
                        resp = ddb.describe_table(TableName=table_name)
                        resources.append(self._normalize_dynamodb(resp["Table"], region))
                    except ClientError as e:
                        logger.warning(
                            "DescribeTable %s failed: %s",
                            table_name,
                            e.response["Error"]["Code"],
                        )
        except ClientError as e:
            logger.warning(
                "DynamoDB scan failed in %s: %s", region, e.response["Error"]["Code"]
            )
            raise
        return resources

    def _normalize_dynamodb(self, table: dict, region: str) -> Resource:
        table_name = table["TableName"]
        arn = table["TableArn"]

        sse = table.get("SSEDescription", {}) or {}
        kms_key_arn = sse.get("KMSMasterKeyArn")

        stream_spec = table.get("StreamSpecification", {}) or {}

        properties = {
            "table_name": table_name,
            "status": table.get("TableStatus"),
            "billing_mode": (
                table.get("BillingModeSummary", {}).get("BillingMode") or "PROVISIONED"
            ),
            "item_count": table.get("ItemCount", 0),
            "size_bytes": table.get("TableSizeBytes", 0),
            "sse_type": sse.get("SSEType"),  # AES256 or KMS
            "sse_enabled": sse.get("Status") == "ENABLED",
            "kms_key_arn": kms_key_arn,
            "stream_enabled": bool(stream_spec.get("StreamEnabled")),
            "deletion_protection": table.get("DeletionProtectionEnabled", False),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.DYNAMODB_TABLE,
            name=table_name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )

    # ─────────────────────────── ElastiCache ─────────────────────────────

    def _scan_elasticache(self, region: str) -> list[Resource]:
        ec = self.session.client("elasticache", region=region)
        resources: list[Resource] = []
        seen_rg_ids: set[str] = set()

        # Redis replication groups — the logical cluster entity (primary + replicas)
        try:
            paginator = ec.get_paginator("describe_replication_groups")
            for page in paginator.paginate():
                for rg in page["ReplicationGroups"]:
                    resources.append(self._normalize_replication_group(rg, region))
                    seen_rg_ids.add(rg["ReplicationGroupId"])
        except ClientError as e:
            logger.warning(
                "ElastiCache DescribeReplicationGroups failed in %s: %s",
                region,
                e.response["Error"]["Code"],
            )

        # Memcached clusters + single-node Redis not in a replication group
        try:
            paginator = ec.get_paginator("describe_cache_clusters")
            for page in paginator.paginate():
                for cluster in page["CacheClusters"]:
                    rg_id = cluster.get("ReplicationGroupId")
                    if rg_id and rg_id in seen_rg_ids:
                        continue  # already covered above
                    resources.append(self._normalize_cache_cluster(cluster, region))
        except ClientError as e:
            logger.warning(
                "ElastiCache DescribeCacheClusters failed in %s: %s",
                region,
                e.response["Error"]["Code"],
            )

        return resources

    def _normalize_replication_group(self, rg: dict, region: str) -> Resource:
        rg_id = rg["ReplicationGroupId"]
        arn = rg.get(
            "ARN",
            f"arn:aws:elasticache:{region}:{self.session.account_id}:replicationgroup:{rg_id}",
        )
        kms_key_arn = rg.get("KmsKeyId") or None  # may be key ARN or ID

        properties = {
            "cluster_id": rg_id,
            "cluster_type": "redis_replication_group",
            "engine": "redis",
            "status": rg.get("Status"),
            "node_type": rg.get("CacheNodeType"),
            "multi_az": rg.get("MultiAZ") == "enabled",
            "automatic_failover": rg.get("AutomaticFailover") == "enabled",
            "cluster_mode": "enabled" if rg.get("ClusterEnabled") else "disabled",
            "at_rest_encryption_enabled": rg.get("AtRestEncryptionEnabled", False),
            "transit_encryption_enabled": rg.get("TransitEncryptionEnabled", False),
            "auth_token_enabled": rg.get("AuthTokenEnabled", False),
            "kms_key_arn": kms_key_arn,
            "member_count": len(rg.get("MemberClusters", [])),
            # SG IDs are only on member cache clusters, not on the replication group object
            "security_group_ids": [],
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.ELASTICACHE_CLUSTER,
            name=rg_id,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )

    def _normalize_cache_cluster(self, cluster: dict, region: str) -> Resource:
        cluster_id = cluster["CacheClusterId"]
        arn = cluster.get(
            "ARN",
            f"arn:aws:elasticache:{region}:{self.session.account_id}:cluster:{cluster_id}",
        )
        engine = cluster.get("Engine", "redis")
        sg_ids = [sg["SecurityGroupId"] for sg in cluster.get("SecurityGroups", [])]
        kms_key_arn = cluster.get("KmsKeyId") or None

        cluster_type = "memcached_cluster" if engine == "memcached" else "redis_standalone"

        properties = {
            "cluster_id": cluster_id,
            "cluster_type": cluster_type,
            "engine": engine,
            "engine_version": cluster.get("EngineVersion"),
            "status": cluster.get("CacheClusterStatus"),
            "node_type": cluster.get("CacheNodeType"),
            "num_cache_nodes": cluster.get("NumCacheNodes", 1),
            "at_rest_encryption_enabled": cluster.get("AtRestEncryptionEnabled", False),
            "transit_encryption_enabled": cluster.get("TransitEncryptionEnabled", False),
            "auth_token_enabled": cluster.get("AuthTokenEnabled", False),
            "kms_key_arn": kms_key_arn,
            "security_group_ids": sg_ids,
            "cache_subnet_group_name": cluster.get("CacheSubnetGroupName"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.ELASTICACHE_CLUSTER,
            name=cluster_id,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )
