"""
Data store scanner — S3 buckets and RDS instances.

S3 is global, so we scan once and resolve each bucket's actual region via
GetBucketLocation. RDS is regional.

What we care about for graph reasoning:
  S3:  public access block, bucket policy presence, encryption, ACL grants
  RDS: publicly_accessible flag, encryption, VPC subnet group, master username

These properties drive `holds_sensitive_data` flags and influence severity
scoring in the LLM phase.
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
