"""
Compute scanner — EC2 instances and Lambda functions.

What we capture and why:

EC2 instances:
  - IAM instance profile  → drives `iam_can_access` edges to S3/RDS/etc.
  - Security groups       → drives `network_can_reach` edges
  - Public IP / subnet    → identifies internet-facing entry points
  - IMDSv1 vs v2          → IMDSv1 is a well-known SSRF escalation vector
  - AMI ID                → for vulnerable-AMI lookups later

Lambda functions:
  - Execution role        → critical for IAM edge construction
  - VPC config            → determines network reachability
  - Environment variables → potential secret leakage (sanitized — values
                            kept but flagged for the secrets scanner)
  - Triggers              → wired up downstream by graph builder
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class ComputeScanner(BaseScanner):
    domain = "compute"

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        resources.extend(self._scan_ec2(region))
        resources.extend(self._scan_lambda(region))
        return resources

    # ─────────────────────────────── EC2 ──────────────────────────────────

    def _scan_ec2(self, region: str) -> list[Resource]:
        """
        Enumerate EC2 instances with paginator (handles accounts with 1000+ instances).
        """
        ec2 = self.session.client("ec2", region=region)
        paginator = ec2.get_paginator("describe_instances")

        resources: list[Resource] = []
        try:
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        resources.append(self._normalize_ec2(instance, region))
        except ClientError as e:
            # opt-in regions, disabled regions, etc.
            logger.warning("EC2 scan failed in %s: %s", region, e.response["Error"]["Code"])
            raise
        return resources

    def _normalize_ec2(self, instance: dict, region: str) -> Resource:
        """Convert raw boto3 EC2 dict into our normalized Resource model."""
        instance_id = instance["InstanceId"]
        arn = f"arn:aws:ec2:{region}:{self.session.account_id}:instance/{instance_id}"

        # Tags come as [{Key, Value}, ...] — flatten to dict
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        name = tags.get("Name", instance_id)

        # IMDS metadata options — IMDSv1 enabled is a finding
        metadata_opts = instance.get("MetadataOptions", {})
        imds_v1_allowed = metadata_opts.get("HttpTokens") != "required"

        properties = {
            "instance_id": instance_id,
            "instance_type": instance.get("InstanceType"),
            "state": instance.get("State", {}).get("Name"),
            "ami_id": instance.get("ImageId"),
            "vpc_id": instance.get("VpcId"),
            "subnet_id": instance.get("SubnetId"),
            "private_ip": instance.get("PrivateIpAddress"),
            "public_ip": instance.get("PublicIpAddress"),
            "is_public": bool(instance.get("PublicIpAddress")),
            "security_group_ids": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
            "iam_instance_profile_arn": instance.get("IamInstanceProfile", {}).get("Arn"),
            "imds_v1_allowed": imds_v1_allowed,
            "key_name": instance.get("KeyName"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.EC2_INSTANCE,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    # ───────────────────────────── Lambda ────────────────────────────────

    def _scan_lambda(self, region: str) -> list[Resource]:
        """
        Enumerate Lambda functions. Environment variables are captured for the
        secrets scanner to inspect — we do not log or redact them here.
        """
        lam = self.session.client("lambda", region=region)
        paginator = lam.get_paginator("list_functions")

        resources: list[Resource] = []
        try:
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    resources.append(self._normalize_lambda(fn, region))
        except ClientError as e:
            logger.warning("Lambda scan failed in %s: %s", region, e.response["Error"]["Code"])
            raise
        return resources

    def _normalize_lambda(self, fn: dict, region: str) -> Resource:
        arn = fn["FunctionArn"]
        name = fn["FunctionName"]

        vpc_config = fn.get("VpcConfig", {}) or {}
        env_vars = fn.get("Environment", {}).get("Variables", {}) if fn.get("Environment") else {}

        properties = {
            "function_name": name,
            "runtime": fn.get("Runtime"),
            "handler": fn.get("Handler"),
            "role_arn": fn.get("Role"),
            "timeout": fn.get("Timeout"),
            "memory_size": fn.get("MemorySize"),
            "vpc_id": vpc_config.get("VpcId"),
            "subnet_ids": vpc_config.get("SubnetIds", []),
            "security_group_ids": vpc_config.get("SecurityGroupIds", []),
            "in_vpc": bool(vpc_config.get("VpcId")),
            "env_var_count": len(env_vars),
            "env_var_keys": list(env_vars.keys()),  # keys only — values to secrets scanner
            "layers": [l["Arn"] for l in fn.get("Layers", [])],
            "last_modified": fn.get("LastModified"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.LAMBDA_FUNCTION,
            name=name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )
