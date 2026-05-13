"""
EKS scanner — clusters, managed node groups, and Fargate profiles.

Key properties for graph reasoning:
  Cluster:
    - cluster_role_arn       → IAM role the EKS control plane uses
    - endpoint_public_access → public API server is a potential entry point
    - vpc_id, security_group_ids → network placement for SG + VPC edges
    - secrets_encrypted      → negative finding if etcd secrets are not KMS-wrapped
    - logging_enabled        → negative finding if cluster logging is off

  NodeGroup:
    - node_role_arn          → IAM role attached to EC2 worker instances (critical
                               escalation path: SSRF on any pod → node IMDS → role)

  FargateProfile:
    - pod_execution_role_arn → IAM role injected into every matching pod
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class EksScanner(BaseScanner):
    domain = "eks"

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        eks = self.session.client("eks", region=region)

        try:
            cluster_names = _paginate(eks, "list_clusters", "clusters")
        except ClientError as e:
            logger.warning(
                "EKS ListClusters failed in %s: %s", region, e.response["Error"]["Code"]
            )
            raise

        for cluster_name in cluster_names:
            try:
                cluster_resp = eks.describe_cluster(name=cluster_name)
                cluster_resource = self._normalize_cluster(cluster_resp["cluster"], region)
                resources.append(cluster_resource)
            except ClientError as e:
                logger.warning(
                    "DescribeCluster %s failed: %s", cluster_name, e.response["Error"]["Code"]
                )
                self.errors.append({
                    "domain": self.domain,
                    "resource": cluster_name,
                    "region": region,
                    "error": str(e),
                    "error_type": "EKSDescribeClusterFailed",
                })
                continue

            self._scan_nodegroups(eks, cluster_name, region, resources)
            self._scan_fargate_profiles(eks, cluster_name, region, resources)

        return resources

    def _scan_nodegroups(
        self,
        eks,
        cluster_name: str,
        region: str,
        resources: list[Resource],
    ) -> None:
        try:
            ng_names = _paginate(eks, "list_nodegroups", "nodegroups", clusterName=cluster_name)
        except ClientError as e:
            logger.warning(
                "ListNodegroups %s failed: %s", cluster_name, e.response["Error"]["Code"]
            )
            return

        for ng_name in ng_names:
            try:
                ng_resp = eks.describe_nodegroup(
                    clusterName=cluster_name, nodegroupName=ng_name
                )
                resources.append(
                    self._normalize_nodegroup(ng_resp["nodegroup"], cluster_name, region)
                )
            except ClientError as e:
                logger.warning(
                    "DescribeNodegroup %s/%s failed: %s",
                    cluster_name,
                    ng_name,
                    e.response["Error"]["Code"],
                )

    def _scan_fargate_profiles(
        self,
        eks,
        cluster_name: str,
        region: str,
        resources: list[Resource],
    ) -> None:
        try:
            fp_names = _paginate(
                eks, "list_fargate_profiles", "fargateProfileNames", clusterName=cluster_name
            )
        except ClientError as e:
            logger.warning(
                "ListFargateProfiles %s failed: %s", cluster_name, e.response["Error"]["Code"]
            )
            return

        for fp_name in fp_names:
            try:
                fp_resp = eks.describe_fargate_profile(
                    clusterName=cluster_name, fargateProfileName=fp_name
                )
                resources.append(
                    self._normalize_fargate_profile(
                        fp_resp["fargateProfile"], cluster_name, region
                    )
                )
            except ClientError as e:
                logger.warning(
                    "DescribeFargateProfile %s/%s failed: %s",
                    cluster_name,
                    fp_name,
                    e.response["Error"]["Code"],
                )

    # ───────────────────────── Normalizers ────────────────────────────────

    def _normalize_cluster(self, cluster: dict, region: str) -> Resource:
        arn = cluster["arn"]
        name = cluster["name"]
        tags = cluster.get("tags", {})

        vpc_config = cluster.get("resourcesVpcConfig", {}) or {}
        sg_ids = list(vpc_config.get("securityGroupIds", []))
        cluster_sg = vpc_config.get("clusterSecurityGroupId")
        if cluster_sg and cluster_sg not in sg_ids:
            sg_ids.append(cluster_sg)

        logging_config = cluster.get("logging", {}) or {}
        enabled_log_types: list[str] = []
        for setup in logging_config.get("clusterLogging", []):
            if setup.get("enabled"):
                enabled_log_types.extend(setup.get("types", []))

        encryption_config = cluster.get("encryptionConfig", []) or []
        secrets_encrypted = any(
            "secrets" in cfg.get("resources", []) for cfg in encryption_config
        )
        kms_key_arn: str | None = None
        for cfg in encryption_config:
            if "secrets" in cfg.get("resources", []):
                kms_key_arn = cfg.get("provider", {}).get("keyArn")
                break

        properties = {
            "cluster_name": name,
            "kubernetes_version": cluster.get("version"),
            "status": cluster.get("status"),
            "cluster_role_arn": cluster.get("roleArn"),
            "vpc_id": vpc_config.get("vpcId"),
            "subnet_ids": vpc_config.get("subnetIds", []),
            "security_group_ids": sg_ids,
            "endpoint_public_access": vpc_config.get("endpointPublicAccess", True),
            "endpoint_private_access": vpc_config.get("endpointPrivateAccess", False),
            "public_access_cidrs": vpc_config.get("publicAccessCidrs", ["0.0.0.0/0"]),
            "enabled_log_types": enabled_log_types,
            "logging_enabled": bool(enabled_log_types),
            "secrets_encrypted": secrets_encrypted,
            "kms_key_arn": kms_key_arn,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.EKS_CLUSTER,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    def _normalize_nodegroup(
        self, ng: dict, cluster_name: str, region: str
    ) -> Resource:
        arn = ng["nodegroupArn"]
        name = ng["nodegroupName"]
        tags = ng.get("tags", {})
        launch_template = ng.get("launchTemplate") or {}

        properties = {
            "nodegroup_name": name,
            "cluster_name": cluster_name,
            "node_role_arn": ng.get("nodeRole"),
            "status": ng.get("status"),
            "ami_type": ng.get("amiType"),
            "instance_types": ng.get("instanceTypes", []),
            "disk_size": ng.get("diskSize"),
            "subnet_ids": ng.get("subnets", []),
            "scaling_desired": ng.get("scalingConfig", {}).get("desiredSize"),
            "scaling_min": ng.get("scalingConfig", {}).get("minSize"),
            "scaling_max": ng.get("scalingConfig", {}).get("maxSize"),
            "launch_template_id": launch_template.get("id"),
            "release_version": ng.get("releaseVersion"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.EKS_NODEGROUP,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    def _normalize_fargate_profile(
        self, fp: dict, cluster_name: str, region: str
    ) -> Resource:
        arn = fp["fargateProfileArn"]
        name = fp["fargateProfileName"]
        tags = fp.get("tags", {})

        properties = {
            "profile_name": name,
            "cluster_name": cluster_name,
            "pod_execution_role_arn": fp.get("podExecutionRoleArn"),
            "status": fp.get("status"),
            "subnet_ids": fp.get("subnets", []),
            "selectors": [
                {"namespace": s.get("namespace"), "labels": s.get("labels", {})}
                for s in fp.get("selectors", [])
            ],
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.EKS_FARGATE_PROFILE,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )


def _paginate(client, method: str, key: str, **kwargs) -> list:
    """Paginate any EKS list-* call and return the flat result list."""
    items: list = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        items.extend(page[key])
    return items
