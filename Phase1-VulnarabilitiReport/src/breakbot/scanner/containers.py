"""
ECS scanner — clusters, services, and task definitions.
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class EcsScanner(BaseScanner):
    domain = "containers"

    def _scan_region(self, region: str) -> list[Resource]:
        return self._safe_scan_call(
            "ecs", "list_clusters", region, lambda: self._scan_ecs(region),
        )

    def _scan_ecs(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        ecs = self.session.client("ecs", region=region)

        cluster_arns = _paginate(ecs, "list_clusters", "clusterArns")
        if not cluster_arns:
            return resources

        for i in range(0, len(cluster_arns), 100):
            batch = cluster_arns[i : i + 100]
            try:
                resp = ecs.describe_clusters(clusters=batch, include=["SETTINGS", "TAGS"])
                for cluster in resp.get("clusters", []):
                    try:
                        resources.append(self._normalize_cluster(cluster, region))
                    except Exception as e:
                        logger.warning(
                            "[containers] failed to normalize cluster %s: %s",
                            cluster.get("clusterName", "?"), e,
                        )
            except ClientError as e:
                logger.warning(
                    "ECS DescribeClusters failed: %s", e.response["Error"]["Code"]
                )

        task_def_arns: set[str] = set()
        for cluster_arn in cluster_arns:
            self._scan_services(ecs, cluster_arn, region, resources, task_def_arns)

        for td_arn in task_def_arns:
            try:
                resp = ecs.describe_task_definition(taskDefinition=td_arn, include=["TAGS"])
                resources.append(self._normalize_task_definition(resp["taskDefinition"], region))
            except ClientError as e:
                logger.warning(
                    "DescribeTaskDefinition %s failed: %s",
                    td_arn, e.response["Error"]["Code"],
                )
            except Exception as e:
                logger.warning(
                    "[containers] failed to normalize task def %s: %s", td_arn, e,
                )

        return resources

    def _scan_services(
        self, ecs, cluster_arn: str, region: str,
        resources: list[Resource], task_def_arns: set[str],
    ) -> None:
        try:
            service_arns = _paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn)
        except ClientError as e:
            logger.warning(
                "ListServices %s failed: %s", cluster_arn, e.response["Error"]["Code"]
            )
            return

        for i in range(0, len(service_arns), 10):
            batch = service_arns[i : i + 10]
            try:
                resp = ecs.describe_services(
                    cluster=cluster_arn, services=batch, include=["TAGS"]
                )
                for svc in resp.get("services", []):
                    try:
                        resources.append(self._normalize_service(svc, region))
                        td_arn = svc.get("taskDefinition")
                        if td_arn:
                            task_def_arns.add(td_arn)
                    except Exception as e:
                        logger.warning(
                            "[containers] failed to normalize service %s: %s",
                            svc.get("serviceName", "?"), e,
                        )
            except ClientError as e:
                logger.warning(
                    "DescribeServices failed: %s", e.response["Error"]["Code"]
                )

    # ───────────────────────── Normalizers ────────────────────────────────

    def _normalize_cluster(self, cluster: dict, region: str) -> Resource:
        arn = cluster["clusterArn"]
        name = cluster["clusterName"]
        tags = {t["key"]: t["value"] for t in cluster.get("tags", [])}

        settings = cluster.get("settings", [])
        insights = next(
            (s["value"] for s in settings if s.get("name") == "containerInsights"),
            "disabled",
        )

        properties = {
            "cluster_name": name,
            "status": cluster.get("status"),
            "capacity_providers": cluster.get("capacityProviders", []),
            "container_insights_enabled": insights == "enabled",
            "active_services_count": cluster.get("activeServicesCount", 0),
            "running_tasks_count": cluster.get("runningTasksCount", 0),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.ECS_CLUSTER,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    def _normalize_service(self, svc: dict, region: str) -> Resource:
        arn = svc["serviceArn"]
        name = svc["serviceName"]
        tags = {t["key"]: t["value"] for t in svc.get("tags", [])}

        net_config = svc.get("networkConfiguration", {}) or {}
        awsvpc = net_config.get("awsvpcConfiguration", {}) or {}

        properties = {
            "service_name": name,
            "cluster_arn": svc.get("clusterArn"),
            "task_definition_arn": svc.get("taskDefinition"),
            "status": svc.get("status"),
            "desired_count": svc.get("desiredCount", 0),
            "running_count": svc.get("runningCount", 0),
            "launch_type": svc.get("launchType"),
            "platform_version": svc.get("platformVersion"),
            "security_group_ids": awsvpc.get("securityGroups", []),
            "subnet_ids": awsvpc.get("subnets", []),
            "assign_public_ip": awsvpc.get("assignPublicIp") == "ENABLED",
            "scheduling_strategy": svc.get("schedulingStrategy"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.ECS_SERVICE,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    def _normalize_task_definition(self, td: dict, region: str) -> Resource:
        arn = td["taskDefinitionArn"]
        family = td["family"]
        revision = td.get("revision", 0)
        name = f"{family}:{revision}"
        tags = {t["key"]: t["value"] for t in td.get("tags", [])}

        containers = td.get("containerDefinitions", [])
        container_summaries = [
            {
                "name": c.get("name"),
                "image": c.get("image"),
                "env_var_count": len(c.get("environment", [])),
                "secret_count": len(c.get("secrets", [])),
                "privileged": c.get("privileged", False),
                "read_only_root_fs": c.get("readonlyRootFilesystem", False),
                "user": c.get("user"),
            }
            for c in containers
        ]

        properties = {
            "family": family,
            "revision": revision,
            "task_role_arn": td.get("taskRoleArn"),
            "execution_role_arn": td.get("executionRoleArn"),
            "network_mode": td.get("networkMode"),
            "requires_compatibilities": td.get("requiresCompatibilities", []),
            "cpu": td.get("cpu"),
            "memory": td.get("memory"),
            "status": td.get("status"),
            "container_count": len(containers),
            "container_summaries": container_summaries,
            "has_privileged_container": any(c.get("privileged", False) for c in containers),
            "pid_mode": td.get("pidMode"),
            "ipc_mode": td.get("ipcMode"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.ECS_TASK_DEFINITION,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )


def _paginate(client, method: str, key: str, **kwargs) -> list:
    items: list = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(key, []))
    return items
