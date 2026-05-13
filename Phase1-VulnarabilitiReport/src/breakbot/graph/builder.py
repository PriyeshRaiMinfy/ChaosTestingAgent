"""
GraphBuilder — constructs a networkx.MultiDiGraph from a ScanResult.

Every scanned AWS resource becomes a node keyed by its ARN.
Relationships between resources become typed directed edges.

Edge types built here (static graph only — behavioral edges from CloudTrail
are added in Phase 3 overlay step):

  iam_can_assume       Trust policy Principal         →  IAM Role
  has_execution_role   Lambda / EKS cluster/nodegroup →  IAM Role
  has_instance_profile EC2                            →  IAM Role (best-effort name match)
  iam_can_access       IAM Role                       →  Resource
  attached_to_sg       EC2 / Lambda / RDS / ALB /
                       EKS cluster / ElastiCache       →  SecurityGroup
  network_can_reach    SecurityGroup                  →  SecurityGroup (ingress SG ref)
  internet_exposes     INTERNET (virtual)             →  SecurityGroup (0.0.0.0/0 ingress)
  in_vpc               Lambda / RDS / EC2 / EKS       →  VPC
  has_node_group       EKS cluster                    →  EKS nodegroup
  has_fargate_profile  EKS cluster                    →  EKS Fargate profile
  encrypted_by         Secret / Param / DynamoDB /
                       ElastiCache / EKS cluster       →  KMS key
"""
from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from breakbot.graph.edges import INTERNET_NODE_ID, EdgeType
from breakbot.models import Resource, ResourceType, ScanResult

logger = logging.getLogger(__name__)


class GraphBuilder:
    """
    Usage:
        builder = GraphBuilder(scan_result)
        graph = builder.build()
        arn_index = builder.arn_index   # dict[str, Resource] for serializer
    """

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()

        # Lookup tables populated during _build_indexes()
        self._arn_index: dict[str, Resource] = {}
        self._sg_id_to_arn: dict[str, str] = {}             # sg-xxxxxx → ARN
        self._role_name_to_arn: dict[str, str] = {}         # role name → ARN
        self._vpc_id_to_arn: dict[str, str] = {}            # vpc-xxxxxx → ARN
        self._eks_cluster_name_to_arn: dict[str, str] = {}  # cluster name → ARN
        self._kms_key_id_to_arn: dict[str, str] = {}        # key UUID → ARN

    @property
    def arn_index(self) -> dict[str, Resource]:
        return self._arn_index

    # ─────────────────────────── Public API ───────────────────────────────

    def build(self) -> nx.MultiDiGraph:
        self._build_indexes()
        self._add_all_nodes()
        self._add_iam_trust_edges()
        self._add_compute_role_edges()
        self._add_eks_role_edges()
        self._add_eks_membership_edges()
        self._add_sg_attachment_edges()
        self._add_network_reachability_edges()
        self._add_internet_exposure_edges()
        self._add_iam_policy_access_edges()
        self._add_vpc_membership_edges()
        self._add_encryption_edges()

        logger.info(
            "Graph built: %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )
        return self.graph

    # ─────────────────────────── Indexes ──────────────────────────────────

    def _build_indexes(self) -> None:
        """Build fast-lookup dicts that edge inference rules rely on."""
        for resource in self.result.resources:
            self._arn_index[resource.arn] = resource

            if resource.resource_type == ResourceType.SECURITY_GROUP:
                sg_id = resource.properties.get("group_id")
                if sg_id:
                    self._sg_id_to_arn[sg_id] = resource.arn

            elif resource.resource_type == ResourceType.IAM_ROLE:
                role_name = resource.properties.get("role_name")
                if role_name:
                    self._role_name_to_arn[role_name] = resource.arn

            elif resource.resource_type == ResourceType.VPC:
                vpc_id = resource.properties.get("vpc_id")
                if vpc_id:
                    self._vpc_id_to_arn[vpc_id] = resource.arn

            elif resource.resource_type == ResourceType.EKS_CLUSTER:
                cluster_name = resource.properties.get("cluster_name")
                if cluster_name:
                    self._eks_cluster_name_to_arn[cluster_name] = resource.arn

            elif resource.resource_type == ResourceType.KMS_KEY:
                key_id = resource.properties.get("key_id")
                if key_id:
                    self._kms_key_id_to_arn[key_id] = resource.arn

    # ─────────────────────────── Nodes ────────────────────────────────────

    def _add_all_nodes(self) -> None:
        """Add every scanned resource as a node, plus the virtual INTERNET node."""
        self.graph.add_node(INTERNET_NODE_ID, type="virtual", name="INTERNET")

        for resource in self.result.resources:
            # Only store scalar attributes directly on the node — complex nested
            # structures (dicts, lists) are accessed via arn_index instead.
            scalar_props = {
                k: v
                for k, v in resource.properties.items()
                if _is_scalar(v)
            }
            self.graph.add_node(
                resource.arn,
                type=resource.resource_type.value,
                name=resource.name,
                region=resource.region,
                account_id=resource.account_id,
                **scalar_props,
            )

    # ─────────────────────── IAM Trust Edges ──────────────────────────────

    def _add_iam_trust_edges(self) -> None:
        """
        For each IAM role, parse its trust policy and add iam_can_assume edges.
        Principal → Role means that Principal can call sts:AssumeRole on this role.
        """
        for resource in self.result.resources:
            if resource.resource_type != ResourceType.IAM_ROLE:
                continue

            trust_policy = resource.properties.get("trust_policy")
            if not trust_policy:
                continue

            for stmt in trust_policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue

                actions = _as_list(stmt.get("Action", []))
                is_assume = any(
                    a in ("sts:AssumeRole", "sts:AssumeRoleWithWebIdentity",
                          "sts:AssumeRoleWithSAML", "*")
                    for a in actions
                )
                if not is_assume:
                    continue

                for principal_id in _normalize_principals(stmt.get("Principal", {})):
                    self._ensure_node(principal_id, "external_principal")
                    self.graph.add_edge(
                        principal_id,
                        resource.arn,
                        edge_type=EdgeType.IAM_CAN_ASSUME,
                        label=EdgeType.IAM_CAN_ASSUME.value,
                    )

    # ──────────────────── Compute → Role Edges ────────────────────────────

    def _add_compute_role_edges(self) -> None:
        """
        Lambda execution role → IAM Role  (has_execution_role)
        EC2 instance profile → IAM Role   (has_instance_profile, best-effort name match)
        """
        for resource in self.result.resources:
            if resource.resource_type == ResourceType.LAMBDA_FUNCTION:
                role_arn = resource.properties.get("role_arn")
                if role_arn:
                    self._ensure_node(role_arn, ResourceType.IAM_ROLE.value)
                    self.graph.add_edge(
                        resource.arn,
                        role_arn,
                        edge_type=EdgeType.HAS_EXECUTION_ROLE,
                        label=EdgeType.HAS_EXECUTION_ROLE.value,
                    )

            elif resource.resource_type == ResourceType.ECS_TASK_DEFINITION:
                task_role_arn = resource.properties.get("task_role_arn")
                if task_role_arn:
                    self._ensure_node(task_role_arn, ResourceType.IAM_ROLE.value)
                    self.graph.add_edge(
                        resource.arn,
                        task_role_arn,
                        edge_type=EdgeType.HAS_EXECUTION_ROLE,
                        label=EdgeType.HAS_EXECUTION_ROLE.value,
                    )

            elif resource.resource_type == ResourceType.EC2_INSTANCE:
                profile_arn = resource.properties.get("iam_instance_profile_arn")
                if not profile_arn:
                    continue

                # Instance profile name and role name are almost always identical.
                # If we can resolve it, add a direct edge to the role.
                profile_name = profile_arn.split("/")[-1]
                role_arn = self._role_name_to_arn.get(profile_name)

                if role_arn:
                    self.graph.add_edge(
                        resource.arn,
                        role_arn,
                        edge_type=EdgeType.HAS_INSTANCE_PROFILE,
                        label=EdgeType.HAS_INSTANCE_PROFILE.value,
                        instance_profile_arn=profile_arn,
                    )
                else:
                    # Can't resolve to a known role — add the profile ARN as an
                    # unresolved node so the graph isn't silently incomplete.
                    self._ensure_node(profile_arn, "iam:instance-profile")
                    self.graph.nodes[profile_arn]["note"] = "unresolved_to_role"
                    self.graph.add_edge(
                        resource.arn,
                        profile_arn,
                        edge_type=EdgeType.HAS_INSTANCE_PROFILE,
                        label=EdgeType.HAS_INSTANCE_PROFILE.value,
                    )

    # ──────────────────── SG Attachment Edges ─────────────────────────────

    def _add_sg_attachment_edges(self) -> None:
        """Resource → SecurityGroup when the resource is assigned to that SG."""
        _SG_PROP: dict[ResourceType, str] = {
            ResourceType.EC2_INSTANCE: "security_group_ids",
            ResourceType.LAMBDA_FUNCTION: "security_group_ids",
            ResourceType.RDS_INSTANCE: "vpc_security_group_ids",
            ResourceType.ALB: "security_group_ids",
            ResourceType.EKS_CLUSTER: "security_group_ids",
            ResourceType.ELASTICACHE_CLUSTER: "security_group_ids",
            ResourceType.ECS_SERVICE: "security_group_ids",   # awsvpc network mode
            ResourceType.MSK_CLUSTER: "security_group_ids",
        }

        for resource in self.result.resources:
            sg_prop = _SG_PROP.get(resource.resource_type)
            if not sg_prop:
                continue

            for sg_id in resource.properties.get(sg_prop, []):
                sg_arn = self._sg_id_to_arn.get(sg_id)
                if sg_arn:
                    self.graph.add_edge(
                        resource.arn,
                        sg_arn,
                        edge_type=EdgeType.ATTACHED_TO_SG,
                        label=EdgeType.ATTACHED_TO_SG.value,
                    )

    # ──────────────────── Network Reachability Edges ──────────────────────

    def _add_network_reachability_edges(self) -> None:
        """
        When SG_B's ingress rules reference SG_A, instances in SG_A can send
        traffic to instances in SG_B on the specified ports.
        Edge: SG_A → SG_B [network_can_reach]
        """
        for resource in self.result.resources:
            if resource.resource_type != ResourceType.SECURITY_GROUP:
                continue

            for rule in resource.properties.get("ingress_rules", []):
                for src_sg_id in rule.get("referenced_sgs", []):
                    src_sg_arn = self._sg_id_to_arn.get(src_sg_id)
                    if src_sg_arn:
                        self.graph.add_edge(
                            src_sg_arn,
                            resource.arn,
                            edge_type=EdgeType.NETWORK_CAN_REACH,
                            label=EdgeType.NETWORK_CAN_REACH.value,
                            from_port=rule.get("from_port"),
                            to_port=rule.get("to_port"),
                            protocol=rule.get("protocol"),
                        )

    # ──────────────────── Internet Exposure Edges ─────────────────────────

    def _add_internet_exposure_edges(self) -> None:
        """
        INTERNET → SG when the SG has a 0.0.0.0/0 or ::/0 ingress rule.
        One edge per exposed port range so the serializer can report specifics.
        """
        for resource in self.result.resources:
            if resource.resource_type != ResourceType.SECURITY_GROUP:
                continue
            if not resource.properties.get("internet_exposed"):
                continue

            for rule in resource.properties.get("ingress_rules", []):
                cidrs = rule.get("cidrs", []) + rule.get("ipv6_cidrs", [])
                if "0.0.0.0/0" not in cidrs and "::/0" not in cidrs:
                    continue

                self.graph.add_edge(
                    INTERNET_NODE_ID,
                    resource.arn,
                    edge_type=EdgeType.INTERNET_EXPOSES,
                    label=EdgeType.INTERNET_EXPOSES.value,
                    from_port=rule.get("from_port"),
                    to_port=rule.get("to_port"),
                    protocol=rule.get("protocol"),
                )

    # ──────────────────── IAM Policy Access Edges ─────────────────────────

    def _add_iam_policy_access_edges(self) -> None:
        """
        IAM Role → Resource for every Allow statement in the role's policies.
        Parses both inline policies and managed policies (if documents are present).
        """
        for resource in self.result.resources:
            if resource.resource_type != ResourceType.IAM_ROLE:
                continue

            all_docs: list[tuple[str, str, dict]] = []

            for inline in resource.properties.get("inline_policies", []):
                doc = inline.get("document")
                if doc:
                    all_docs.append(("inline", inline["name"], doc))

            for managed in resource.properties.get("managed_policies", []):
                doc = managed.get("document")
                if doc:
                    all_docs.append(("managed", managed["name"], doc))

            for policy_type, policy_name, doc in all_docs:
                self._parse_policy_into_edges(resource.arn, policy_type, policy_name, doc)

    def _parse_policy_into_edges(
        self,
        role_arn: str,
        policy_type: str,
        policy_name: str,
        document: dict,
    ) -> None:
        for stmt in document.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue

            actions = _as_list(stmt.get("Action", []))
            resources = _as_list(stmt.get("Resource", []))
            conditions = stmt.get("Condition", {})
            is_admin = "*" in actions

            for resource_arn in resources:
                if resource_arn == "*":
                    # Full resource wildcard — mark the role node rather than
                    # creating an edge to every resource in the account.
                    self.graph.nodes[role_arn]["has_wildcard_resource_access"] = True
                    self.graph.nodes[role_arn]["wildcard_actions"] = actions
                    continue

                target = self._resolve_resource_arn(resource_arn)
                self._ensure_node(target, "unknown")

                self.graph.add_edge(
                    role_arn,
                    target,
                    edge_type=EdgeType.IAM_CAN_ACCESS,
                    label=EdgeType.IAM_CAN_ACCESS.value,
                    actions=actions,
                    resource_pattern=resource_arn,
                    policy_type=policy_type,
                    policy_name=policy_name,
                    is_wildcard_resource="*" in resource_arn,
                    is_admin=is_admin,
                    has_conditions=bool(conditions),
                )

    def _resolve_resource_arn(self, arn: str) -> str:
        """
        Strip common ARN path suffixes to find a root resource node.
        arn:aws:s3:::my-bucket/*  →  arn:aws:s3:::my-bucket  (if that node exists)
        Returns the original ARN unchanged if no match is found.
        """
        if arn in self._arn_index:
            return arn
        for suffix in ("/*", ":*"):
            if arn.endswith(suffix):
                stripped = arn[: -len(suffix)]
                if stripped in self._arn_index:
                    return stripped
        return arn

    # ──────────────────── VPC Membership Edges ────────────────────────────

    def _add_vpc_membership_edges(self) -> None:
        """Resources with a vpc_id property → VPC when the VPC is in the scan."""
        _VPC_TYPES = {
            ResourceType.LAMBDA_FUNCTION,
            ResourceType.RDS_INSTANCE,
            ResourceType.EC2_INSTANCE,
            ResourceType.EKS_CLUSTER,
            ResourceType.NAT_GATEWAY,
            ResourceType.INTERNET_GATEWAY,
        }
        for resource in self.result.resources:
            if resource.resource_type not in _VPC_TYPES:
                continue
            vpc_id = resource.properties.get("vpc_id")
            if not vpc_id:
                continue
            vpc_arn = self._vpc_id_to_arn.get(vpc_id)
            if vpc_arn:
                self.graph.add_edge(
                    resource.arn,
                    vpc_arn,
                    edge_type=EdgeType.IN_VPC,
                    label=EdgeType.IN_VPC.value,
                )

    # ──────────────────── EKS Role Edges ──────────────────────────────────

    def _add_eks_role_edges(self) -> None:
        """
        EKS cluster/nodegroup/Fargate profile → IAM role (has_execution_role).

        Attack path significance:
          - cluster role:   can call AWS APIs on behalf of the control plane
          - node role:      attached to EC2 worker instances; SSRF on any pod
                            can reach instance IMDS and steal this role
          - pod exec role:  injected into every Fargate pod matching the selector
        """
        _ROLE_PROP: dict[ResourceType, str] = {
            ResourceType.EKS_CLUSTER: "cluster_role_arn",
            ResourceType.EKS_NODEGROUP: "node_role_arn",
            ResourceType.EKS_FARGATE_PROFILE: "pod_execution_role_arn",
        }
        for resource in self.result.resources:
            prop = _ROLE_PROP.get(resource.resource_type)
            if not prop:
                continue
            role_arn = resource.properties.get(prop)
            if role_arn:
                self._ensure_node(role_arn, ResourceType.IAM_ROLE.value)
                self.graph.add_edge(
                    resource.arn,
                    role_arn,
                    edge_type=EdgeType.HAS_EXECUTION_ROLE,
                    label=EdgeType.HAS_EXECUTION_ROLE.value,
                )

    # ──────────────────── EKS Membership Edges ────────────────────────────

    def _add_eks_membership_edges(self) -> None:
        """EKS cluster → nodegroup / Fargate profile."""
        for resource in self.result.resources:
            cluster_name: str | None = None
            edge_type: EdgeType | None = None

            if resource.resource_type == ResourceType.EKS_NODEGROUP:
                cluster_name = resource.properties.get("cluster_name")
                edge_type = EdgeType.HAS_NODE_GROUP
            elif resource.resource_type == ResourceType.EKS_FARGATE_PROFILE:
                cluster_name = resource.properties.get("cluster_name")
                edge_type = EdgeType.HAS_FARGATE_PROFILE

            if cluster_name and edge_type:
                cluster_arn = self._eks_cluster_name_to_arn.get(cluster_name)
                if cluster_arn:
                    self.graph.add_edge(
                        cluster_arn,
                        resource.arn,
                        edge_type=edge_type,
                        label=edge_type.value,
                    )

    # ──────────────────── Encryption Edges ────────────────────────────────

    def _add_encryption_edges(self) -> None:
        """Resource → KMS key (encrypted_by) for every resource with kms_key_arn set."""
        _ENCRYPTED_TYPES: set[ResourceType] = {
            ResourceType.EKS_CLUSTER,
            ResourceType.SECRETS_MANAGER_SECRET,
            ResourceType.SSM_PARAMETER,
            ResourceType.DYNAMODB_TABLE,
            ResourceType.ELASTICACHE_CLUSTER,
            ResourceType.SQS_QUEUE,
            ResourceType.SNS_TOPIC,
            ResourceType.MSK_CLUSTER,
            ResourceType.KINESIS_STREAM,
        }
        for resource in self.result.resources:
            if resource.resource_type not in _ENCRYPTED_TYPES:
                continue
            key_ref = resource.properties.get("kms_key_arn")
            if not key_ref:
                continue
            key_arn = self._resolve_kms_key(key_ref)
            if key_arn:
                self._ensure_node(key_arn, ResourceType.KMS_KEY.value)
                self.graph.add_edge(
                    resource.arn,
                    key_arn,
                    edge_type=EdgeType.ENCRYPTED_BY,
                    label=EdgeType.ENCRYPTED_BY.value,
                )

    def _resolve_kms_key(self, key_ref: str) -> str | None:
        """Resolve a KMS key reference (ARN or bare key UUID) to a graph-usable ARN."""
        if not key_ref:
            return None
        if key_ref.startswith("arn:") and ":key/" in key_ref:
            return key_ref
        if key_ref.startswith("arn:"):
            return None  # alias ARN — can't resolve statically
        if key_ref.startswith("alias/"):
            return None
        if key_ref in self._kms_key_id_to_arn:
            return self._kms_key_id_to_arn[key_ref]
        return None

    # ─────────────────────────── Helpers ──────────────────────────────────

    def _ensure_node(self, node_id: str, node_type: str = "unknown") -> None:
        """Add a node only if it doesn't already exist."""
        if node_id not in self.graph:
            self.graph.add_node(node_id, type=node_type, name=node_id)


# ─────────────────────────── Module helpers ───────────────────────────────


def _normalize_principals(principal: Any) -> list[str]:
    """
    Flatten an IAM trust policy Principal into a list of string IDs.

    Handles all principal shapes:
      "*"                             → ["*"]
      "arn:aws:iam::123:role/X"       → ["arn:aws:iam::123:role/X"]
      {"AWS": "arn:..."}              → ["arn:..."]
      {"AWS": ["arn:...", "arn:..."]} → ["arn:...", "arn:..."]
      {"Service": "lambda.amazonaws.com"} → ["lambda.amazonaws.com"]
      {"Federated": "..."}            → ["federated:..."]
    """
    if principal == "*":
        return ["*"]
    if isinstance(principal, str):
        return [principal]
    if not isinstance(principal, dict):
        return []

    result: list[str] = []
    for key, value in principal.items():
        values = [value] if isinstance(value, str) else list(value)
        if key == "Federated":
            result.extend(f"federated:{v}" for v in values)
        else:
            result.extend(values)
    return result


def _as_list(value: Any) -> list:
    """Normalize a string-or-list field to always be a list."""
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _is_scalar(value: Any) -> bool:
    """Only scalar Python values are stored directly as networkx node attributes."""
    return isinstance(value, (str, int, float, bool)) or value is None
