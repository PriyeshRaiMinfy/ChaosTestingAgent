"""
GraphSerializer — converts the dependency graph into a compact text format
optimised for LLM context windows.

Output format (roughly 10× more token-efficient than nested JSON):

  === ENTRY POINTS ===
  NODE arn:aws:elbv2:...:loadbalancer/app/prod-alb [ALB] internet_facing=true dns=prod-alb.elb.amazonaws.com
  NODE arn:aws:ec2:...:instance/i-abc [EC2_INSTANCE] public_ip=1.2.3.4 imds_v1=true

  === SENSITIVE SINKS ===
  NODE arn:aws:rds:...:db:prod-db [RDS_INSTANCE] engine=postgres encrypted=true

  === ATTACK SURFACE PATHS (entry → sink, ≤N hops) ===
  PATH  arn:.../prod-alb  →  arn:.../LambdaRole  →  arn:.../prod-db
    EDGE  arn:.../prod-alb  --[attached_to_sg]-->  arn:.../sg-web
    EDGE  INTERNET          --[internet_exposes port=443]-->  arn:.../sg-web
    ...

  === ALL NODES ===
  ...

  === ALL EDGES ===
  ...
"""
from __future__ import annotations

import logging
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING

import networkx as nx

from breakbot.graph.edges import INTERNET_NODE_ID, EdgeType
from breakbot.models import Resource, ResourceType

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Resource types that represent internet-facing entry points.
_INTERNET_FACING_TYPES = {
    ResourceType.ALB.value,
    ResourceType.EC2_INSTANCE.value,
    ResourceType.S3_BUCKET.value,
    ResourceType.API_GATEWAY_REST_API.value,
    ResourceType.API_GATEWAY_HTTP_API.value,
    ResourceType.CLOUDFRONT_DISTRIBUTION.value,
    ResourceType.EKS_CLUSTER.value,
    ResourceType.ECS_SERVICE.value,
}

# Resource types that hold sensitive data (sinks for attack path analysis).
_SINK_TYPES = {
    ResourceType.RDS_INSTANCE.value,
    ResourceType.S3_BUCKET.value,
    ResourceType.IAM_ROLE.value,
    ResourceType.SECRETS_MANAGER_SECRET.value,
    ResourceType.DYNAMODB_TABLE.value,
    ResourceType.KMS_KEY.value,
    ResourceType.SSM_PARAMETER.value,
}


class GraphSerializer:
    """
    Converts a built dependency graph into LLM-ready text.

    Args:
        graph:     The networkx graph produced by GraphBuilder.build()
        arn_index: The arn_index from GraphBuilder — gives access to full
                   Resource objects (including complex nested properties that
                   aren't stored as node attributes).
        max_hops:  Maximum path length when searching entry → sink paths.
    """

    def __init__(
        self,
        graph: nx.MultiDiGraph,
        arn_index: dict[str, Resource],
        max_hops: int = 5,
    ) -> None:
        self.graph = graph
        self.arn_index = arn_index
        self.max_hops = max_hops

    # ─────────────────────────── Public API ───────────────────────────────

    def serialize(self, max_chars: int | None = None) -> str:
        """
        Return the LLM-ready text representation.

        Args:
            max_chars: optional upper bound on output size. When set, ALL NODES
                and ALL EDGES sections are truncated to fit, while ENTRY POINTS,
                SENSITIVE SINKS, and ATTACK SURFACE PATHS are always preserved
                in full (they're the high-signal sections — a truncated path
                section would defeat the purpose).

                Rough heuristic: tokens ≈ chars / 3 for English. For a 200K-token
                user-message budget on Claude Opus 4.7, pass max_chars ≈ 600_000.
        """
        buf = StringIO()

        entry_points = self._find_entry_points()
        sinks = self._find_sinks()

        # Bounded, always-rendered sections
        self._write_entry_points(buf, entry_points)
        self._write_sinks(buf, sinks)
        self._write_attack_paths(buf, entry_points, sinks)

        # Unbounded sections — can be truncated under a budget
        self._write_all_nodes(buf, remaining=_remaining(max_chars, buf))
        self._write_all_edges(buf, remaining=_remaining(max_chars, buf))

        return buf.getvalue()

    def save(self, path: Path) -> None:
        path.write_text(self.serialize(), encoding="utf-8")
        logger.info("Graph serialization written to %s", path)

    def stats(self) -> dict:
        """Summary counts — useful for CLI output before serializing."""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "entry_points": len(self._find_entry_points()),
            "sinks": len(self._find_sinks()),
            "internet_exposed_sgs": sum(
                1 for _, a in self.graph.nodes(data=True)
                if a.get("type") == ResourceType.SECURITY_GROUP.value
                and a.get("internet_exposed")
            ),
        }

    # ──────────────────── Entry Point / Sink Detection ────────────────────

    def _find_entry_points(self) -> set[str]:
        """
        Internet-facing resources:
          1. ALBs with internet-facing scheme
          2. EC2 instances with a public IP
          3. S3 buckets without a full public access block
          4. API Gateway REST APIs (non-private)
          5. API Gateway HTTP APIs (endpoint not disabled)
          6. CloudFront distributions (enabled)
          7. EKS clusters with public API endpoint
          8. ECS services with public IP assignment
          9. Any resource attached to internet-exposed security groups
        """
        entry_points: set[str] = set()

        for node_id, attrs in self.graph.nodes(data=True):
            t = attrs.get("type", "")

            if t == ResourceType.ALB.value and attrs.get("is_internet_facing"):
                entry_points.add(node_id)

            elif t == ResourceType.EC2_INSTANCE.value and attrs.get("is_public"):
                entry_points.add(node_id)

            elif t == ResourceType.S3_BUCKET.value:
                resource = self.arn_index.get(node_id)
                if resource and _s3_is_public(resource):
                    entry_points.add(node_id)

            elif t == ResourceType.API_GATEWAY_REST_API.value:
                if not attrs.get("is_private"):
                    entry_points.add(node_id)

            elif t == ResourceType.API_GATEWAY_HTTP_API.value:
                if not attrs.get("disable_execute_api_endpoint"):
                    entry_points.add(node_id)

            elif t == ResourceType.CLOUDFRONT_DISTRIBUTION.value:
                if attrs.get("enabled"):
                    entry_points.add(node_id)

            elif t == ResourceType.EKS_CLUSTER.value:
                if attrs.get("endpoint_public_access"):
                    entry_points.add(node_id)

            elif t == ResourceType.ECS_SERVICE.value:
                if attrs.get("assign_public_ip"):
                    entry_points.add(node_id)

        # Resources attached to internet-exposed security groups
        for sg_arn in self.graph.successors(INTERNET_NODE_ID):
            for resource_arn in self.graph.predecessors(sg_arn):
                attrs = self.graph.nodes.get(resource_arn, {})
                if attrs.get("type") in _INTERNET_FACING_TYPES:
                    entry_points.add(resource_arn)

        return entry_points

    def _find_sinks(self) -> set[str]:
        """
        High-value targets: data stores, secrets, crypto keys, and custom
        roles with dangerous access. Excludes AWS service-linked and
        AWS-managed roles which inflate sink count without real attack value.
        """
        sinks: set[str] = set()
        for node_id, attrs in self.graph.nodes(data=True):
            t = attrs.get("type", "")

            if t == ResourceType.RDS_INSTANCE.value:
                sinks.add(node_id)

            elif t == ResourceType.S3_BUCKET.value:
                sinks.add(node_id)

            elif t == ResourceType.IAM_ROLE.value:
                if attrs.get("has_wildcard_resource_access"):
                    if not _is_service_linked_or_aws_managed(node_id, attrs):
                        sinks.add(node_id)

            elif t == ResourceType.SECRETS_MANAGER_SECRET.value:
                sinks.add(node_id)

            elif t == ResourceType.DYNAMODB_TABLE.value:
                sinks.add(node_id)

            elif t == ResourceType.KMS_KEY.value:
                sinks.add(node_id)

            elif t == ResourceType.SSM_PARAMETER.value:
                sinks.add(node_id)

        return sinks

    # ──────────────────────────── Writers ─────────────────────────────────

    def _write_entry_points(self, buf: StringIO, entry_points: set[str]) -> None:
        buf.write("=== ENTRY POINTS ===\n")
        if not entry_points:
            buf.write("  (none identified)\n")
        for arn in sorted(entry_points):
            buf.write(f"  {self._node_line(arn)}\n")
        buf.write("\n")

    def _write_sinks(self, buf: StringIO, sinks: set[str]) -> None:
        buf.write("=== SENSITIVE SINKS ===\n")
        if not sinks:
            buf.write("  (none identified)\n")
        for arn in sorted(sinks):
            buf.write(f"  {self._node_line(arn)}\n")
        buf.write("\n")

    def _write_attack_paths(
        self,
        buf: StringIO,
        entry_points: set[str],
        sinks: set[str],
    ) -> None:
        # Self-exposed resources: entry point AND sink (e.g., public S3 bucket)
        self_exposed = sorted(entry_points & sinks)
        if self_exposed:
            buf.write("=== SELF-EXPOSED RESOURCES (entry point = sink) ===\n")
            for node_id in self_exposed:
                buf.write(f"  {self._node_line(node_id)}\n")
            buf.write("\n")

        buf.write(f"=== ATTACK SURFACE PATHS (entry → sink, ≤{self.max_hops} hops) ===\n")

        path_count = 0
        for src in sorted(entry_points):
            for dst in sorted(sinks):
                if src == dst:
                    continue
                try:
                    paths = list(
                        nx.all_simple_paths(self.graph, src, dst, cutoff=self.max_hops)
                    )
                except nx.NetworkXError:
                    continue

                # Rank paths by risk-weighted score and take the top 3 per pair.
                # The arbitrary [:3] truncation we used before dropped real
                # attack chains when there were many low-quality candidates.
                ranked = self._rank_paths(paths)

                for path, _score, markers in ranked[:3]:
                    path_count += 1
                    node_chain = "  →  ".join(
                        self.graph.nodes[n].get("name", n) for n in path
                    )
                    marker_str = (" [" + " ".join(markers) + "]") if markers else ""
                    buf.write(f"\nPATH {path_count}{marker_str}: {node_chain}\n")
                    for i in range(len(path) - 1):
                        u, v = path[i], path[i + 1]
                        for edge_attrs in self.graph[u][v].values():
                            buf.write(f"  EDGE  {self._edge_line(u, v, edge_attrs)}\n")

        if path_count == 0:
            buf.write("  (no paths found between entry points and sinks)\n")
        buf.write("\n")

    # ───────────────────────── Path ranking ───────────────────────────────

    def _rank_paths(
        self, paths: list[list[str]]
    ) -> list[tuple[list[str], int, list[str]]]:
        """
        Score each path and return [(path, score, markers), ...] sorted by
        score descending. `markers` is a small set of headline tags
        (ADMIN, WILDCARD, CONFIRMED, WEAK) that surface what makes the
        path notable without re-parsing the edge list.

        Scoring rationale:
            +5  per behavioral edge   ← CloudTrail-confirmed; not theoretical
            +3  per admin edge        ← is_admin=True
            +2  per wildcard edge     ← is_wildcard_resource=True
            -2  per conditional edge  ← has_conditions=True (weaker exploit)
            -1  per edge (length)     ← shorter paths preferred
        """
        scored: list[tuple[list[str], int, list[str]]] = []
        for path in paths:
            score = 0
            wildcard_count = 0
            admin_count = 0
            behavioral_count = 0
            conditional_count = 0

            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                score -= 1  # path length penalty per hop
                for attrs in self.graph[u][v].values():
                    if attrs.get("is_behavioral"):
                        score += 5
                        behavioral_count += 1
                    if attrs.get("is_admin"):
                        score += 3
                        admin_count += 1
                    if attrs.get("is_wildcard_resource"):
                        score += 2
                        wildcard_count += 1
                    if attrs.get("has_conditions"):
                        score -= 2
                        conditional_count += 1

            markers: list[str] = []
            if behavioral_count:
                markers.append("CONFIRMED")
            if admin_count:
                markers.append("ADMIN")
            if wildcard_count:
                markers.append("WILDCARD")
            if conditional_count and not behavioral_count:
                # CONFIRMED behavioral edges trump the WEAK marker —
                # a path that actually happened isn't weakened by a Condition.
                markers.append("WEAK")

            scored.append((path, score, markers))

        # Stable sort by score desc, then by length asc, then by string
        # repr of path for determinism in tests.
        scored.sort(key=lambda t: (-t[1], len(t[0]), str(t[0])))
        return scored

    def _write_all_nodes(self, buf: StringIO, remaining: int | None = None) -> None:
        buf.write("=== ALL NODES ===\n")
        total = self.graph.number_of_nodes()
        written = 0
        for node_id, _attrs in sorted(self.graph.nodes(data=True)):
            line = f"  {self._node_line(node_id)}\n"
            if remaining is not None and len(line) > remaining:
                buf.write(f"  [truncated: {written} of {total} nodes shown — budget exhausted]\n")
                break
            buf.write(line)
            if remaining is not None:
                remaining -= len(line)
            written += 1
        buf.write("\n")

    def _write_all_edges(self, buf: StringIO, remaining: int | None = None) -> None:
        buf.write("=== ALL EDGES ===\n")
        total = self.graph.number_of_edges()
        written = 0
        for u, v, attrs in sorted(
            self.graph.edges(data=True),
            key=lambda e: (e[0], e[1]),
        ):
            line = f"  {self._edge_line(u, v, attrs)}\n"
            if remaining is not None and len(line) > remaining:
                buf.write(f"  [truncated: {written} of {total} edges shown — budget exhausted]\n")
                break
            buf.write(line)
            if remaining is not None:
                remaining -= len(line)
            written += 1
        buf.write("\n")

    # ──────────────────────── Line Formatters ─────────────────────────────

    def _node_line(self, node_id: str) -> str:
        """
        NODE <arn-or-id> [TYPE] key=val key=val ...
        Only the most security-relevant scalar attributes are included.
        """
        attrs = self.graph.nodes.get(node_id, {})
        t = attrs.get("type", "unknown")
        name = attrs.get("name", node_id)

        parts: list[str] = []

        # Type-specific important fields
        if t == ResourceType.EC2_INSTANCE.value:
            _kv(parts, "public_ip", attrs.get("public_ip"))
            _kv(parts, "imds_v1", attrs.get("imds_v1_allowed"))
            _kv(parts, "profile", attrs.get("iam_instance_profile_arn"))

        elif t == ResourceType.LAMBDA_FUNCTION.value:
            _kv(parts, "runtime", attrs.get("runtime"))
            _kv(parts, "role", attrs.get("role_arn"))
            _kv(parts, "in_vpc", attrs.get("in_vpc"))
            _kv(parts, "env_var_count", attrs.get("env_var_count"))

        elif t == ResourceType.IAM_ROLE.value:
            _kv(parts, "wildcard_access", attrs.get("has_wildcard_resource_access"))

        elif t == ResourceType.S3_BUCKET.value:
            resource = self.arn_index.get(node_id)
            if resource:
                _kv(parts, "public", _s3_is_public(resource))
                _kv(parts, "encrypted", resource.properties.get("is_encrypted"))
                _kv(parts, "has_policy", resource.properties.get("has_bucket_policy"))

        elif t == ResourceType.RDS_INSTANCE.value:
            _kv(parts, "engine", attrs.get("engine"))
            _kv(parts, "public", attrs.get("publicly_accessible"))
            _kv(parts, "encrypted", attrs.get("storage_encrypted"))
            _kv(parts, "iam_auth", attrs.get("iam_database_auth_enabled"))

        elif t == ResourceType.SECURITY_GROUP.value:
            _kv(parts, "internet_exposed", attrs.get("internet_exposed"))
            _kv(parts, "vpc", attrs.get("vpc_id"))

        elif t == ResourceType.ALB.value:
            _kv(parts, "internet_facing", attrs.get("is_internet_facing"))
            _kv(parts, "dns", attrs.get("dns_name"))

        elif t == ResourceType.API_GATEWAY_REST_API.value:
            _kv(parts, "private", attrs.get("is_private"))
            _kv(parts, "has_authorizers", attrs.get("has_authorizers"))
            _kv(parts, "has_waf", attrs.get("has_waf"))

        elif t == ResourceType.API_GATEWAY_HTTP_API.value:
            _kv(parts, "endpoint", attrs.get("endpoint"))
            _kv(parts, "has_authorizer", attrs.get("has_authorizer"))
            _kv(parts, "cors_allows_all", attrs.get("cors_allows_all_origins"))

        elif t == ResourceType.CLOUDFRONT_DISTRIBUTION.value:
            _kv(parts, "domain", attrs.get("domain_name"))
            _kv(parts, "enabled", attrs.get("enabled"))
            _kv(parts, "has_waf", attrs.get("has_waf"))
            _kv(parts, "https_only", attrs.get("https_only"))

        elif t == ResourceType.EKS_CLUSTER.value:
            _kv(parts, "public_endpoint", attrs.get("endpoint_public_access"))
            _kv(parts, "public_cidrs", attrs.get("public_access_cidrs"))
            _kv(parts, "version", attrs.get("kubernetes_version"))

        elif t == ResourceType.ECS_SERVICE.value:
            _kv(parts, "public_ip", attrs.get("assign_public_ip"))
            _kv(parts, "launch_type", attrs.get("launch_type"))

        elif t == ResourceType.SECRETS_MANAGER_SECRET.value:
            _kv(parts, "name", attrs.get("name"))

        elif t == ResourceType.DYNAMODB_TABLE.value:
            _kv(parts, "name", attrs.get("name"))

        elif t == ResourceType.KMS_KEY.value:
            _kv(parts, "name", attrs.get("name"))

        elif t == ResourceType.SSM_PARAMETER.value:
            _kv(parts, "name", attrs.get("name"))

        kv_str = " ".join(parts)
        label = f"[{t}]"
        return f"NODE {name!r} {label} {kv_str}".strip()

    def _edge_line(self, u: str, v: str, attrs: dict) -> str:
        """  <src_name> --[edge_type attrs]--> <dst_name>"""
        src_name = self.graph.nodes.get(u, {}).get("name", u)
        dst_name = self.graph.nodes.get(v, {}).get("name", v)
        edge_type = attrs.get("edge_type", attrs.get("label", "?"))
        if isinstance(edge_type, EdgeType):
            edge_type = edge_type.value

        extra_parts: list[str] = []
        if attrs.get("from_port") is not None:
            extra_parts.append(f"port={attrs['from_port']}-{attrs['to_port']}")
        if attrs.get("protocol") and attrs["protocol"] != "-1":
            extra_parts.append(f"proto={attrs['protocol']}")
        if attrs.get("actions"):
            actions_str = ",".join(attrs["actions"][:3])
            if len(attrs["actions"]) > 3:
                actions_str += "..."
            extra_parts.append(f"actions=[{actions_str}]")
        if attrs.get("is_wildcard_resource"):
            extra_parts.append("wildcard_resource=true")
        if attrs.get("is_admin"):
            extra_parts.append("ADMIN")
        if attrs.get("has_conditions"):
            extra_parts.append("has_conditions")

        edge_label = edge_type
        if extra_parts:
            edge_label += " " + " ".join(extra_parts)

        return f"{src_name!r} --[{edge_label}]--> {dst_name!r}"


# ─────────────────────────── Module helpers ───────────────────────────────


def _remaining(max_chars: int | None, buf: StringIO) -> int | None:
    """Chars left in the buffer's budget. None = unlimited (no truncation)."""
    if max_chars is None:
        return None
    return max(0, max_chars - len(buf.getvalue()))


def _kv(parts: list[str], key: str, value: object) -> None:
    """Append key=value to parts only when value is not None/False/empty."""
    if value is None:
        return
    if isinstance(value, bool):
        if value:
            parts.append(f"{key}=true")
        # False values omitted — reduces noise
        return
    parts.append(f"{key}={value}")


def _s3_is_public(resource: Resource) -> bool:
    """True if the S3 bucket does NOT have a full public access block."""
    pab = resource.properties.get("public_access_block", {}) or {}
    return not all([
        pab.get("block_public_acls"),
        pab.get("ignore_public_acls"),
        pab.get("block_public_policy"),
        pab.get("restrict_public_buckets"),
    ])


_SERVICE_LINKED_PATTERNS = (
    "/aws-service-role/",
    "AWSServiceRole",
)

_AWS_MANAGED_ROLE_PREFIXES = (
    "AWS-QuickSetup-",
    "AWS-SSM-",
    "AWSBackup",
    "AWSCodePipeline",
    "AWSGlue",
    "AWSReservedSSO_",
    "AmazonBedrock",
    "AmazonEKSAuto",
    "AmazonEKSPodIdentity",
    "AmazonEKS_",
    "AmazonQ",
    "AmazonSSM",
    "APIGatewayCloudWatchLogsRole",
)


def _is_service_linked_or_aws_managed(node_id: str, attrs: dict) -> bool:
    """
    Returns True for AWS service-linked roles and AWS-managed service roles
    that are not realistic attack targets (attacker can't assume them directly).
    """
    role_name = attrs.get("role_name", "") or ""
    for pattern in _SERVICE_LINKED_PATTERNS:
        if pattern in node_id or pattern in role_name:
            return True
    for prefix in _AWS_MANAGED_ROLE_PREFIXES:
        if role_name.startswith(prefix):
            return True
    return False
