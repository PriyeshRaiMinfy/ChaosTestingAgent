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
}

# Resource types that hold sensitive data (sinks for attack path analysis).
_SINK_TYPES = {
    ResourceType.RDS_INSTANCE.value,
    ResourceType.S3_BUCKET.value,
    ResourceType.IAM_ROLE.value,
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

    def serialize(self) -> str:
        """Return the full LLM-ready text representation."""
        buf = StringIO()

        entry_points = self._find_entry_points()
        sinks = self._find_sinks()

        self._write_entry_points(buf, entry_points)
        self._write_sinks(buf, sinks)
        self._write_attack_paths(buf, entry_points, sinks)
        self._write_all_nodes(buf)
        self._write_all_edges(buf)

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
        Internet-facing resources. Three sources:
          1. ALBs with internet-facing scheme
          2. EC2 instances with a public IP
          3. S3 buckets without a full public access block
          4. Any resource with an INTERNET_EXPOSES edge pointing at its SG,
             which in turn is attached to compute resources
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

        # Resources attached to internet-exposed security groups
        for sg_arn in self.graph.successors(INTERNET_NODE_ID):
            for resource_arn in self.graph.predecessors(sg_arn):
                attrs = self.graph.nodes.get(resource_arn, {})
                if attrs.get("type") in _INTERNET_FACING_TYPES:
                    entry_points.add(resource_arn)

        return entry_points

    def _find_sinks(self) -> set[str]:
        """
        High-value targets: databases, S3, and admin IAM roles.
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

                for path in paths[:3]:  # cap at 3 paths per (src, dst) pair
                    path_count += 1
                    node_chain = "  →  ".join(
                        self.graph.nodes[n].get("name", n) for n in path
                    )
                    buf.write(f"\nPATH {path_count}: {node_chain}\n")
                    for i in range(len(path) - 1):
                        u, v = path[i], path[i + 1]
                        for edge_attrs in self.graph[u][v].values():
                            buf.write(f"  EDGE  {self._edge_line(u, v, edge_attrs)}\n")

        if path_count == 0:
            buf.write("  (no paths found between entry points and sinks)\n")
        buf.write("\n")

    def _write_all_nodes(self, buf: StringIO) -> None:
        buf.write("=== ALL NODES ===\n")
        for node_id, attrs in sorted(self.graph.nodes(data=True)):
            buf.write(f"  {self._node_line(node_id)}\n")
        buf.write("\n")

    def _write_all_edges(self, buf: StringIO) -> None:
        buf.write("=== ALL EDGES ===\n")
        for u, v, attrs in sorted(
            self.graph.edges(data=True),
            key=lambda e: (e[0], e[1]),
        ):
            buf.write(f"  {self._edge_line(u, v, attrs)}\n")
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
