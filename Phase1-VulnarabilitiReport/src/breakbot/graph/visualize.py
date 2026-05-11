"""
HTML graph visualization using pyvis.

Requires the `viz` extras: pip install breakbot[viz]

Color scheme (security-centric):
  Red         INTERNET virtual node + internet-exposed SGs
  Orange      Compute (EC2, Lambda)
  Yellow      Data stores (S3, RDS)
  Teal/Green  Identity (IAM Role, IAM User)
  Blue        Networking (VPC, SG, ALB)
  Grey        Unknown / external principals
"""
from __future__ import annotations

import logging
from pathlib import Path

import networkx as nx

from breakbot.models import ResourceType

logger = logging.getLogger(__name__)

_TYPE_COLOR: dict[str, str] = {
    "virtual": "#E63946",                     # INTERNET — red
    ResourceType.EC2_INSTANCE.value: "#F4A261",
    ResourceType.LAMBDA_FUNCTION.value: "#E9C46A",
    ResourceType.S3_BUCKET.value: "#FFD166",
    ResourceType.RDS_INSTANCE.value: "#F4A261",
    ResourceType.IAM_ROLE.value: "#06D6A0",
    ResourceType.IAM_USER.value: "#06D6A0",
    ResourceType.IAM_POLICY.value: "#06D6A0",
    ResourceType.SECURITY_GROUP.value: "#118AB2",
    ResourceType.VPC.value: "#118AB2",
    ResourceType.SUBNET.value: "#118AB2",
    ResourceType.ALB.value: "#073B4C",
    "external_principal": "#ADB5BD",
    "unknown": "#ADB5BD",
}

_EDGE_COLOR: dict[str, str] = {
    "iam_can_assume": "#06D6A0",
    "iam_can_access": "#2EC4B6",
    "has_execution_role": "#CBF3F0",
    "has_instance_profile": "#CBF3F0",
    "network_can_reach": "#118AB2",
    "internet_exposes": "#E63946",
    "attached_to_sg": "#457B9D",
    "in_vpc": "#A8DADC",
}


def render_html(graph: nx.MultiDiGraph, output_path: Path) -> None:
    """
    Render the dependency graph as a standalone interactive HTML file.

    Raises ImportError if pyvis is not installed.
    """
    try:
        from pyvis.network import Network
    except ImportError as exc:
        raise ImportError(
            "pyvis is required for visualization. Install it with:\n"
            "  pip install breakbot[viz]"
        ) from exc

    net = Network(
        height="900px",
        width="100%",
        directed=True,
        bgcolor="#1A1A2E",
        font_color="#EAEAEA",
    )
    net.set_options("""
    {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -80,
          "centralGravity": 0.01,
          "springLength": 120
        },
        "solver": "forceAtlas2Based",
        "stabilization": {"iterations": 150}
      },
      "interaction": {"hover": true, "navigationButtons": true},
      "edges": {"smooth": {"type": "curvedCW", "roundness": 0.2}}
    }
    """)

    for node_id, attrs in graph.nodes(data=True):
        node_type = attrs.get("type", "unknown")
        color = _TYPE_COLOR.get(node_type, "#ADB5BD")

        # Larger nodes for high-value targets
        size = 20
        if node_id == "INTERNET":
            size = 35
        elif node_type in (ResourceType.RDS_INSTANCE.value, ResourceType.S3_BUCKET.value):
            size = 28
        elif node_type == ResourceType.IAM_ROLE.value and attrs.get("has_wildcard_resource_access"):
            size = 30
            color = "#E63946"  # Flag admin roles in red

        label = attrs.get("name", str(node_id))
        # Truncate long ARNs for readability
        if label.startswith("arn:") and len(label) > 50:
            label = "…" + label[-40:]

        tooltip = _build_tooltip(node_id, attrs)
        net.add_node(str(node_id), label=label, color=color, size=size, title=tooltip)

    for u, v, attrs in graph.edges(data=True):
        edge_type = attrs.get("edge_type", "")
        if hasattr(edge_type, "value"):
            edge_type = edge_type.value

        color = _EDGE_COLOR.get(str(edge_type), "#888888")
        width = 3 if edge_type in ("internet_exposes", "iam_can_access") else 1
        edge_label = str(edge_type).replace("_", " ")

        net.add_edge(
            str(u),
            str(v),
            label=edge_label,
            color=color,
            width=width,
            arrows="to",
            title=_build_edge_tooltip(attrs),
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(output_path))
    logger.info("Graph visualization written to %s", output_path)


def _build_tooltip(node_id: str, attrs: dict) -> str:
    lines = [f"<b>{node_id}</b>", f"type: {attrs.get('type', '?')}"]
    for key in ("region", "account_id", "engine", "runtime", "is_public",
                "publicly_accessible", "is_internet_facing", "internet_exposed",
                "imds_v1_allowed", "has_wildcard_resource_access", "storage_encrypted"):
        if key in attrs and attrs[key] is not None:
            lines.append(f"{key}: {attrs[key]}")
    return "<br>".join(lines)


def _build_edge_tooltip(attrs: dict) -> str:
    lines = []
    for key in ("edge_type", "actions", "resource_pattern", "policy_name",
                "from_port", "to_port", "protocol", "is_admin",
                "is_wildcard_resource", "has_conditions"):
        if key in attrs and attrs[key] is not None:
            lines.append(f"{key}: {attrs[key]}")
    return "<br>".join(lines) if lines else ""
