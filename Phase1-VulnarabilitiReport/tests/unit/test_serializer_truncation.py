"""
Tests for GraphSerializer's two serialization modes:
  - serialize()         → full graph (all nodes + edges)
  - serialize_for_llm() → attack-focused (path-relevant only)
"""
from __future__ import annotations

import networkx as nx

from breakbot.graph.edges import INTERNET_NODE_ID, EdgeType
from breakbot.graph.serializer import GraphSerializer
from breakbot.models import ResourceType


def _populate_graph(node_count: int) -> nx.MultiDiGraph:
    """Build a graph with `node_count` nodes and ~node_count edges."""
    g = nx.MultiDiGraph()
    g.add_node(INTERNET_NODE_ID, type="virtual", name=INTERNET_NODE_ID)
    for i in range(node_count):
        g.add_node(f"arn-{i}", type="test", name=f"node-{i}")
    for i in range(node_count - 1):
        g.add_edge(
            f"arn-{i}", f"arn-{i+1}",
            edge_type=EdgeType.IAM_CAN_ACCESS,
            actions=["test:Action"],
        )
    return g


def test_full_serialize_renders_all_nodes():
    g = _populate_graph(50)
    s = GraphSerializer(graph=g, arn_index={}).serialize()
    assert "=== ALL NODES ===" in s
    assert "=== ALL EDGES ===" in s
    assert "node-49" in s


def test_llm_serialize_omits_all_nodes_section():
    g = _populate_graph(50)
    s = GraphSerializer(graph=g, arn_index={}).serialize_for_llm()
    assert "=== ALL NODES ===" not in s
    assert "=== ALL EDGES ===" not in s
    assert "=== ENTRY POINTS ===" in s
    assert "=== SENSITIVE SINKS ===" in s


def test_llm_serialize_includes_path_relevant_nodes():
    g = nx.MultiDiGraph()
    g.add_node(INTERNET_NODE_ID, type="virtual", name=INTERNET_NODE_ID)
    # Entry point: public EC2
    g.add_node("arn:ec2:i-1", type=ResourceType.EC2_INSTANCE.value,
               name="bastion", is_public=True)
    # Middle node: IAM role
    g.add_node("arn:iam:role/admin", type=ResourceType.IAM_ROLE.value,
               name="admin-role", has_wildcard_resource_access=True, role_name="admin")
    # Sink: secret
    g.add_node("arn:secretsmanager:secret/db-pass",
               type=ResourceType.SECRETS_MANAGER_SECRET.value, name="db-pass")
    # Unrelated node (should NOT appear in LLM output)
    g.add_node("arn:ec2:subnet-1", type="subnet", name="subnet-1")

    # Internet exposes bastion
    g.add_edge(INTERNET_NODE_ID, "arn:ec2:i-1",
               edge_type=EdgeType.INTERNET_EXPOSES)
    # bastion → role
    g.add_edge("arn:ec2:i-1", "arn:iam:role/admin",
               edge_type=EdgeType.IAM_CAN_ACCESS, actions=["sts:AssumeRole"])
    # role → secret
    g.add_edge("arn:iam:role/admin", "arn:secretsmanager:secret/db-pass",
               edge_type=EdgeType.IAM_CAN_ACCESS, actions=["secretsmanager:GetSecretValue"])

    s = GraphSerializer(graph=g, arn_index={}).serialize_for_llm()
    assert "bastion" in s
    assert "admin-role" in s
    assert "db-pass" in s
    assert "subnet-1" not in s
    assert "PATH-RELEVANT" in s


def test_llm_serialize_includes_behavioral_edges():
    g = nx.MultiDiGraph()
    g.add_node(INTERNET_NODE_ID, type="virtual", name=INTERNET_NODE_ID)
    g.add_node("arn:iam:role/svc", type=ResourceType.IAM_ROLE.value,
               name="svc-role", role_name="svc")
    g.add_node("arn:kms:key/k1", type=ResourceType.KMS_KEY.value, name="my-key")
    g.add_edge("arn:iam:role/svc", "arn:kms:key/k1",
               edge_type=EdgeType.ACTUALLY_ACCESSED, is_behavioral=True)

    s = GraphSerializer(graph=g, arn_index={}).serialize_for_llm()
    assert "BEHAVIORAL EVIDENCE" in s
    assert "actually_accessed" in s


def test_llm_serialize_smaller_than_full():
    g = _populate_graph(200)
    full = GraphSerializer(graph=g, arn_index={}).serialize()
    llm = GraphSerializer(graph=g, arn_index={}).serialize_for_llm()
    assert len(llm) < len(full)
