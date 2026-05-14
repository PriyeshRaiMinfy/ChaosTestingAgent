"""
Tests for GraphSerializer's optional max_chars truncation budget.

The budget exists for very large accounts (thousands of resources) where the
serialized attack surface would exceed Claude's context window. ENTRY POINTS,
SENSITIVE SINKS, and ATTACK SURFACE PATHS must always render in full — they
are the high-signal sections. ALL NODES and ALL EDGES truncate first.
"""
from __future__ import annotations

import networkx as nx

from breakbot.graph.edges import INTERNET_NODE_ID, EdgeType
from breakbot.graph.serializer import GraphSerializer


def _populate_graph(node_count: int) -> nx.MultiDiGraph:
    """Build a graph with `node_count` nodes and ~node_count edges.

    Always includes the virtual INTERNET node so the serializer's
    entry-point detection works.
    """
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


def test_no_budget_renders_everything():
    g = _populate_graph(50)
    s = GraphSerializer(graph=g, arn_index={}).serialize()
    # All 50 nodes rendered in ALL NODES section
    assert s.count("\n  NODE") + s.count("\n  'node-") >= 50 or "node-49" in s
    assert "truncated" not in s


def test_budget_preserves_entry_and_sink_sections_even_when_tiny():
    g = _populate_graph(50)
    # Absurdly tight budget — only entry/sink/path sections should be rendered
    # ALL NODES / ALL EDGES sections should truncate to nothing
    out = GraphSerializer(graph=g, arn_index={}).serialize(max_chars=200)
    assert "=== ENTRY POINTS ===" in out
    assert "=== SENSITIVE SINKS ===" in out
    assert "=== ATTACK SURFACE PATHS" in out


def test_budget_marks_truncation_when_nodes_exceed():
    g = _populate_graph(500)
    out = GraphSerializer(graph=g, arn_index={}).serialize(max_chars=2000)
    # Truncation marker present in at least one of the unbounded sections
    assert "truncated" in out


def test_budget_marker_includes_counts():
    g = _populate_graph(500)
    out = GraphSerializer(graph=g, arn_index={}).serialize(max_chars=2000)
    # The marker should report "M of N" so the LLM knows the proportion
    assert " of 500" in out or " of 499" in out  # 500 nodes, 499 edges


def test_budget_does_not_truncate_small_graphs():
    """A graph that fits easily should produce identical output to no-budget."""
    g = _populate_graph(5)
    no_budget = GraphSerializer(graph=g, arn_index={}).serialize()
    with_budget = GraphSerializer(graph=g, arn_index={}).serialize(max_chars=100_000)
    assert no_budget == with_budget
