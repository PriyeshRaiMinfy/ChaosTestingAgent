"""
Tests for GraphSerializer._rank_paths — the new risk-weighted ranker.

The serializer used to truncate at the first 3 paths per (src, dst), which
dropped real attack chains in favor of arbitrarily-ordered ones. The new
ranker scores paths by:
  +5 per behavioral (CloudTrail-confirmed) edge  ← CONFIRMED marker
  +3 per admin edge                              ← ADMIN marker
  +2 per wildcard-resource edge                  ← WILDCARD marker
  -2 per conditional edge                        ← WEAK marker (unless CONFIRMED)
  -1 per hop (path length penalty)
"""
from __future__ import annotations

import networkx as nx

from breakbot.graph.edges import EdgeType
from breakbot.graph.serializer import GraphSerializer


def _serializer_with(graph: nx.MultiDiGraph) -> GraphSerializer:
    return GraphSerializer(graph=graph, arn_index={}, max_hops=5)


def _add_node(g: nx.MultiDiGraph, name: str, type_: str = "test") -> None:
    g.add_node(name, type=type_, name=name)


def _add_edge(g: nx.MultiDiGraph, u: str, v: str, **attrs) -> None:
    attrs.setdefault("edge_type", EdgeType.IAM_CAN_ACCESS)
    g.add_edge(u, v, **attrs)


# ─────────────────────────── Score arithmetic ─────────────────────────────

def test_shorter_path_wins_when_other_factors_equal():
    g = nx.MultiDiGraph()
    for n in ["A", "B", "C", "D"]:
        _add_node(g, n)
    # path 1: A -> D (1 hop)
    _add_edge(g, "A", "D")
    # path 2: A -> B -> C -> D (3 hops)
    _add_edge(g, "A", "B")
    _add_edge(g, "B", "C")
    _add_edge(g, "C", "D")

    s = _serializer_with(g)
    ranked = s._rank_paths([["A", "D"], ["A", "B", "C", "D"]])

    assert ranked[0][0] == ["A", "D"]


def test_behavioral_edge_beats_theoretical_path():
    g = nx.MultiDiGraph()
    for n in ["A", "B", "C", "D"]:
        _add_node(g, n)
    # Confirmed path: A -> D (behavioral)
    _add_edge(g, "A", "D", is_behavioral=True)
    # Theoretical wildcard path: A -> B -> C -> D
    _add_edge(g, "A", "B", is_wildcard_resource=True)
    _add_edge(g, "B", "C")
    _add_edge(g, "C", "D", is_wildcard_resource=True)

    s = _serializer_with(g)
    ranked = s._rank_paths([["A", "D"], ["A", "B", "C", "D"]])

    # CONFIRMED 5 - 1 = 4 vs. WILDCARD WILDCARD 2+2 - 3 = 1
    assert ranked[0][0] == ["A", "D"]
    assert "CONFIRMED" in ranked[0][2]


def test_admin_marker_set_when_admin_edge_present():
    g = nx.MultiDiGraph()
    for n in ["A", "B"]:
        _add_node(g, n)
    _add_edge(g, "A", "B", is_admin=True)

    s = _serializer_with(g)
    ranked = s._rank_paths([["A", "B"]])

    assert "ADMIN" in ranked[0][2]


def test_wildcard_marker_set_when_wildcard_edge_present():
    g = nx.MultiDiGraph()
    for n in ["A", "B"]:
        _add_node(g, n)
    _add_edge(g, "A", "B", is_wildcard_resource=True)

    s = _serializer_with(g)
    ranked = s._rank_paths([["A", "B"]])

    assert "WILDCARD" in ranked[0][2]


def test_weak_marker_set_when_path_has_conditional_edge():
    g = nx.MultiDiGraph()
    for n in ["A", "B"]:
        _add_node(g, n)
    _add_edge(g, "A", "B", has_conditions=True)

    s = _serializer_with(g)
    ranked = s._rank_paths([["A", "B"]])

    assert "WEAK" in ranked[0][2]


def test_confirmed_suppresses_weak_marker():
    """If a path is CloudTrail-confirmed, the WEAK marker is misleading."""
    g = nx.MultiDiGraph()
    for n in ["A", "B"]:
        _add_node(g, n)
    _add_edge(g, "A", "B", is_behavioral=True, has_conditions=True)

    s = _serializer_with(g)
    ranked = s._rank_paths([["A", "B"]])

    assert "CONFIRMED" in ranked[0][2]
    assert "WEAK" not in ranked[0][2]


def test_admin_wildcard_path_outranks_long_clean_path():
    g = nx.MultiDiGraph()
    for n in ["A", "B", "C", "D", "E"]:
        _add_node(g, n)
    # Short admin + wildcard path: A -> B (2 hops worth of score)
    _add_edge(g, "A", "B", is_admin=True, is_wildcard_resource=True)
    # Long clean path: A -> C -> D -> E -> B
    _add_edge(g, "A", "C")
    _add_edge(g, "C", "D")
    _add_edge(g, "D", "E")
    _add_edge(g, "E", "B")

    s = _serializer_with(g)
    ranked = s._rank_paths([["A", "B"], ["A", "C", "D", "E", "B"]])

    assert ranked[0][0] == ["A", "B"]
    assert {"ADMIN", "WILDCARD"} <= set(ranked[0][2])
