"""
TrailOverlay — applies CloudTrail behavioral events as edges on the static graph.

Behavioral edges:
  actually_assumed   Actor → IAM Role   (sts:AssumeRole was called)
  actually_accessed  Actor → Resource   (GetSecretValue / Decrypt / GetParameter called)

Difference from static edges:
  Static edges = what CAN happen (config-derived: trust policies, SG rules, IAM policies)
  Behavioral edges = what DID happen (CloudTrail-derived: actual API calls in the last 90 days)

An attack path that has both a static edge AND a behavioral edge on the same arc
is a confirmed active path — highest-priority finding for the LLM analyst.

Nodes not in the graph (e.g. calls from external accounts or services not scanned)
get stub nodes so the path is visible without breaking the graph structure.
"""
from __future__ import annotations

import logging

import networkx as nx

from breakbot.graph.edges import EdgeType
from breakbot.models import ResourceType
from breakbot.scanner.cloudtrail import TrailEvent

logger = logging.getLogger(__name__)

_EVENT_TO_EDGE: dict[str, EdgeType] = {
    "AssumeRole":                        EdgeType.ACTUALLY_ASSUMED,
    "GetSecretValue":                    EdgeType.ACTUALLY_ACCESSED,
    "Decrypt":                           EdgeType.ACTUALLY_ACCESSED,
    "GenerateDataKey":                   EdgeType.ACTUALLY_ACCESSED,
    "GenerateDataKeyWithoutPlaintext":   EdgeType.ACTUALLY_ACCESSED,
    "GetParameter":                      EdgeType.ACTUALLY_ACCESSED,
    "GetParameters":                     EdgeType.ACTUALLY_ACCESSED,
}


class TrailOverlay:
    """
    Usage:
        overlay = TrailOverlay()
        edges_added = overlay.apply(graph, arn_index, trail_events)
    """

    def apply(
        self,
        graph: nx.MultiDiGraph,
        arn_index: dict,
        events: list[TrailEvent],
    ) -> int:
        """
        Add behavioral edges to graph. Returns the count of unique edges added.
        Deduplicates: one edge per (actor, target, edge_type) pair regardless of
        how many times the same call appeared in the 90-day window.
        """
        edges_added = 0
        seen: set[tuple[str, str, str]] = set()

        for event in events:
            edge_type = _EVENT_TO_EDGE.get(event.event_name)
            if not edge_type or not event.target_arn:
                continue

            key = (event.actor_arn, event.target_arn, edge_type.value)
            if key in seen:
                continue
            seen.add(key)

            # Ensure actor node exists
            if event.actor_arn not in graph:
                graph.add_node(
                    event.actor_arn,
                    type=_infer_type(event.actor_arn),
                    name=event.actor_arn,
                    is_external=True,
                )

            # Ensure target node exists
            if event.target_arn not in graph:
                graph.add_node(
                    event.target_arn,
                    type="unknown",
                    name=event.target_arn,
                    is_external=True,
                )

            graph.add_edge(
                event.actor_arn,
                event.target_arn,
                edge_type=edge_type,
                label=edge_type.value,
                event_name=event.event_name,
                is_behavioral=True,  # flag so serializer can highlight these
            )
            edges_added += 1

        logger.info(
            "TrailOverlay: %d unique behavioral edges from %d events",
            edges_added,
            len(events),
        )
        return edges_added


def _infer_type(arn: str) -> str:
    if ":role/" in arn:
        return ResourceType.IAM_ROLE.value
    if ":user/" in arn:
        return ResourceType.IAM_USER.value
    return "external_principal"
