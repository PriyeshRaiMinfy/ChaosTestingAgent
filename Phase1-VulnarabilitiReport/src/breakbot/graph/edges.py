"""
Edge type definitions for the BreakBot dependency graph.

Every edge in the graph has an `edge_type` attribute set to one of these values.
The LLM serializer uses these labels to reason about what traversal means.
"""
from __future__ import annotations

from enum import Enum


class EdgeType(str, Enum):
    # IAM / identity edges
    IAM_CAN_ASSUME = "iam_can_assume"
    IAM_CAN_ACCESS = "iam_can_access"
    HAS_EXECUTION_ROLE = "has_execution_role"
    HAS_INSTANCE_PROFILE = "has_instance_profile"

    # Network edges
    NETWORK_CAN_REACH = "network_can_reach"
    INTERNET_EXPOSES = "internet_exposes"
    ATTACHED_TO_SG = "attached_to_sg"

    # Structural / membership edges
    IN_VPC = "in_vpc"
    HAS_NODE_GROUP = "has_node_group"              # EKS cluster → managed node group
    HAS_FARGATE_PROFILE = "has_fargate_profile"    # EKS cluster → Fargate profile
    HAS_TARGET_GROUP = "has_target_group"          # ALB/NLB → target group
    ROUTES_TO = "routes_to"                        # EventBridge rule → target resource

    # Security posture edges
    PROTECTED_BY_WAF = "protected_by_waf"          # CloudFront/API GW → WAF web ACL

    # Encryption edges
    ENCRYPTED_BY = "encrypted_by"  # resource → KMS key


# Synthetic node IDs — not real AWS ARNs, but useful anchors in the graph.
INTERNET_NODE_ID = "INTERNET"
