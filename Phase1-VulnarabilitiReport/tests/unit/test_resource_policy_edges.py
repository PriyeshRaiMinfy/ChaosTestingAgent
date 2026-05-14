"""
Tests for resource-based policy edges (resource_policy_grants).

The graph builder previously only handled identity-based IAM policies
(role's policy → resource). This file covers the new path:

  Resource's policy → Principal (named in the policy's Statement)

Edge direction is Principal → Resource so attack-path BFS reaches the
resource through any granted principal, same as iam_can_access.
"""
from __future__ import annotations

from datetime import datetime

from breakbot.graph.builder import GraphBuilder
from breakbot.graph.edges import EdgeType
from breakbot.models import Resource, ResourceType, ScanResult

ACCOUNT = "111122223333"


def _scan(*resources: Resource) -> ScanResult:
    return ScanResult(
        scan_id="t",
        scanner_account_id=ACCOUNT,
        accounts_scanned=[ACCOUNT],
        started_at=datetime(2025, 1, 1),
        completed_at=datetime(2025, 1, 1),
        regions_scanned=["us-east-1"],
        resources=list(resources),
    )


def _bucket(name: str, policy: dict | None) -> Resource:
    return Resource(
        arn=f"arn:aws:s3:::{name}",
        resource_type=ResourceType.S3_BUCKET,
        name=name,
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"bucket_name": name, "bucket_policy": policy},
    )


def _role(name: str) -> Resource:
    return Resource(
        arn=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        resource_type=ResourceType.IAM_ROLE,
        name=name,
        region="global",
        account_id=ACCOUNT,
        properties={"role_name": name, "trust_policy": {}},
    )


def _kms_key(key_id: str, policy: dict | None) -> Resource:
    arn = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{key_id}"
    return Resource(
        arn=arn,
        resource_type=ResourceType.KMS_KEY,
        name=key_id,
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"key_id": key_id, "key_policy": policy},
    )


def _resource_policy_edges(g):
    return [
        (u, v, d) for u, v, d in g.edges(data=True)
        if d.get("edge_type") == EdgeType.RESOURCE_POLICY_GRANTS
    ]


# ──────────────────────────── S3 bucket policy ────────────────────────────

def test_s3_bucket_policy_grants_specific_role_in_account():
    role = _role("PartnerAuditor")
    bucket_arn = "arn:aws:s3:::customer-data"
    bucket = _bucket("customer-data", policy={
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": role.arn},
            "Action": ["s3:GetObject"],
            "Resource": [f"{bucket_arn}/*"],
        }],
    })
    g = GraphBuilder(_scan(role, bucket)).build()
    edges = _resource_policy_edges(g)
    assert len(edges) == 1
    u, v, d = edges[0]
    assert u == role.arn
    assert v == bucket.arn
    assert "s3:GetObject" in d["actions"]
    assert d["has_conditions"] is False
    assert d["is_wildcard_resource"] is False


def test_s3_bucket_policy_with_wildcard_principal_is_skipped():
    """Public S3 policy is a posture finding, not a graph edge."""
    bucket = _bucket("public-bucket", policy={
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "*",
        }],
    })
    g = GraphBuilder(_scan(bucket)).build()
    edges = _resource_policy_edges(g)
    assert len(edges) == 0


def test_s3_bucket_policy_service_principal_is_skipped():
    """Service principals (cloudfront.amazonaws.com) aren't attack-chain principals."""
    bucket = _bucket("served", policy={
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": "*",
        }],
    })
    g = GraphBuilder(_scan(bucket)).build()
    assert len(_resource_policy_edges(g)) == 0


def test_s3_bucket_policy_deny_statement_is_skipped():
    """Deny statements don't grant anything; no edge."""
    role = _role("Auditor")
    bucket = _bucket("restricted", policy={
        "Statement": [{
            "Effect": "Deny",
            "Principal": {"AWS": role.arn},
            "Action": "s3:DeleteObject",
            "Resource": "*",
        }],
    })
    g = GraphBuilder(_scan(role, bucket)).build()
    assert len(_resource_policy_edges(g)) == 0


def test_s3_bucket_policy_cross_account_creates_external_stub():
    """Cross-account principal we don't scan becomes an external stub."""
    bucket = _bucket("shared", policy={
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999988887777:role/ExternalAuditor"},
            "Action": "s3:GetObject",
            "Resource": "*",
        }],
    })
    g = GraphBuilder(_scan(bucket)).build()
    edges = _resource_policy_edges(g)
    assert len(edges) == 1
    u, _, _ = edges[0]
    assert g.nodes[u].get("is_external") is True


def test_s3_bucket_policy_with_condition_marks_edge_conditional():
    role = _role("Auditor")
    bucket = _bucket("source-account-only", policy={
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": role.arn},
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT}},
        }],
    })
    g = GraphBuilder(_scan(role, bucket)).build()
    edges = _resource_policy_edges(g)
    assert len(edges) == 1
    assert edges[0][2]["has_conditions"] is True


def test_s3_bucket_policy_with_wildcard_action_marks_edge_admin():
    role = _role("Admin")
    bucket = _bucket("full-control", policy={
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": role.arn},
            "Action": "s3:*",
            "Resource": "*",
        }],
    })
    g = GraphBuilder(_scan(role, bucket)).build()
    edges = _resource_policy_edges(g)
    assert edges[0][2]["is_admin"] is True
    assert edges[0][2]["is_wildcard_resource"] is True


# ──────────────────────────── KMS key policy ──────────────────────────────

def test_kms_key_policy_grants_role():
    role = _role("DecryptUser")
    key = _kms_key("abcd-1234-...", policy={
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": role.arn},
            "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
            "Resource": "*",
        }],
    })
    g = GraphBuilder(_scan(role, key)).build()
    edges = _resource_policy_edges(g)
    assert len(edges) == 1
    u, v, d = edges[0]
    assert u == role.arn
    assert v == key.arn
    assert set(d["actions"]) == {"kms:Decrypt", "kms:GenerateDataKey"}
