"""
End-to-end smoke test for BreakBot.

Builds a synthetic AWS account (no AWS calls) with a planted attack chain:

  INTERNET
      |  :443
      v
   sg-web <-- attached_to_sg -- EC2 web-01 (public, IMDSv1)
      |                              |
      |  :5432                       |  has_instance_profile
      v                              v
   sg-db                          AppRole (s3:* on customer-data)
      |                              |
      v                              v
   RDS prod-db                   S3 customer-data (public, unencrypted)

Phases 1-4 are fully deterministic and asserted strictly.
Phase 5 (Claude) is skipped if ANTHROPIC_API_KEY is not set; when present, we
assert only on schema/cardinality, not on LLM-generated text (too flaky).

Run all integration tests:
    pytest -m integration

Run just this file:
    pytest tests/integration/test_end_to_end.py -v -s

The `-s` flag lets you see the printed phase artifacts inline.
"""
from __future__ import annotations

import os
from datetime import datetime

import pytest

from breakbot.graph import GraphBuilder, GraphSerializer
from breakbot.graph.edges import INTERNET_NODE_ID, EdgeType
from breakbot.models import Resource, ResourceType, ScanResult
from breakbot.posture import PostureAnalyzer

ACCOUNT = "123456789012"
REGION = "us-east-1"


# ─────────────────────── Synthetic resource builders ──────────────────────

def _vpc(vpc_id: str) -> Resource:
    return Resource(
        arn=f"arn:aws:ec2:{REGION}:{ACCOUNT}:vpc/{vpc_id}",
        resource_type=ResourceType.VPC,
        name=vpc_id,
        region=REGION,
        account_id=ACCOUNT,
        properties={"vpc_id": vpc_id, "cidr_block": "10.0.0.0/16", "is_default": False},
    )


def _sg(sg_id: str, ingress_rules: list[dict], internet_exposed: bool, vpc_id: str) -> Resource:
    return Resource(
        arn=f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{sg_id}",
        resource_type=ResourceType.SECURITY_GROUP,
        name=sg_id,
        region=REGION,
        account_id=ACCOUNT,
        properties={
            "group_id": sg_id,
            "ingress_rules": ingress_rules,
            "egress_rules": [],
            "internet_exposed": internet_exposed,
            "vpc_id": vpc_id,
        },
    )


def _ec2(instance_id: str, sg_ids: list[str], profile_name: str, public_ip: str) -> Resource:
    return Resource(
        arn=f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{instance_id}",
        resource_type=ResourceType.EC2_INSTANCE,
        name=instance_id,
        region=REGION,
        account_id=ACCOUNT,
        properties={
            "instance_id": instance_id,
            "security_group_ids": sg_ids,
            "iam_instance_profile_arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/{profile_name}",
            "public_ip": public_ip,
            "is_public": True,
            "imds_v1_allowed": True,
            "vpc_id": "vpc-prod",
        },
    )


def _alb(name: str, sg_ids: list[str], vpc_id: str) -> Resource:
    return Resource(
        arn=f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/{name}/abc123",
        resource_type=ResourceType.ALB,
        name=name,
        region=REGION,
        account_id=ACCOUNT,
        properties={
            "lb_name": name,
            "dns_name": f"{name}-1234567890.{REGION}.elb.amazonaws.com",
            "scheme": "internet-facing",
            "is_internet_facing": True,
            "security_group_ids": sg_ids,
            "vpc_id": vpc_id,
        },
    )


def _iam_role(name: str, trust: dict, inline_policies: list[dict]) -> Resource:
    return Resource(
        arn=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        resource_type=ResourceType.IAM_ROLE,
        name=name,
        region="global",
        account_id=ACCOUNT,
        properties={
            "role_name": name,
            "trust_policy": trust,
            "inline_policies": inline_policies,
            "managed_policies": [],
        },
    )


def _s3(name: str, public: bool, encrypted: bool) -> Resource:
    pab = {
        "block_public_acls": not public,
        "ignore_public_acls": not public,
        "block_public_policy": not public,
        "restrict_public_buckets": not public,
    }
    return Resource(
        arn=f"arn:aws:s3:::{name}",
        resource_type=ResourceType.S3_BUCKET,
        name=name,
        region=REGION,
        account_id=ACCOUNT,
        properties={
            "bucket_name": name,
            "public_access_block": pab,
            "has_bucket_policy": False,
            "is_encrypted": encrypted,
        },
    )


def _rds(name: str, sg_ids: list[str], publicly_accessible: bool, encrypted: bool) -> Resource:
    return Resource(
        arn=f"arn:aws:rds:{REGION}:{ACCOUNT}:db:{name}",
        resource_type=ResourceType.RDS_INSTANCE,
        name=name,
        region=REGION,
        account_id=ACCOUNT,
        properties={
            "db_identifier": name,
            "engine": "postgres",
            "publicly_accessible": publicly_accessible,
            "storage_encrypted": encrypted,
            "iam_database_auth_enabled": False,
            "security_group_ids": sg_ids,
        },
    )


def _build_attack_chain() -> ScanResult:
    """Construct the synthetic ScanResult with a planted attack chain."""
    vpc = _vpc("vpc-prod")
    sg_web = _sg(
        "sg-web",
        ingress_rules=[{
            "protocol": "tcp", "from_port": 443, "to_port": 443,
            "cidrs": ["0.0.0.0/0"], "ipv6_cidrs": [], "referenced_sgs": [],
        }],
        internet_exposed=True,
        vpc_id="vpc-prod",
    )
    sg_db = _sg(
        "sg-db",
        ingress_rules=[{
            "protocol": "tcp", "from_port": 5432, "to_port": 5432,
            "cidrs": [], "ipv6_cidrs": [], "referenced_sgs": ["sg-web"],
        }],
        internet_exposed=False,
        vpc_id="vpc-prod",
    )
    alb = _alb("prod-alb", sg_ids=["sg-web"], vpc_id="vpc-prod")
    ec2 = _ec2("web-01", sg_ids=["sg-web"], profile_name="AppRole", public_ip="3.4.5.6")
    bucket = _s3("customer-data", public=True, encrypted=False)
    rds = _rds("prod-db", sg_ids=["sg-db"], publicly_accessible=True, encrypted=False)
    app_role = _iam_role(
        "AppRole",
        trust={
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        },
        inline_policies=[{
            "name": "customer-data-access",
            "document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": [bucket.arn, f"{bucket.arn}/*"],
                }],
            },
        }],
    )
    return ScanResult(
        scan_id="smoke-test",
        scanner_account_id=ACCOUNT,
        accounts_scanned=[ACCOUNT],
        started_at=datetime(2025, 1, 1),
        completed_at=datetime(2025, 1, 1),
        regions_scanned=[REGION],
        resources=[vpc, sg_web, sg_db, alb, ec2, app_role, bucket, rds],
    )


# ─────────────────────────────── Fixtures ─────────────────────────────────

@pytest.fixture(scope="module")
def scan_result() -> ScanResult:
    return _build_attack_chain()


@pytest.fixture(scope="module")
def graph(scan_result: ScanResult):
    return GraphBuilder(scan_result)


@pytest.fixture(scope="module")
def serializer(graph):
    g = graph.build()
    return GraphSerializer(g, graph.arn_index, max_hops=5), g


# ───────────────────────── Phase 1-2: scan shape ──────────────────────────

def test_synthetic_scan_has_eight_resources(scan_result: ScanResult):
    assert scan_result.resource_count == 8
    types = {r.resource_type for r in scan_result.resources}
    assert ResourceType.EC2_INSTANCE in types
    assert ResourceType.S3_BUCKET in types
    assert ResourceType.IAM_ROLE in types
    assert ResourceType.RDS_INSTANCE in types
    assert ResourceType.ALB in types


# ───────────────────────── Phase 4: graph build ───────────────────────────

def test_graph_includes_internet_virtual_node(serializer):
    _, g = serializer
    assert INTERNET_NODE_ID in g.nodes


def test_graph_has_all_expected_edge_types(serializer):
    _, g = serializer
    edge_types = {d.get("edge_type") for _, _, d in g.edges(data=True)}
    expected = {
        EdgeType.ATTACHED_TO_SG,
        EdgeType.HAS_INSTANCE_PROFILE,
        EdgeType.IAM_CAN_ACCESS,
        EdgeType.IAM_CAN_ASSUME,
        EdgeType.IN_VPC,
        EdgeType.INTERNET_EXPOSES,
        EdgeType.NETWORK_CAN_REACH,
    }
    missing = expected - edge_types
    assert not missing, f"missing edge types: {missing}"


def test_graph_has_planted_privesc_chain(serializer):
    """EC2 -> AppRole -> S3 must exist as a connected path."""
    _, g = serializer
    ec2_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/web-01"
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/AppRole"
    bucket_arn = "arn:aws:s3:::customer-data"

    assert g.has_edge(ec2_arn, role_arn)
    assert g.has_edge(role_arn, bucket_arn)


# ──────────────────────── Phase 4: serialization ──────────────────────────

def test_serializer_detects_entry_points_and_sinks(serializer):
    s, _ = serializer
    stats = s.stats()
    assert stats["entry_points"] >= 2     # public EC2 + ALB + public S3
    assert stats["sinks"] >= 2            # RDS + S3


def test_attack_surface_text_contains_path(serializer):
    s, _ = serializer
    text = s.serialize()
    # Sections
    assert "=== ENTRY POINTS ===" in text
    assert "=== SENSITIVE SINKS ===" in text
    assert "=== ATTACK SURFACE PATHS" in text
    # Resources from the planted chain
    assert "web-01" in text
    assert "AppRole" in text
    assert "customer-data" in text
    # At least one path entry rendered
    assert "PATH 1:" in text


# ─────────────────────────── Phase 3: posture ─────────────────────────────

def test_posture_catches_planted_misconfigs(scan_result: ScanResult):
    findings = PostureAnalyzer().analyze(scan_result)
    check_ids = {f.check_id for f in findings}
    # Each of the planted misconfigurations should surface
    assert "RDS_PUBLICLY_ACCESSIBLE" in check_ids
    assert "RDS_NOT_ENCRYPTED" in check_ids
    assert "S3_PUBLIC_ACCESS_BLOCK_DISABLED" in check_ids


# ──────────────────── Phase 5: SecurityAnalyst (Claude) ───────────────────

@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set; skipping live Claude call.",
)
def test_security_analyst_returns_structured_report(serializer, scan_result):
    """
    Asserts schema and cardinality, NOT specific LLM text.
    Forced tool use guarantees the schema; we just verify our parsing path.
    """
    from breakbot.brain import AnalysisReport, AttackPath, SecurityAnalyst

    s, _ = serializer
    attack_surface = s.serialize()
    posture = [f.to_dict() for f in PostureAnalyzer().analyze(scan_result)]

    report = SecurityAnalyst().analyze(attack_surface, posture)

    # Top-level shape
    assert isinstance(report, AnalysisReport)
    assert report.scan_summary
    assert report.overall_severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert isinstance(report.top_risks, list)
    assert isinstance(report.attack_paths, list)
    assert len(report.attack_paths) >= 1, "expected at least one attack path"

    # Every path validates
    for path in report.attack_paths:
        assert isinstance(path, AttackPath)
        assert path.entry_point
        assert path.blast_radius
        assert path.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert path.confidence in {"HIGH", "MEDIUM", "LOW"}
        assert len(path.attack_steps) >= 1
        assert len(path.remediation) >= 1

    # Renderers don't crash
    assert report.to_markdown()
    assert report.to_json()
    assert report.to_dict()
