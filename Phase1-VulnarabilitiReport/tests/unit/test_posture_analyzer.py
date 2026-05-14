"""
Tests for the new posture checks added in phase 5a-posture:
  - IAM Role (wildcard trust, cross-account no ExternalId, wildcard PassRole)
  - Lambda (EOL runtime)
  - EC2 (IMDSv1)
  - Secrets Manager (rotation disabled)
  - SSM Parameter (plaintext-named secret)
  - VPC (default VPC still available)
  - ALB (internet-facing without SG)

We construct minimal Resource fixtures by hand and feed them through the
analyzer. No AWS calls, no moto — same pattern as test_graph_builder.py.
"""
from __future__ import annotations

from datetime import datetime

from breakbot.models import Resource, ResourceType, ScanResult
from breakbot.posture.analyzer import PostureAnalyzer
from breakbot.posture.findings import Severity

ACCOUNT = "123456789012"


# ─────────────────────────────── Helpers ──────────────────────────────────

def _scan(resources: list[Resource]) -> ScanResult:
    return ScanResult(
        scan_id="test",
        scanner_account_id=ACCOUNT,
        accounts_scanned=[ACCOUNT],
        started_at=datetime(2025, 1, 1),
        completed_at=datetime(2025, 1, 1),
        regions_scanned=["us-east-1"],
        resources=resources,
    )


def _analyze(resource: Resource) -> list:
    return PostureAnalyzer().analyze(_scan([resource]))


def _iam_role(
    name: str,
    trust: dict | None = None,
    inline_policies: list[dict] | None = None,
    managed_policies: list[dict] | None = None,
) -> Resource:
    return Resource(
        arn=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        resource_type=ResourceType.IAM_ROLE,
        name=name,
        region="global",
        account_id=ACCOUNT,
        properties={
            "role_name": name,
            "trust_policy": trust or {},
            "inline_policies": inline_policies or [],
            "managed_policies": managed_policies or [],
        },
    )


# ───────────────────────── IAM_ROLE_WILDCARD_TRUST ────────────────────────

def test_iam_role_wildcard_trust_principal_star():
    role = _iam_role(
        "OpenRole",
        trust={
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }],
        },
    )
    findings = _analyze(role)
    codes = {f.check_id for f in findings}
    assert "IAM_ROLE_WILDCARD_TRUST" in codes
    f = next(f for f in findings if f.check_id == "IAM_ROLE_WILDCARD_TRUST")
    assert f.severity == Severity.CRITICAL


def test_iam_role_wildcard_trust_aws_star():
    role = _iam_role(
        "OpenRole",
        trust={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            }],
        },
    )
    findings = _analyze(role)
    assert "IAM_ROLE_WILDCARD_TRUST" in {f.check_id for f in findings}


def test_iam_role_wildcard_trust_with_condition_is_not_flagged():
    """A wildcard Principal with a Condition is no longer truly wildcard."""
    role = _iam_role(
        "OpenButConditional",
        trust={
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
            }],
        },
    )
    findings = _analyze(role)
    assert "IAM_ROLE_WILDCARD_TRUST" not in {f.check_id for f in findings}


def test_iam_role_service_trust_is_not_flagged():
    """Service trust (e.g., lambda.amazonaws.com) is normal."""
    role = _iam_role(
        "LambdaExec",
        trust={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        },
    )
    findings = _analyze(role)
    assert "IAM_ROLE_WILDCARD_TRUST" not in {f.check_id for f in findings}


# ────────────── IAM_ROLE_CROSS_ACCOUNT_NO_EXTERNAL_ID ────────────────────

def test_iam_role_cross_account_no_external_id():
    role = _iam_role(
        "PartnerAccess",
        trust={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                "Action": "sts:AssumeRole",
            }],
        },
    )
    findings = _analyze(role)
    codes = {f.check_id for f in findings}
    assert "IAM_ROLE_CROSS_ACCOUNT_NO_EXTERNAL_ID" in codes
    f = next(f for f in findings if f.check_id == "IAM_ROLE_CROSS_ACCOUNT_NO_EXTERNAL_ID")
    assert f.severity == Severity.HIGH


def test_iam_role_cross_account_with_external_id_is_not_flagged():
    role = _iam_role(
        "PartnerAccess",
        trust={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "shared-secret-x"}},
            }],
        },
    )
    findings = _analyze(role)
    assert "IAM_ROLE_CROSS_ACCOUNT_NO_EXTERNAL_ID" not in {f.check_id for f in findings}


def test_iam_role_same_account_trust_is_not_flagged():
    """Trusts to the same account number aren't cross-account."""
    role = _iam_role(
        "SelfTrust",
        trust={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/OtherRole"},
                "Action": "sts:AssumeRole",
            }],
        },
    )
    findings = _analyze(role)
    assert "IAM_ROLE_CROSS_ACCOUNT_NO_EXTERNAL_ID" not in {f.check_id for f in findings}


# ─────────────────── IAM_ROLE_WILDCARD_PASS_ROLE ──────────────────────────

def test_iam_role_wildcard_pass_role_inline():
    role = _iam_role(
        "Provisioner",
        inline_policies=[{
            "name": "deploy-anything",
            "document": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                }],
            },
        }],
    )
    findings = _analyze(role)
    codes = {f.check_id for f in findings}
    assert "IAM_ROLE_WILDCARD_PASS_ROLE" in codes


def test_iam_role_wildcard_pass_role_via_iam_star():
    role = _iam_role(
        "Provisioner",
        managed_policies=[{
            "name": "AdminCustom",
            "document": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["iam:*", "ec2:*"],
                    "Resource": "*",
                }],
            },
        }],
    )
    findings = _analyze(role)
    assert "IAM_ROLE_WILDCARD_PASS_ROLE" in {f.check_id for f in findings}


def test_iam_role_scoped_pass_role_is_not_flagged():
    role = _iam_role(
        "Provisioner",
        inline_policies=[{
            "name": "deploy-specific",
            "document": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{ACCOUNT}:role/LambdaExec",
                }],
            },
        }],
    )
    findings = _analyze(role)
    assert "IAM_ROLE_WILDCARD_PASS_ROLE" not in {f.check_id for f in findings}


# ───────────────────────────── Lambda EOL ─────────────────────────────────

def test_lambda_eol_runtime():
    fn = Resource(
        arn=f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:legacy",
        resource_type=ResourceType.LAMBDA_FUNCTION,
        name="legacy",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"function_name": "legacy", "runtime": "python3.7"},
    )
    findings = _analyze(fn)
    assert "LAMBDA_EOL_RUNTIME" in {f.check_id for f in findings}


def test_lambda_modern_runtime_is_not_flagged():
    fn = Resource(
        arn=f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:modern",
        resource_type=ResourceType.LAMBDA_FUNCTION,
        name="modern",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"function_name": "modern", "runtime": "python3.12"},
    )
    findings = _analyze(fn)
    assert "LAMBDA_EOL_RUNTIME" not in {f.check_id for f in findings}


# ─────────────────────────────── EC2 IMDSv1 ───────────────────────────────

def test_ec2_imdsv1_allowed_is_flagged():
    inst = Resource(
        arn=f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-aaa",
        resource_type=ResourceType.EC2_INSTANCE,
        name="i-aaa",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"instance_id": "i-aaa", "imds_v1_allowed": True},
    )
    findings = _analyze(inst)
    assert "EC2_IMDSV1_ALLOWED" in {f.check_id for f in findings}


def test_ec2_imdsv2_required_is_not_flagged():
    inst = Resource(
        arn=f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-bbb",
        resource_type=ResourceType.EC2_INSTANCE,
        name="i-bbb",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"instance_id": "i-bbb", "imds_v1_allowed": False},
    )
    findings = _analyze(inst)
    assert "EC2_IMDSV1_ALLOWED" not in {f.check_id for f in findings}


# ─────────────────────── Secrets Manager rotation ─────────────────────────

def test_secret_without_rotation_is_flagged():
    s = Resource(
        arn=f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:db-creds-abc",
        resource_type=ResourceType.SECRETS_MANAGER_SECRET,
        name="db-creds",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"secret_name": "db-creds", "rotation_enabled": False},
    )
    findings = _analyze(s)
    assert "SECRET_ROTATION_DISABLED" in {f.check_id for f in findings}


# ────────────────────────── SSM plaintext secret ──────────────────────────

def test_ssm_plaintext_named_password_is_flagged():
    p = Resource(
        arn=f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/db_password",
        resource_type=ResourceType.SSM_PARAMETER,
        name="/app/db_password",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"parameter_name": "/app/db_password", "type": "String"},
    )
    findings = _analyze(p)
    assert "SSM_PARAMETER_PLAINTEXT_SECRET" in {f.check_id for f in findings}


def test_ssm_securestring_named_password_is_not_flagged():
    p = Resource(
        arn=f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/db_password",
        resource_type=ResourceType.SSM_PARAMETER,
        name="/app/db_password",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"parameter_name": "/app/db_password", "type": "SecureString"},
    )
    findings = _analyze(p)
    assert "SSM_PARAMETER_PLAINTEXT_SECRET" not in {f.check_id for f in findings}


def test_ssm_plaintext_non_secret_name_is_not_flagged():
    p = Resource(
        arn=f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/log_level",
        resource_type=ResourceType.SSM_PARAMETER,
        name="/app/log_level",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"parameter_name": "/app/log_level", "type": "String"},
    )
    findings = _analyze(p)
    assert "SSM_PARAMETER_PLAINTEXT_SECRET" not in {f.check_id for f in findings}


# ─────────────────────────────── Default VPC ──────────────────────────────

def test_default_vpc_available_is_flagged():
    v = Resource(
        arn=f"arn:aws:ec2:us-east-1:{ACCOUNT}:vpc/vpc-aaa",
        resource_type=ResourceType.VPC,
        name="vpc-aaa",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"vpc_id": "vpc-aaa", "is_default": True, "state": "available"},
    )
    findings = _analyze(v)
    assert "DEFAULT_VPC_AVAILABLE" in {f.check_id for f in findings}


def test_non_default_vpc_is_not_flagged():
    v = Resource(
        arn=f"arn:aws:ec2:us-east-1:{ACCOUNT}:vpc/vpc-bbb",
        resource_type=ResourceType.VPC,
        name="vpc-bbb",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={"vpc_id": "vpc-bbb", "is_default": False, "state": "available"},
    )
    findings = _analyze(v)
    assert "DEFAULT_VPC_AVAILABLE" not in {f.check_id for f in findings}


# ───────────────────────── ALB internet-facing no SG ──────────────────────

def test_alb_internet_facing_no_sg_is_flagged():
    lb = Resource(
        arn=f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/prod/abc",
        resource_type=ResourceType.ALB,
        name="prod",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={
            "lb_type": "application",
            "is_alb": True,
            "is_internet_facing": True,
            "security_group_ids": [],
        },
    )
    findings = _analyze(lb)
    assert "ALB_INTERNET_FACING_NO_SG" in {f.check_id for f in findings}


def test_nlb_internet_facing_no_sg_is_not_flagged():
    """NLBs don't use security groups — the missing-SG check shouldn't apply."""
    lb = Resource(
        arn=f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/net/prod/abc",
        resource_type=ResourceType.ALB,
        name="prod-nlb",
        region="us-east-1",
        account_id=ACCOUNT,
        properties={
            "lb_type": "network",
            "is_alb": False,
            "is_nlb": True,
            "is_internet_facing": True,
            "security_group_ids": [],
        },
    )
    findings = _analyze(lb)
    assert "ALB_INTERNET_FACING_NO_SG" not in {f.check_id for f in findings}
