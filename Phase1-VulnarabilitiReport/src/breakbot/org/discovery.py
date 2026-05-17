"""
Auto-discovery of AWS account topology and CloudTrail configuration.

Answers three questions without user input:
  1. Is this account part of an AWS Organization?
  2. If org: which member accounts exist, and can we assume into them?
  3. Is there an Organization Trail with an accessible S3 bucket?

Usage (CLI or web UI):
    from breakbot.org.discovery import EnvironmentDiscovery

    discovery = EnvironmentDiscovery(session)
    result = discovery.detect()
    # result.is_org, result.accounts, result.org_trail_bucket, ...
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from breakbot.utils import AWSSession

logger = logging.getLogger(__name__)


@dataclass
class OrgTrailInfo:
    """Describes an Organization CloudTrail and its S3 bucket accessibility."""
    trail_name: str
    trail_arn: str
    s3_bucket_name: str
    s3_key_prefix: str | None
    is_accessible: bool
    access_error: str | None = None


@dataclass
class AccountInfo:
    """A member account discovered from the Organization."""
    account_id: str
    name: str
    email: str
    status: str
    can_assume: bool = False
    assume_error: str | None = None


@dataclass
class DiscoveryResult:
    """Complete discovery output — everything needed to decide scan strategy."""
    is_org: bool
    current_account_id: str
    org_id: str | None = None
    accounts: list[AccountInfo] = field(default_factory=list)
    org_trail: OrgTrailInfo | None = None
    detection_error: str | None = None

    @property
    def accessible_accounts(self) -> list[AccountInfo]:
        return [a for a in self.accounts if a.can_assume]

    @property
    def inaccessible_accounts(self) -> list[AccountInfo]:
        return [a for a in self.accounts if not a.can_assume]

    @property
    def has_org_trail_access(self) -> bool:
        return self.org_trail is not None and self.org_trail.is_accessible


class EnvironmentDiscovery:
    """
    Probes the AWS environment to determine topology and trail availability.

    Reusable by CLI and web UI — no I/O except AWS API calls.
    """

    def __init__(self, session: AWSSession, member_role_name: str = "BreakBotReadOnly"):
        self._session = session
        self._member_role = member_role_name

    def detect(self, check_assume: bool = True) -> DiscoveryResult:
        """
        Run full discovery. Steps:
          1. Try organizations:ListAccounts
          2. If org: find Organization Trail
          3. If org trail has S3 bucket: check if readable
          4. Optionally: try assuming role into each member account

        Args:
            check_assume: if True, test sts:AssumeRole into each member
                          account (slower but gives complete picture)
        """
        current_account = self._session.account_id

        # Step 1: Org detection
        is_org, accounts, detection_error, org_id = self._detect_org()

        if not is_org:
            return DiscoveryResult(
                is_org=False,
                current_account_id=current_account,
                detection_error=detection_error,
            )

        # Step 2-3: Find org trail + check S3 access
        org_trail = self._find_org_trail()

        # Step 4: Check assumability of each account
        if check_assume:
            self._check_assume_access(accounts, current_account)

        return DiscoveryResult(
            is_org=True,
            current_account_id=current_account,
            org_id=org_id,
            accounts=accounts,
            org_trail=org_trail,
        )

    def _detect_org(self) -> tuple[bool, list[AccountInfo], str | None, str | None]:
        """Try DescribeOrganization + ListAccounts. Returns (is_org, accounts, error, org_id)."""
        try:
            orgs = self._session.client("organizations", region="us-east-1")

            # Get org ID first
            org_id: str | None = None
            try:
                desc = orgs.describe_organization()
                org_id = desc.get("Organization", {}).get("Id")
            except ClientError:
                pass  # proceed without org_id — non-fatal

            paginator = orgs.get_paginator("list_accounts")
            accounts: list[AccountInfo] = []
            for page in paginator.paginate():
                for acct in page["Accounts"]:
                    if acct["Status"] != "ACTIVE":
                        continue
                    accounts.append(AccountInfo(
                        account_id=acct["Id"],
                        name=acct["Name"],
                        email=acct["Email"],
                        status=acct["Status"],
                    ))
            logger.info("Org detected: %d active accounts (org_id=%s)", len(accounts), org_id)
            return True, accounts, None, org_id
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "AWSOrganizationsNotInUseException":
                return False, [], "Account is not in an AWS Organization", None
            if code == "AccessDeniedException":
                return False, [], "No organizations:ListAccounts permission (may still be in org)", None
            return False, [], f"Org detection failed: {code}", None

    def _find_org_trail(self) -> OrgTrailInfo | None:
        """Find Organization Trail and check if its S3 bucket is readable."""
        try:
            ct = self._session.client("cloudtrail", region="us-east-1")
            resp = ct.describe_trails(includeShadowTrails=False)
            for trail in resp.get("trailList", []):
                if trail.get("IsOrganizationTrail"):
                    bucket = trail.get("S3BucketName", "")
                    prefix = trail.get("S3KeyPrefix")
                    trail_info = OrgTrailInfo(
                        trail_name=trail.get("Name", ""),
                        trail_arn=trail.get("TrailARN", ""),
                        s3_bucket_name=bucket,
                        s3_key_prefix=prefix,
                        is_accessible=False,
                    )
                    if bucket:
                        trail_info.is_accessible, trail_info.access_error = (
                            self._check_bucket_access(bucket, prefix)
                        )
                    return trail_info
        except ClientError as e:
            logger.warning("Could not describe trails: %s", e)
        return None

    def _check_bucket_access(self, bucket: str, prefix: str | None) -> tuple[bool, str | None]:
        """Try listing objects in the trail bucket to confirm read access."""
        s3 = self._session.client("s3", region="us-east-1")
        list_prefix = f"{prefix}/" if prefix else ""
        try:
            s3.list_objects_v2(Bucket=bucket, Prefix=list_prefix, MaxKeys=1)
            return True, None
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            return False, f"Cannot read trail bucket '{bucket}': {code}"

    def _check_assume_access(
        self, accounts: list[AccountInfo], current_account_id: str
    ) -> None:
        """Test AssumeRole into each member account (skip self)."""
        sts = self._session.client("sts", region="us-east-1")
        for acct in accounts:
            if acct.account_id == current_account_id:
                acct.can_assume = True  # self — no assume needed
                continue
            role_arn = f"arn:aws:iam::{acct.account_id}:role/{self._member_role}"
            try:
                sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="breakbot-discovery-check",
                    DurationSeconds=900,
                )
                acct.can_assume = True
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                acct.can_assume = False
                acct.assume_error = code


def generate_cfn_stackset_template(
    audit_account_id: str,
    role_name: str = "BreakBotReadOnly",
    external_id: str | None = None,
) -> str:
    """
    Generate a CloudFormation template for deploying the read-only role
    into member accounts via StackSet.

    Returns YAML string ready for deployment.
    """
    condition_block = ""
    if external_id:
        condition_block = (
            "\n        Condition:\n"
            "          StringEquals:\n"
            f'            sts:ExternalId: "{external_id}"'
        )

    lines = [
        "AWSTemplateFormatVersion: '2010-09-09'",
        "Description: >",
        "  BreakBot read-only cross-account role.",
        "  Deployed via StackSet from the audit/management account.",
        "",
        "Resources:",
        "  BreakBotReadOnlyRole:",
        "    Type: AWS::IAM::Role",
        "    Properties:",
        f"      RoleName: {role_name}",
        "      AssumeRolePolicyDocument:",
        "        Version: '2012-10-17'",
        "        Statement:",
        "          - Effect: Allow",
        "            Principal:",
        f"              AWS: arn:aws:iam::{audit_account_id}:root",
        f"            Action: sts:AssumeRole{condition_block}",
        "      ManagedPolicyArns:",
        "        - arn:aws:iam::aws:policy/SecurityAudit",
        "        - arn:aws:iam::aws:policy/ReadOnlyAccess",
        "      Tags:",
        "        - Key: Purpose",
        "          Value: BreakBot security scanning",
        "        - Key: ManagedBy",
        "          Value: BreakBot-StackSet",
        "",
        "Outputs:",
        "  RoleArn:",
        "    Value: !GetAtt BreakBotReadOnlyRole.Arn",
        "    Description: ARN of the BreakBot read-only role in this account",
    ]
    return "\n".join(lines) + "\n"
