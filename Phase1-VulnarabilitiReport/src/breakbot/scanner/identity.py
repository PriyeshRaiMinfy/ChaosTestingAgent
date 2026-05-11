"""
Identity scanner — IAM roles, policies, and users.

IAM is global. We scan it once.

Why this is the most important scanner:
  - Every attack path traverses IAM at some point. "Lambda has role X.
    Role X can read S3 bucket Y. Therefore Lambda can read Y."
  - The trust policy on a role tells us who can assume it. This is the
    most common privilege-escalation vector.
  - We capture the full policy document so Phase 4 can parse it into edges.

What we DON'T do here:
  - Parse policy documents into Action × Resource edges. That's graph
    builder territory (Phase 4). The scanner's job is faithful capture.
"""
from __future__ import annotations

import json
import logging
from urllib.parse import unquote

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class IdentityScanner(BaseScanner):
    domain = "identity"
    is_global = True  # IAM is global — scan once

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        resources.extend(self._scan_roles())
        resources.extend(self._scan_users())
        return resources

    # ──────────────────────────── Roles ─────────────────────────────────

    def _scan_roles(self) -> list[Resource]:
        """
        For each role, capture:
          - assume_role_policy (trust policy)
          - attached managed policies (names + ARNs)
          - inline policies (full documents)
        """
        iam = self.session.client("iam", region="us-east-1")
        paginator = iam.get_paginator("list_roles")

        resources = []
        try:
            for page in paginator.paginate():
                for role in page["Roles"]:
                    try:
                        resources.append(self._inspect_role(role))
                    except ClientError as e:
                        logger.warning(
                            "Role %s inspection failed: %s",
                            role["RoleName"], e.response["Error"]["Code"],
                        )
                        self.errors.append({
                            "domain": self.domain,
                            "resource": role["RoleName"],
                            "error": str(e),
                        })
        except ClientError as e:
            logger.warning("list_roles failed: %s", e.response["Error"]["Code"])
            raise
        return resources

    def _inspect_role(self, role: dict) -> Resource:
        iam = self.session.client("iam", region="us-east-1")
        role_name = role["RoleName"]

        # Trust policy comes URL-encoded in describe_role output
        trust_policy = role.get("AssumeRolePolicyDocument")
        if isinstance(trust_policy, str):
            trust_policy = json.loads(unquote(trust_policy))

        # Attached managed policies
        attached = iam.list_attached_role_policies(RoleName=role_name)
        managed_policies = [
            {"name": p["PolicyName"], "arn": p["PolicyArn"]}
            for p in attached.get("AttachedPolicies", [])
        ]

        # Inline policies — fetch each document
        inline_names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        inline_policies = []
        for pname in inline_names:
            pdoc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
            doc = pdoc["PolicyDocument"]
            if isinstance(doc, str):
                doc = json.loads(unquote(doc))
            inline_policies.append({"name": pname, "document": doc})

        properties = {
            "role_name": role_name,
            "role_id": role.get("RoleId"),
            "path": role.get("Path"),
            "trust_policy": trust_policy,
            "managed_policies": managed_policies,
            "inline_policies": inline_policies,
            "max_session_duration": role.get("MaxSessionDuration"),
            "description": role.get("Description"),
        }

        return Resource(
            arn=role["Arn"],
            resource_type=ResourceType.IAM_ROLE,
            name=role_name,
            region="global",
            account_id=self.session.account_id,
            properties=properties,
        )

    # ──────────────────────────── Users ─────────────────────────────────

    def _scan_users(self) -> list[Resource]:
        """
        IAM users matter because they're often long-lived static credentials —
        a much weaker auth posture than role-based access. Capture access key
        metadata (NOT the keys themselves, which read-only can't see anyway).
        """
        iam = self.session.client("iam", region="us-east-1")
        paginator = iam.get_paginator("list_users")

        resources = []
        try:
            for page in paginator.paginate():
                for user in page["Users"]:
                    try:
                        resources.append(self._inspect_user(user))
                    except ClientError as e:
                        logger.warning(
                            "User %s inspection failed: %s",
                            user["UserName"], e.response["Error"]["Code"],
                        )
        except ClientError as e:
            logger.warning("list_users failed: %s", e.response["Error"]["Code"])
            raise
        return resources

    def _inspect_user(self, user: dict) -> Resource:
        iam = self.session.client("iam", region="us-east-1")
        user_name = user["UserName"]

        # Access keys — metadata only (we never see secrets)
        access_keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
        keys = [
            {
                "access_key_id": k["AccessKeyId"],
                "status": k["Status"],
                "create_date": k["CreateDate"].isoformat(),
            }
            for k in access_keys
        ]

        # MFA devices
        mfa = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])

        # Group memberships
        groups = iam.list_groups_for_user(UserName=user_name).get("Groups", [])

        properties = {
            "user_name": user_name,
            "user_id": user.get("UserId"),
            "path": user.get("Path"),
            "create_date": user["CreateDate"].isoformat() if user.get("CreateDate") else None,
            "access_keys": keys,
            "has_active_access_keys": any(k["status"] == "Active" for k in keys),
            "mfa_enabled": len(mfa) > 0,
            "groups": [g["GroupName"] for g in groups],
        }

        return Resource(
            arn=user["Arn"],
            resource_type=ResourceType.IAM_USER,
            name=user_name,
            region="global",
            account_id=self.session.account_id,
            properties=properties,
        )
