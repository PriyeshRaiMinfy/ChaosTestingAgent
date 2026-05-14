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
from breakbot.scanner.errors import ScanError, categorize

logger = logging.getLogger(__name__)


class IdentityScanner(BaseScanner):
    domain = "identity"
    is_global = True  # IAM is global — scan once

    def __init__(self, session):
        super().__init__(session)
        # Policy document cache keyed by policy ARN — avoids refetching the
        # same AWS-managed policy when it's attached to hundreds of roles.
        self._policy_doc_cache: dict[str, dict | None] = {}

    def _scan_region(self, region: str) -> list[Resource]:
        # Roles and Users are isolated — Users still scans if Roles fails.
        resources: list[Resource] = []
        resources.extend(self._safe_scan_call(
            "iam", "list_roles", region,
            lambda: self._scan_roles(),
        ))
        resources.extend(self._safe_scan_call(
            "iam", "list_users", region,
            lambda: self._scan_users(),
        ))
        return resources

    # ──────────────────────────── Roles ─────────────────────────────────

    def _scan_roles(self) -> list[Resource]:
        """
        For each role, capture:
          - assume_role_policy (trust policy)
          - attached managed policies (names + ARNs)
          - inline policies (full documents)

        Errors from list_roles itself propagate up to _safe_scan_call.
        Per-role inspection errors are isolated below so one bad role
        doesn't lose the rest.
        """
        iam = self.session.client("iam", region="us-east-1")
        paginator = iam.get_paginator("list_roles")

        resources = []
        for page in paginator.paginate():
            for role in page["Roles"]:
                try:
                    resources.append(self._inspect_role(role))
                except ClientError as e:
                    self._record_per_resource_error(
                        operation="get_role_policy",
                        resource_name=role.get("RoleName", "?"),
                        error=e,
                    )
        return resources

    def _inspect_role(self, role: dict) -> Resource:
        iam = self.session.client("iam", region="us-east-1")
        role_name = role["RoleName"]

        # Trust policy comes URL-encoded in describe_role output
        trust_policy = role.get("AssumeRolePolicyDocument")
        if isinstance(trust_policy, str):
            trust_policy = json.loads(unquote(trust_policy))

        # Attached managed policies — fetch each policy's default version
        # document so the graph builder can construct iam_can_access edges
        # without extra calls.
        attached = iam.list_attached_role_policies(RoleName=role_name)
        managed_policies = []
        for p in attached.get("AttachedPolicies", []):
            doc = self._get_policy_document(p["PolicyArn"])
            managed_policies.append({
                "name": p["PolicyName"],
                "arn": p["PolicyArn"],
                "is_aws_managed": p["PolicyArn"].startswith("arn:aws:iam::aws:"),
                "document": doc,
            })

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

    # ──────────────────────── Policy Documents ───────────────────────────

    def _get_policy_document(self, policy_arn: str) -> dict | None:
        """
        Fetches the default policy version document for a managed policy.
        Results are cached so the same AWS-managed policy attached to 50 roles
        only causes one API call.
        """
        if policy_arn in self._policy_doc_cache:
            return self._policy_doc_cache[policy_arn]

        iam = self.session.client("iam", region="us-east-1")
        try:
            policy_meta = iam.get_policy(PolicyArn=policy_arn)
            version_id = policy_meta["Policy"]["DefaultVersionId"]
            version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            doc = version["PolicyVersion"]["Document"]
            if isinstance(doc, str):
                doc = json.loads(unquote(doc))
            self._policy_doc_cache[policy_arn] = doc
        except ClientError as e:
            logger.warning(
                "Could not fetch policy document %s: %s",
                policy_arn, e.response["Error"]["Code"],
            )
            self._policy_doc_cache[policy_arn] = None

        return self._policy_doc_cache[policy_arn]

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
        for page in paginator.paginate():
            for user in page["Users"]:
                try:
                    resources.append(self._inspect_user(user))
                except ClientError as e:
                    self._record_per_resource_error(
                        operation="list_access_keys",
                        resource_name=user.get("UserName", "?"),
                        error=e,
                    )
        return resources

    def _inspect_user(self, user: dict) -> Resource:
        iam = self.session.client("iam", region="us-east-1")
        user_name = user["UserName"]

        access_keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
        keys = [
            {
                "access_key_id": k["AccessKeyId"],
                "status": k["Status"],
                "create_date": k["CreateDate"].isoformat(),
            }
            for k in access_keys
        ]

        mfa = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
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

    # ──────────────────────── Per-resource errors ────────────────────────

    def _record_per_resource_error(
        self, operation: str, resource_name: str, error: ClientError,
    ) -> None:
        """Record a structured error for a single role/user inspection failure."""
        err = error.response.get("Error", {}) or {}
        code = err.get("Code", "Unknown")
        message = err.get("Message", str(error))
        request_id = (error.response.get("ResponseMetadata") or {}).get("RequestId")

        logger.warning(
            "[%s] %s on %s failed: %s",
            self.domain, operation, resource_name, code,
        )
        self.errors.append(ScanError(
            domain=self.domain,
            account_id=self.session.account_id,
            region="global",
            service="iam",
            operation=f"{operation}({resource_name})",
            error_code=code,
            error_type="ClientError",
            message=message,
            request_id=request_id,
            category=categorize(code),
        ).to_dict())
