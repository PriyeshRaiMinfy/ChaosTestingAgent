"""
Cross-account session helpers for org-wide scanning.

How this fits the deployment model:

  Audit Account                              Member Account (Production)
  ─────────────                              ──────────────────────────
  breakbot runs here                         BreakBotReadOnly role
  │                                          (deployed via CFN StackSet)
  │  master_session (profile/instance role)         ▲
  │       │                                         │
  │       └─ organizations:ListAccounts ─────┐      │
  │       │                                  │      │
  │       └─ sts:AssumeRole ─────────────────┼─────►│
  │                                          │      │
  │  member_session (temp credentials) ◄─────┘      │
  │       │                                         │
  │       └─ every scanner uses this ──────────────►│  Describe*/List*/Get*
  │                                                 │

The factory caches one session per (account_id, region) so we don't
re-assume on every scanner call.
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.utils import AWSSession

logger = logging.getLogger(__name__)

DEFAULT_MEMBER_ROLE = "BreakBotReadOnly"


class OrganizationScanner:
    """
    Enumerates accounts in an AWS Organization.

    Requires `organizations:ListAccounts` on the master session. In a
    Control Tower landing zone this is normally only granted in the
    Management account or to a delegated administrator (the Audit account
    is the standard choice).
    """

    def __init__(self, master_session: AWSSession):
        self.session = master_session

    def list_accounts(self, include_suspended: bool = False) -> list[dict[str, str]]:
        """
        Returns active accounts in the Organization.

        Each dict has: {Id, Name, Email, Status}. Suspended accounts are
        filtered by default — they cannot be assumed into and would only
        produce errors in the scan output.
        """
        # Organizations is a global service, always endpoint in us-east-1
        orgs = self.session.client("organizations", region="us-east-1")
        paginator = orgs.get_paginator("list_accounts")

        accounts: list[dict[str, str]] = []
        try:
            for page in paginator.paginate():
                for acct in page["Accounts"]:
                    if not include_suspended and acct["Status"] != "ACTIVE":
                        continue
                    accounts.append({
                        "Id": acct["Id"],
                        "Name": acct["Name"],
                        "Email": acct["Email"],
                        "Status": acct["Status"],
                    })
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "AWSOrganizationsNotInUseException":
                raise RuntimeError(
                    "This account is not part of an AWS Organization. "
                    "Use single-account mode (omit --org) instead."
                ) from e
            if code == "AccessDeniedException":
                raise RuntimeError(
                    "The master session does not have organizations:ListAccounts. "
                    "Run BreakBot from the Management account or a delegated "
                    "administrator (typically the Audit account)."
                ) from e
            raise

        logger.info("Discovered %d active accounts in the Organization", len(accounts))
        return accounts


class CrossAccountSessionFactory:
    """
    Produces per-account AWSSession instances by assuming the
    BreakBotReadOnly role in each member account.

    Sessions are cached per (account_id, region) so repeated scanner
    calls reuse the same assumed credentials.
    """

    def __init__(
        self,
        master_session: AWSSession,
        member_role_name: str = DEFAULT_MEMBER_ROLE,
        external_id: str | None = None,
    ):
        self.master = master_session
        self.role_name = member_role_name
        self.external_id = external_id
        self._cache: dict[tuple[str, str], AWSSession] = {}

    def session_for(self, account_id: str, region: str = "us-east-1") -> AWSSession:
        """
        Returns an AWSSession pointing at `account_id` with credentials
        good for ~1 hour. Cached on (account_id, region).
        """
        key = (account_id, region)
        if key in self._cache:
            return self._cache[key]

        role_arn = f"arn:aws:iam::{account_id}:role/{self.role_name}"
        sess = AWSSession.from_assumed_role(
            source=self.master,
            role_arn=role_arn,
            region=region,
            external_id=self.external_id,
        )
        self._cache[key] = sess
        return sess

    def try_session_for(
        self, account_id: str, region: str = "us-east-1"
    ) -> AWSSession | None:
        """
        Like session_for() but returns None instead of raising if the role
        cannot be assumed (e.g. role not deployed yet, suspended account).

        Used during validation and scanning so one bad account doesn't
        derail the whole org sweep.
        """
        try:
            return self.session_for(account_id, region)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            logger.warning(
                "Cannot assume %s in account %s: %s",
                self.role_name, account_id, code,
            )
            return None
