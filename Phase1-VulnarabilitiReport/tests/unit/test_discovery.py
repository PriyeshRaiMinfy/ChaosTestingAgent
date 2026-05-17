"""
Unit tests for EnvironmentDiscovery.

Uses mocked boto3 clients — no real AWS calls.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from breakbot.org.discovery import (
    AccountInfo,
    DiscoveryResult,
    EnvironmentDiscovery,
    OrgTrailInfo,
    generate_cfn_stackset_template,
)


def _client_error(code: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "test"}}, "TestOp"
    )


def _mock_session(account_id: str = "111111111111") -> MagicMock:
    sess = MagicMock()
    sess.account_id = account_id
    return sess


class TestDetectOrg:
    def test_detects_org_with_accounts_and_org_id(self):
        sess = _mock_session()
        orgs_client = MagicMock()
        orgs_client.describe_organization.return_value = {
            "Organization": {"Id": "o-abc123"}
        }
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Accounts": [
                {"Id": "111111111111", "Name": "Audit", "Email": "a@x.com", "Status": "ACTIVE"},
                {"Id": "222222222222", "Name": "Prod", "Email": "b@x.com", "Status": "ACTIVE"},
                {"Id": "333333333333", "Name": "Suspended", "Email": "c@x.com", "Status": "SUSPENDED"},
            ]}
        ]
        orgs_client.get_paginator.return_value = paginator
        sess.client.return_value = orgs_client

        disc = EnvironmentDiscovery(sess)
        is_org, accounts, error, org_id = disc._detect_org()

        assert is_org is True
        assert len(accounts) == 2  # SUSPENDED filtered
        assert org_id == "o-abc123"
        assert error is None
        assert accounts[0].account_id == "111111111111"
        assert accounts[1].account_id == "222222222222"

    def test_not_in_org(self):
        sess = _mock_session()
        orgs_client = MagicMock()
        orgs_client.get_paginator.side_effect = _client_error("AWSOrganizationsNotInUseException")
        sess.client.return_value = orgs_client

        disc = EnvironmentDiscovery(sess)
        is_org, accounts, error, org_id = disc._detect_org()

        assert is_org is False
        assert accounts == []
        assert org_id is None
        assert "not in an AWS Organization" in error

    def test_access_denied(self):
        sess = _mock_session()
        orgs_client = MagicMock()
        orgs_client.get_paginator.side_effect = _client_error("AccessDeniedException")
        sess.client.return_value = orgs_client

        disc = EnvironmentDiscovery(sess)
        is_org, accounts, error, org_id = disc._detect_org()

        assert is_org is False
        assert "permission" in error.lower()

    def test_describe_org_fails_gracefully(self):
        """If DescribeOrganization fails but ListAccounts works, org_id is None."""
        sess = _mock_session()
        orgs_client = MagicMock()
        orgs_client.describe_organization.side_effect = _client_error("AccessDeniedException")
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Accounts": [
                {"Id": "111111111111", "Name": "Audit", "Email": "a@x.com", "Status": "ACTIVE"},
            ]}
        ]
        orgs_client.get_paginator.return_value = paginator
        sess.client.return_value = orgs_client

        disc = EnvironmentDiscovery(sess)
        is_org, accounts, error, org_id = disc._detect_org()

        assert is_org is True
        assert org_id is None
        assert len(accounts) == 1


class TestFindOrgTrail:
    def test_finds_org_trail_accessible(self):
        sess = _mock_session()
        ct_client = MagicMock()
        ct_client.describe_trails.return_value = {
            "trailList": [{
                "Name": "OrgTrail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:111:trail/OrgTrail",
                "IsOrganizationTrail": True,
                "S3BucketName": "my-org-trail-bucket",
                "S3KeyPrefix": "cloudtrail",
            }]
        }
        s3_client = MagicMock()
        s3_client.list_objects_v2.return_value = {"Contents": []}

        def client_router(service, **kwargs):
            if service == "cloudtrail":
                return ct_client
            return s3_client

        sess.client.side_effect = client_router

        disc = EnvironmentDiscovery(sess)
        trail = disc._find_org_trail()

        assert trail is not None
        assert trail.trail_name == "OrgTrail"
        assert trail.s3_bucket_name == "my-org-trail-bucket"
        assert trail.s3_key_prefix == "cloudtrail"
        assert trail.is_accessible is True

    def test_finds_org_trail_inaccessible(self):
        sess = _mock_session()
        ct_client = MagicMock()
        ct_client.describe_trails.return_value = {
            "trailList": [{
                "Name": "OrgTrail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:111:trail/OrgTrail",
                "IsOrganizationTrail": True,
                "S3BucketName": "locked-bucket",
                "S3KeyPrefix": None,
            }]
        }
        s3_client = MagicMock()
        s3_client.list_objects_v2.side_effect = _client_error("AccessDenied")

        def client_router(service, **kwargs):
            if service == "cloudtrail":
                return ct_client
            return s3_client

        sess.client.side_effect = client_router

        disc = EnvironmentDiscovery(sess)
        trail = disc._find_org_trail()

        assert trail is not None
        assert trail.is_accessible is False
        assert "AccessDenied" in trail.access_error

    def test_no_org_trail_found(self):
        sess = _mock_session()
        ct_client = MagicMock()
        ct_client.describe_trails.return_value = {
            "trailList": [{
                "Name": "RegularTrail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:111:trail/RegularTrail",
                "IsOrganizationTrail": False,
                "S3BucketName": "some-bucket",
            }]
        }
        sess.client.return_value = ct_client

        disc = EnvironmentDiscovery(sess)
        trail = disc._find_org_trail()
        assert trail is None


class TestCheckAssumeAccess:
    def test_marks_self_as_assumable(self):
        sess = _mock_session("111111111111")
        sts_client = MagicMock()
        sess.client.return_value = sts_client

        accounts = [
            AccountInfo("111111111111", "Self", "a@x.com", "ACTIVE"),
            AccountInfo("222222222222", "Other", "b@x.com", "ACTIVE"),
        ]
        sts_client.assume_role.return_value = {}

        disc = EnvironmentDiscovery(sess)
        disc._check_assume_access(accounts, "111111111111")

        assert accounts[0].can_assume is True
        assert accounts[1].can_assume is True
        # Only called for non-self account
        sts_client.assume_role.assert_called_once()

    def test_marks_failed_assume(self):
        sess = _mock_session("111111111111")
        sts_client = MagicMock()
        sts_client.assume_role.side_effect = _client_error("AccessDenied")
        sess.client.return_value = sts_client

        accounts = [
            AccountInfo("222222222222", "Other", "b@x.com", "ACTIVE"),
        ]

        disc = EnvironmentDiscovery(sess)
        disc._check_assume_access(accounts, "111111111111")

        assert accounts[0].can_assume is False
        assert accounts[0].assume_error == "AccessDenied"


class TestDiscoveryResult:
    def test_properties(self):
        accounts = [
            AccountInfo("111", "A", "a@x", "ACTIVE", can_assume=True),
            AccountInfo("222", "B", "b@x", "ACTIVE", can_assume=False, assume_error="AccessDenied"),
            AccountInfo("333", "C", "c@x", "ACTIVE", can_assume=True),
        ]
        result = DiscoveryResult(
            is_org=True,
            current_account_id="111",
            org_id="o-test",
            accounts=accounts,
        )
        assert len(result.accessible_accounts) == 2
        assert len(result.inaccessible_accounts) == 1
        assert result.has_org_trail_access is False
        assert result.org_id == "o-test"


class TestCfnTemplate:
    def test_basic_template(self):
        template = generate_cfn_stackset_template("123456789012")
        assert "BreakBotReadOnly" in template
        assert "123456789012" in template
        assert "SecurityAudit" in template

    def test_with_external_id(self):
        template = generate_cfn_stackset_template("123456789012", external_id="secret-123")
        assert "secret-123" in template
        assert "ExternalId" in template
