"""
Cognito scanner — user pools.

Cognito user pools are regional (unlike IAM), so this scanner runs per region.

Key properties for security analysis:
  - mfa_required = False         → users authenticate with password only
  - advanced_security_mode = OFF → no adaptive auth, no compromised-credential checks
  - deletion_protection = False  → pool can be deleted without confirmation
  - password_min_length < 12     → weak password policy
  - lambda_trigger_count > 0     → pre/post-auth Lambda hooks (can be attack surface
                                    if the Lambda has permissive IAM role)
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class CognitoScanner(BaseScanner):
    domain = "cognito"

    def _scan_region(self, region: str) -> list[Resource]:
        cognito = self.session.client("cognito-idp", region=region)
        resources: list[Resource] = []

        pool_ids: list[str] = []
        try:
            paginator = cognito.get_paginator("list_user_pools")
            for page in paginator.paginate(MaxResults=60):
                for pool in page.get("UserPools", []):
                    pool_ids.append(pool["Id"])
        except ClientError as e:
            logger.warning(
                "Cognito ListUserPools failed in %s: %s",
                region,
                e.response["Error"]["Code"],
            )
            raise

        for pool_id in pool_ids:
            try:
                resp = cognito.describe_user_pool(UserPoolId=pool_id)
                resources.append(self._normalize_user_pool(resp["UserPool"], region))
            except ClientError as e:
                logger.warning(
                    "DescribeUserPool %s failed: %s",
                    pool_id,
                    e.response["Error"]["Code"],
                )

        return resources

    def _normalize_user_pool(self, pool: dict, region: str) -> Resource:
        pool_id = pool["Id"]
        arn = pool.get(
            "Arn",
            f"arn:aws:cognito-idp:{region}:{self.session.account_id}:userpool/{pool_id}",
        )
        name = pool.get("Name", pool_id)

        mfa_config = pool.get("MfaConfiguration", "OFF")
        pwd_policy = (pool.get("Policies") or {}).get("PasswordPolicy") or {}
        addons = pool.get("UserPoolAddOns") or {}

        # Lambda triggers are keys in LambdaConfig whose values are Lambda ARNs
        lambda_config = pool.get("LambdaConfig") or {}
        trigger_arns = [v for v in lambda_config.values() if isinstance(v, str) and v.startswith("arn:")]

        properties = {
            "pool_name": name,
            "pool_id": pool_id,
            "status": pool.get("Status"),
            "mfa_configuration": mfa_config,
            "mfa_required": mfa_config == "ON",
            "advanced_security_mode": addons.get("AdvancedSecurityMode", "OFF"),
            "deletion_protection": pool.get("DeletionProtection") == "ACTIVE",
            "password_min_length": pwd_policy.get("MinimumLength", 8),
            "password_require_uppercase": pwd_policy.get("RequireUppercase", False),
            "password_require_lowercase": pwd_policy.get("RequireLowercase", False),
            "password_require_numbers": pwd_policy.get("RequireNumbers", False),
            "password_require_symbols": pwd_policy.get("RequireSymbols", False),
            "lambda_trigger_count": len(trigger_arns),
            "lambda_trigger_arns": trigger_arns,
            "estimated_user_count": pool.get("EstimatedNumberOfUsers", 0),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.COGNITO_USER_POOL,
            name=name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )
