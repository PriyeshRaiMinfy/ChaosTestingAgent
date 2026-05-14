"""
Secrets scanner — Secrets Manager, SSM Parameter Store, and KMS customer keys.
"""
from __future__ import annotations

import json
import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class SecretsScanner(BaseScanner):
    domain = "secrets"

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        resources.extend(self._safe_scan_call(
            "secretsmanager", "list_secrets", region,
            lambda: self._scan_secrets_manager(region),
        ))
        resources.extend(self._safe_scan_call(
            "ssm", "describe_parameters", region,
            lambda: self._scan_ssm_parameters(region),
        ))
        resources.extend(self._safe_scan_call(
            "kms", "list_keys", region,
            lambda: self._scan_kms_keys(region),
        ))
        return resources

    # ───────────────────── Secrets Manager ───────────────────────────────

    def _scan_secrets_manager(self, region: str) -> list[Resource]:
        sm = self.session.client("secretsmanager", region=region)
        paginator = sm.get_paginator("list_secrets")
        resources: list[Resource] = []
        for page in paginator.paginate():
            for secret in page["SecretList"]:
                try:
                    resources.append(self._normalize_secret(secret, region))
                except Exception as e:
                    logger.warning(
                        "[secrets] failed to normalize secret %s: %s",
                        secret.get("Name", "?"), e,
                    )
        return resources

    def _normalize_secret(self, secret: dict, region: str) -> Resource:
        arn = secret["ARN"]
        name = secret["Name"]
        tags = {t["Key"]: t["Value"] for t in secret.get("Tags", [])}

        kms_key_id = secret.get("KmsKeyId")
        kms_key_arn = _normalize_kms_ref(kms_key_id, region, self.session.account_id)

        properties = {
            "secret_name": name,
            "rotation_enabled": secret.get("RotationEnabled", False),
            "rotation_lambda_arn": secret.get("RotationLambdaARN"),
            "kms_key_arn": kms_key_arn,
            "last_rotated_date": _dt_str(secret.get("LastRotatedDate")),
            "last_accessed_date": _dt_str(secret.get("LastAccessedDate")),
            "last_changed_date": _dt_str(secret.get("LastChangedDate")),
            "deleted_date": _dt_str(secret.get("DeletedDate")),
            "primary_region": secret.get("PrimaryRegion"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.SECRETS_MANAGER_SECRET,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    # ───────────────────── SSM Parameter Store ────────────────────────────

    def _scan_ssm_parameters(self, region: str) -> list[Resource]:
        ssm = self.session.client("ssm", region=region)
        paginator = ssm.get_paginator("describe_parameters")
        resources: list[Resource] = []
        for page in paginator.paginate():
            for param in page["Parameters"]:
                try:
                    resources.append(self._normalize_ssm_parameter(param, region))
                except Exception as e:
                    logger.warning(
                        "[secrets] failed to normalize SSM param %s: %s",
                        param.get("Name", "?"), e,
                    )
        return resources

    def _normalize_ssm_parameter(self, param: dict, region: str) -> Resource:
        name = param["Name"]
        normalized_name = name.lstrip("/")
        arn = f"arn:aws:ssm:{region}:{self.session.account_id}:parameter/{normalized_name}"

        kms_key_id = param.get("KeyId")
        kms_key_arn = _normalize_kms_ref(kms_key_id, region, self.session.account_id)

        properties = {
            "parameter_name": name,
            "type": param.get("Type"),
            "tier": param.get("Tier"),
            "data_type": param.get("DataType"),
            "kms_key_arn": kms_key_arn,
            "is_encrypted": param.get("Type") == "SecureString",
            "last_modified_date": _dt_str(param.get("LastModifiedDate")),
            "version": param.get("Version"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.SSM_PARAMETER,
            name=name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )

    # ───────────────────────── KMS Keys ──────────────────────────────────

    def _scan_kms_keys(self, region: str) -> list[Resource]:
        kms = self.session.client("kms", region=region)
        paginator = kms.get_paginator("list_keys")
        resources: list[Resource] = []
        for page in paginator.paginate():
            for key_entry in page["Keys"]:
                key_arn = key_entry["KeyArn"]
                key_id = key_entry["KeyId"]
                try:
                    resource = self._inspect_kms_key(kms, key_id, key_arn, region)
                    if resource:
                        resources.append(resource)
                except ClientError as e:
                    code = e.response["Error"]["Code"]
                    # Keys pending deletion or in different regions can fail
                    if code not in ("NotFoundException", "KMSInvalidStateException"):
                        logger.warning("KMS DescribeKey %s failed: %s", key_id, code)
                except Exception as e:
                    logger.warning(
                        "[secrets] failed to inspect KMS key %s: %s", key_id, e,
                    )
        return resources

    def _inspect_kms_key(
        self, kms, key_id: str, key_arn: str, region: str
    ) -> Resource | None:
        desc_resp = kms.describe_key(KeyId=key_id)
        meta = desc_resp["KeyMetadata"]

        key_state = meta.get("KeyState")
        key_manager = meta.get("KeyManager")
        key_spec = meta.get("KeySpec", meta.get("CustomerMasterKeySpec", "SYMMETRIC_DEFAULT"))
        origin = meta.get("Origin")

        rotation_enabled: bool | None = None
        if key_manager == "CUSTOMER" and key_spec == "SYMMETRIC_DEFAULT" and origin == "AWS_KMS":
            try:
                rot_resp = kms.get_key_rotation_status(KeyId=key_id)
                rotation_enabled = rot_resp.get("KeyRotationEnabled", False)
            except ClientError:
                pass

        key_policy: dict | None = None
        try:
            policy_resp = kms.get_key_policy(KeyId=key_id, PolicyName="default")
            key_policy = json.loads(policy_resp["Policy"])
        except ClientError:
            pass

        aliases: list[str] = []
        try:
            alias_resp = kms.list_aliases(KeyId=key_id)
            aliases = [a["AliasName"] for a in alias_resp.get("Aliases", [])]
        except ClientError:
            pass

        display_name = aliases[0] if aliases else key_id

        properties = {
            "key_id": key_id,
            "key_state": key_state,
            "key_manager": key_manager,
            "key_usage": meta.get("KeyUsage"),
            "key_spec": key_spec,
            "origin": origin,
            "enabled": meta.get("Enabled", False),
            "rotation_enabled": rotation_enabled,
            "multi_region": meta.get("MultiRegion", False),
            "deletion_date": _dt_str(meta.get("DeletionDate")),
            "valid_to": _dt_str(meta.get("ValidTo")),
            "description": meta.get("Description", ""),
            "aliases": aliases,
            "key_policy": key_policy,
            "is_customer_managed": key_manager == "CUSTOMER",
        }

        return Resource(
            arn=key_arn,
            resource_type=ResourceType.KMS_KEY,
            name=display_name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )


# ──────────────────────────── Helpers ─────────────────────────────────────


def _normalize_kms_ref(
    key_ref: str | None, region: str, account_id: str
) -> str | None:
    if not key_ref:
        return None
    if key_ref.startswith("arn:aws") and ":key/" in key_ref:
        return key_ref
    if key_ref.startswith("arn:") or key_ref.startswith("alias/"):
        return None
    if len(key_ref) == 36 and key_ref.count("-") == 4:
        return f"arn:aws:kms:{region}:{account_id}:key/{key_ref}"
    return None


def _dt_str(value) -> str | None:
    if value is None:
        return None
    try:
        return value.isoformat()
    except AttributeError:
        return str(value)
