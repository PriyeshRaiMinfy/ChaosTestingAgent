"""
Copy Lane Lambda: Security Lake → WORM Vault

Trigger: S3 event notification on new object in Security Lake bucket
Action: Copy object to vault bucket WITH Object Lock retention header

The copy preserves:
  - Original key path (same partition structure)
  - OCSF Parquet format
  - Adds COMPLIANCE retention on the vault copy
  - Encrypts with vault KMS CMK
"""
import os
import logging
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

VAULT_BUCKET = os.environ["VAULT_BUCKET_NAME"]
VAULT_KMS_KEY_ARN = os.environ["VAULT_KMS_KEY_ARN"]
RETENTION_DAYS = int(os.environ["RETENTION_DAYS"])

s3 = boto3.client("s3")


def lambda_handler(event, context):
    """Process S3 event records — copy each new object to vault."""
    records = event.get("Records", [])
    copied = 0
    errors = 0

    for record in records:
        source_bucket = record["s3"]["bucket"]["name"]
        source_key = record["s3"]["object"]["key"]

        # Skip non-parquet (metadata files, etc.)
        if not source_key.endswith(".parquet"):
            logger.info("Skipping non-parquet: %s", source_key)
            continue

        try:
            _copy_to_vault(source_bucket, source_key)
            copied += 1
        except Exception:
            logger.exception("Failed to copy %s/%s", source_bucket, source_key)
            errors += 1

    logger.info("Copy complete. copied=%d errors=%d", copied, errors)
    return {"copied": copied, "errors": errors}


def _copy_to_vault(source_bucket: str, source_key: str) -> None:
    """Copy single object to vault with Object Lock retention."""
    retain_until = datetime.now(timezone.utc) + timedelta(days=RETENTION_DAYS)

    # Vault key mirrors source key for consistent partition structure
    vault_key = f"security-lake/{source_key}"

    s3.copy_object(
        CopySource={"Bucket": source_bucket, "Key": source_key},
        Bucket=VAULT_BUCKET,
        Key=vault_key,
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=VAULT_KMS_KEY_ARN,
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=retain_until,
        MetadataDirective="COPY",
    )

    logger.info(
        "Copied %s → %s/%s (retain until %s)",
        source_key,
        VAULT_BUCKET,
        vault_key,
        retain_until.isoformat(),
    )
