#!/usr/bin/env python3
"""CDK app entry point — instantiates all stacks in deploy order."""
import json
from pathlib import Path

import aws_cdk as cdk

from stacks.vault_account_stack import VaultAccountStack
from stacks.security_lake_stack import SecurityLakeStack

app = cdk.App()

env_name = app.node.try_get_context("env") or "dev"
config_path = Path(__file__).parent / "config" / f"{env_name}.json"
config = json.loads(config_path.read_text())

env = cdk.Environment(
    account=config.get("account_id") or None,
    region=config.get("region", "ap-south-1"),
)

# Phase 0: WORM Vault — S3 + KMS + Object Lock
vault_stack = VaultAccountStack(
    app,
    "VaultAccountStack",
    env=env,
    config=config,
)

# Phase 1: Security Lake + native sources + copy lane
security_lake_stack = SecurityLakeStack(
    app,
    "SecurityLakeStack",
    env=env,
    config=config,
    vault_bucket_arn=vault_stack.vault.bucket_arn,
    vault_kms_key_arn=vault_stack.vault_key.key_arn,
)
security_lake_stack.add_dependency(vault_stack)

# Phase 2-3: Custom Sources (future)
# custom_sources_stack = CustomSourcesStack(app, "CustomSourcesStack", ...)

# Phase 4: Detection Rules + AI Correlation (future)
# detections_stack = DetectionsStack(app, "DetectionsStack", ...)

# Phase 5: Auto-Remediation (future)
# remediation_stack = RemediationStack(app, "RemediationStack", ...)

# Phase 6: Integrity Verification (future)
# integrity_stack = IntegrityStack(app, "IntegrityStack", ...)

app.synth()
