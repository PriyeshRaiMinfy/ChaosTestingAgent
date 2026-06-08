"""Shared test fixtures — synthesize stacks once, reuse across all tests."""
import json
from pathlib import Path

import pytest
import aws_cdk as cdk
from aws_cdk.assertions import Template

from stacks.vault_account_stack import VaultAccountStack


def _load_config(env_name: str) -> dict:
    config_path = Path(__file__).parent.parent / "config" / f"{env_name}.json"
    return json.loads(config_path.read_text())


@pytest.fixture(scope="session")
def dev_template() -> Template:
    """Synthesized VaultAccountStack with dev config (1-day retention)."""
    app = cdk.App()
    config = _load_config("dev")
    stack = VaultAccountStack(app, "TestVaultDev", config=config)
    return Template.from_stack(stack)


@pytest.fixture(scope="session")
def prod_template() -> Template:
    """Synthesized VaultAccountStack with prod config (2555-day retention)."""
    app = cdk.App()
    config = _load_config("prod")
    stack = VaultAccountStack(app, "TestVaultProd", config=config)
    return Template.from_stack(stack)
