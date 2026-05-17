"""
AWS Organizations support — multi-account scanning and auto-discovery.

Primitives:
  - OrganizationScanner       Lists accounts via organizations:ListAccounts
  - CrossAccountSessionFactory Assumes BreakBotReadOnly per account, caches sessions
  - EnvironmentDiscovery       Auto-detects org/single, trail, role access
"""
from breakbot.org.cross_account import (
    DEFAULT_MEMBER_ROLE,
    CrossAccountSessionFactory,
    OrganizationScanner,
)
from breakbot.org.discovery import (
    AccountInfo,
    DiscoveryResult,
    EnvironmentDiscovery,
    OrgTrailInfo,
    generate_cfn_stackset_template,
)

__all__ = [
    "DEFAULT_MEMBER_ROLE",
    "CrossAccountSessionFactory",
    "OrganizationScanner",
    "AccountInfo",
    "DiscoveryResult",
    "EnvironmentDiscovery",
    "OrgTrailInfo",
    "generate_cfn_stackset_template",
]
