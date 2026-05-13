"""
AWS Organizations support — multi-account scanning.

Two primitives:
  - OrganizationScanner       Lists accounts via organizations:ListAccounts
  - CrossAccountSessionFactory Assumes BreakBotReadOnly per account, caches sessions
"""
from breakbot.org.cross_account import (
    DEFAULT_MEMBER_ROLE,
    CrossAccountSessionFactory,
    OrganizationScanner,
)

__all__ = [
    "DEFAULT_MEMBER_ROLE",
    "CrossAccountSessionFactory",
    "OrganizationScanner",
]
