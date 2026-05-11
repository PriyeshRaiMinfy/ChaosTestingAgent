"""
Core pydantic models for normalized AWS resources.

Every scanner emits resources conforming to one of these models. This keeps
the graph builder downstream uniform — it doesn't care whether a node came
from EC2 or Lambda, only what its ARN, type, and properties are.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ResourceType(str, Enum):
    # Compute
    EC2_INSTANCE = "ec2:instance"
    LAMBDA_FUNCTION = "lambda:function"
    # Networking
    VPC = "ec2:vpc"
    SUBNET = "ec2:subnet"
    SECURITY_GROUP = "ec2:security-group"
    ALB = "elbv2:load-balancer"
    # Data
    S3_BUCKET = "s3:bucket"
    RDS_INSTANCE = "rds:db-instance"
    # Identity
    IAM_ROLE = "iam:role"
    IAM_POLICY = "iam:policy"
    IAM_USER = "iam:user"


class Resource(BaseModel):
    """
    Normalized AWS resource. Every scanner output conforms to this.

    The `properties` dict carries service-specific fields so we don't have to
    define 200 subclasses. Critical fields (ARN, type, name) are first-class
    for fast indexing during graph construction.
    """
    model_config = ConfigDict(extra="forbid")

    arn: str = Field(..., description="AWS ARN — unique identifier across the account")
    resource_type: ResourceType
    name: str
    region: str
    account_id: str
    tags: dict[str, str] = Field(default_factory=dict)
    properties: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def node_id(self) -> str:
        """Graph node ID. ARN is globally unique so we use it directly."""
        return self.arn


class ScanResult(BaseModel):
    """A scan's complete output — what gets serialized to JSON on disk."""
    scan_id: str
    account_id: str
    started_at: datetime
    completed_at: datetime | None = None
    regions_scanned: list[str]
    resources: list[Resource]
    errors: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def resource_count(self) -> int:
        return len(self.resources)
