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
    # Container orchestration
    EKS_CLUSTER = "eks:cluster"
    EKS_NODEGROUP = "eks:nodegroup"
    EKS_FARGATE_PROFILE = "eks:fargate-profile"
    # Networking
    VPC = "ec2:vpc"
    SUBNET = "ec2:subnet"
    SECURITY_GROUP = "ec2:security-group"
    ALB = "elbv2:load-balancer"
    # Data stores
    S3_BUCKET = "s3:bucket"
    RDS_INSTANCE = "rds:db-instance"
    DYNAMODB_TABLE = "dynamodb:table"
    ELASTICACHE_CLUSTER = "elasticache:cluster"
    # Containers
    ECS_CLUSTER = "ecs:cluster"
    ECS_SERVICE = "ecs:service"
    ECS_TASK_DEFINITION = "ecs:task-definition"
    # Messaging and streaming
    SQS_QUEUE = "sqs:queue"
    SNS_TOPIC = "sns:topic"
    MSK_CLUSTER = "msk:cluster"
    KINESIS_STREAM = "kinesis:stream"
    # Secrets and key management
    SECRETS_MANAGER_SECRET = "secretsmanager:secret"
    SSM_PARAMETER = "ssm:parameter"
    KMS_KEY = "kms:key"
    # Identity
    IAM_ROLE = "iam:role"
    IAM_POLICY = "iam:policy"
    IAM_USER = "iam:user"
    COGNITO_USER_POOL = "cognito-idp:user-pool"
    # Security
    WAF_WEB_ACL = "wafv2:web-acl"
    # Extended networking
    NAT_GATEWAY = "ec2:nat-gateway"
    INTERNET_GATEWAY = "ec2:internet-gateway"
    LOAD_BALANCER_TARGET_GROUP = "elbv2:target-group"
    ROUTE_TABLE = "ec2:route-table"
    NETWORK_ACL = "ec2:network-acl"
    VPC_PEERING_CONNECTION = "ec2:vpc-peering-connection"
    # DNS
    ROUTE53_HOSTED_ZONE = "route53:hosted-zone"
    # API Gateway
    API_GATEWAY_REST_API = "apigateway:rest-api"
    API_GATEWAY_HTTP_API = "apigatewayv2:http-api"
    # CDN
    CLOUDFRONT_DISTRIBUTION = "cloudfront:distribution"
    # Serverless orchestration
    EVENTBRIDGE_RULE = "events:rule"
    STEP_FUNCTIONS_STATE_MACHINE = "states:state-machine"


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
    scanner_account_id: str = Field(
        ...,
        description="Account BreakBot ran from. In org mode this is the Audit account; "
                    "in single-account mode it equals the only entry in accounts_scanned.",
    )
    accounts_scanned: list[str] = Field(
        ...,
        description="Every account whose resources are included in this scan.",
    )
    started_at: datetime
    completed_at: datetime | None = None
    regions_scanned: list[str]
    resources: list[Resource]
    errors: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def resource_count(self) -> int:
        return len(self.resources)

    @property
    def is_org_scan(self) -> bool:
        return len(self.accounts_scanned) > 1
