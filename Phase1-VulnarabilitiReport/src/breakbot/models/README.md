# Models

Pydantic v2 schemas that form the **data contract** between every module in
BreakBot. A scanner emits `Resource` objects. The graph builder consumes them.
The CLI serializes them to disk as `ScanResult` JSON.

Nothing in the codebase passes raw boto3 dicts between modules — everything is
normalized into these models first.

---

## `Resource`

Represents one discovered AWS resource. Every scanner output is a list of these.

```python
class Resource(BaseModel):
    arn:           str            # Globally unique AWS ARN
    resource_type: ResourceType   # Enum — drives graph node type and file naming
    name:          str            # Human-readable name (tag "Name" or ID fallback)
    region:        str            # AWS region, or "global" for IAM/S3
    account_id:    str            # 12-digit AWS account ID
    tags:          dict[str, str] # All resource tags, flattened {Key: Value}
    properties:    dict[str, Any] # Service-specific fields (see scanner README)
    discovered_at: datetime       # UTC timestamp of discovery
```

`resource.node_id` — property that returns `arn`, used as the graph node key.

`properties` is intentionally a loose `dict[str, Any]` rather than hundreds of
subclasses. The scanner READMEs document exactly what each resource type puts
in its properties dict.

---

## `ResourceType`

String enum — each value matches the format `service:resource-type` which maps
to both the ARN service prefix and the output filename.

```python
class ResourceType(str, Enum):
    # Compute
    EC2_INSTANCE     = "ec2:instance"
    LAMBDA_FUNCTION  = "lambda:function"
    # Networking
    VPC              = "ec2:vpc"
    SUBNET           = "ec2:subnet"
    SECURITY_GROUP   = "ec2:security-group"
    ALB              = "elbv2:load-balancer"
    # Data
    S3_BUCKET        = "s3:bucket"
    RDS_INSTANCE     = "rds:db-instance"
    # Identity
    IAM_ROLE         = "iam:role"
    IAM_POLICY       = "iam:policy"
    IAM_USER         = "iam:user"
```

---

## `ScanResult`

The complete output of a `breakbot scan` run. Serialized to `scan.json`.

```python
class ScanResult(BaseModel):
    scan_id:         str            # "scan-YYYYMMDD-HHMMSS-xxxxxx"
    account_id:      str
    started_at:      datetime
    completed_at:    datetime | None
    regions_scanned: list[str]
    resources:       list[Resource]
    errors:          list[dict]     # Non-fatal errors collected during scan

    @property
    def resource_count(self) -> int: ...
```

**Loading a scan result:**
```python
from breakbot.models import ScanResult
from pathlib import Path

result = ScanResult.model_validate_json(
    Path("scans/scan-20250511-142300-a3f9b1/scan.json").read_text()
)
print(f"{result.resource_count} resources in account {result.account_id}")
```

---

## Design Notes

**Why one flat `Resource` model instead of EC2Resource, LambdaResource, etc.?**

Two reasons:
1. The graph builder and serializer treat all resources uniformly — they care
   about ARN, type, and a few well-known property keys. If we had 20 subclasses,
   every graph operation would need 20 isinstance checks.
2. Adding a new resource type (DynamoDB, ElastiCache, etc.) only requires adding
   a `ResourceType` enum value, not a new class.

The tradeoff is that `properties` is untyped — the scanner READMEs serve as
the documentation for what's in there.

**`model_config = ConfigDict(extra="forbid")`**
This is set on `Resource` so that if a scanner accidentally sends an unexpected
field, pydantic raises an error at construction time rather than silently
discarding it. Fail loud, fail early.
