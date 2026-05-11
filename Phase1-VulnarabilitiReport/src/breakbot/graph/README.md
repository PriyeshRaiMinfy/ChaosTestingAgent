# Graph — Phase 4

Converts a flat list of scanned resources into a directed dependency graph,
then serializes that graph into a compact format optimised for LLM reasoning.

---

## Files

```
graph/
├── edges.py       EdgeType enum + INTERNET virtual node constant
├── builder.py     GraphBuilder — constructs the networkx graph from ScanResult
├── serializer.py  GraphSerializer — filters to attack surface, emits compact text
└── visualize.py   render_html() — interactive pyvis HTML output
```

---

## The Graph Model

```
networkx.MultiDiGraph

Node  = one AWS resource (key = ARN)
        or a virtual node (INTERNET)

Edge  = a typed relationship between two resources
        multiple parallel edges allowed (MultiDiGraph)
        each edge carries: edge_type, label, + type-specific attributes
```

### Node attributes

Scalar properties from the `Resource.properties` dict are stored directly
as node attributes. Complex nested structures (dicts, lists) are only
in `builder.arn_index[arn].properties` — accessible via the arn_index.

Important scalar attributes per type:

| Resource type | Key node attributes |
|---|---|
| EC2 instance | `is_public`, `imds_v1_allowed`, `iam_instance_profile_arn` |
| Lambda | `role_arn`, `in_vpc`, `runtime`, `env_var_count` |
| IAM Role | `has_wildcard_resource_access`, `wildcard_actions` |
| S3 Bucket | *(complex — accessed via arn_index)* |
| RDS Instance | `publicly_accessible`, `storage_encrypted`, `engine` |
| Security Group | `internet_exposed`, `vpc_id` |
| ALB | `is_internet_facing`, `dns_name` |

---

## Edge Types

```
iam_can_assume
  From: trust policy principal (service / role ARN / "*")
  To:   IAM role
  Means: the principal can call sts:AssumeRole on this role
  Source: role.properties["trust_policy"]["Statement"]

has_execution_role
  From: Lambda function
  To:   IAM role
  Means: Lambda runs with this role's permissions
  Source: lambda.properties["role_arn"]

has_instance_profile
  From: EC2 instance
  To:   IAM role (resolved by name match from instance profile ARN)
  Means: EC2 can call AWS APIs with this role's permissions
  Source: ec2.properties["iam_instance_profile_arn"]

iam_can_access
  From: IAM role
  To:   target resource (S3, RDS, Secrets Manager, etc.)
  Attrs: actions[], resource_pattern, policy_type, policy_name,
         is_wildcard_resource, is_admin, has_conditions
  Means: the role's policies grant access to this resource
  Source: inline_policies + managed_policies documents

attached_to_sg
  From: EC2 / Lambda / RDS / ALB
  To:   Security group
  Means: the resource is assigned to this security group
  Source: resource.properties["security_group_ids"]

network_can_reach
  From: Security group A
  To:   Security group B
  Attrs: from_port, to_port, protocol
  Means: instances in SG-A can send traffic to instances in SG-B
         (SG-B has an ingress rule referencing SG-A)
  Source: sg.properties["ingress_rules"][].referenced_sgs

internet_exposes
  From: INTERNET (virtual node)
  To:   Security group
  Attrs: from_port, to_port, protocol
  Means: the internet can send traffic through this SG (0.0.0.0/0 ingress)
  Source: sg.properties["ingress_rules"] where cidrs contains "0.0.0.0/0"

in_vpc
  From: Lambda / RDS / EC2
  To:   VPC
  Means: the resource lives inside this VPC
  Source: resource.properties["vpc_id"]
```

---

## Attack Chain Example

Given this AWS setup:
- ALB (internet-facing) → sg-web
- EC2 instance in sg-web and sg-app
- EC2 has instance profile `AppRole`
- `AppRole` has inline policy: `s3:*` on `customer-data` bucket

The graph encodes this as:

```
INTERNET ──[internet_exposes port=443]──► sg-web
EC2:web-server ──[attached_to_sg]──► sg-web
EC2:web-server ──[attached_to_sg]──► sg-app
EC2:web-server ──[has_instance_profile]──► IAM:AppRole
IAM:AppRole ──[iam_can_access actions=[s3:*]]──► S3:customer-data
```

The serializer's BFS from `INTERNET` to `S3:customer-data` finds this path
in ≤5 hops and includes it in `attack_surface.txt` for the LLM to reason over.

---

## GraphBuilder

```python
from breakbot.graph import GraphBuilder
from breakbot.models import ScanResult

result = ScanResult.model_validate_json(Path("scans/.../scan.json").read_text())

builder = GraphBuilder(result)
graph   = builder.build()         # networkx.MultiDiGraph
arn_idx = builder.arn_index       # dict[str, Resource]
```

`build()` runs 8 inference passes in order:

```
1. _build_indexes()          ← build ARN / SG-ID / role-name / VPC-ID lookup dicts
2. _add_all_nodes()          ← add every resource + INTERNET virtual node
3. _add_iam_trust_edges()    ← iam_can_assume (from trust policies)
4. _add_compute_role_edges() ← has_execution_role + has_instance_profile
5. _add_sg_attachment_edges() ← attached_to_sg
6. _add_network_reachability_edges() ← network_can_reach
7. _add_internet_exposure_edges()   ← internet_exposes
8. _add_iam_policy_access_edges()   ← iam_can_access
9. _add_vpc_membership_edges()      ← in_vpc
```

---

## GraphSerializer

```python
from breakbot.graph import GraphSerializer

serializer = GraphSerializer(graph, arn_index, max_hops=5)

# Stats summary (for CLI table output)
print(serializer.stats())
# {"total_nodes": 47, "total_edges": 83, "entry_points": 3, "sinks": 5, ...}

# Full LLM-ready text
text = serializer.serialize()

# Save to file
serializer.save(Path("attack_surface.txt"))
```

**Entry point detection:**
- ALBs with `is_internet_facing=True`
- EC2 instances with a public IP
- S3 buckets without a complete public access block
- Any compute resource attached to a SG reachable from `INTERNET`

**Sink detection:**
- All RDS instances (always hold data)
- All S3 buckets (potential data exfiltration target)
- IAM roles with `has_wildcard_resource_access=True` (admin / privilege escalation)

**Path finding:**
`networkx.all_simple_paths(graph, src, dst, cutoff=max_hops)` — returns all
simple (non-repeating) paths. Capped at 3 paths per (entry, sink) pair to
avoid token explosion in accounts with thousands of resources.

---

## Visualization

Requires the `viz` extra: `pip install breakbot[viz]`

```python
from breakbot.graph.visualize import render_html
from pathlib import Path

render_html(graph, Path("graph.html"))
```

```
Colour coding:
  Red     ── INTERNET virtual node + admin IAM roles
  Orange  ── Compute (EC2, Lambda, RDS)
  Yellow  ── Data stores (S3)
  Teal    ── Identity (IAM roles, users)
  Blue    ── Networking (VPC, SG, ALB)
  Grey    ── External principals / unknown nodes

Edge width:
  Thick   ── internet_exposes, iam_can_access (high-risk)
  Normal  ── all other edge types
```

Or via CLI:
```bash
breakbot graph scans/scan-... --html graph.html
```

---

## Known Limitations

| Limitation | Impact | Planned fix |
|---|---|---|
| Managed policy docs not fetched for `is_global=False` scanners before Phase 4 | None — IdentityScanner fetches them | Already resolved |
| Instance profile → role resolution is name-based (best-effort) | Unresolved profiles appear as dangling nodes | Add `list_instance_profiles` to IdentityScanner |
| `Resource: "*"` policies set a node flag, not an edge | Admin roles look less connected in viz | Phase 5 will highlight this in text output |
| No behavioral edges yet (CloudTrail / X-Ray) | Graph is static — doesn't show what *actually* happened | Phase 3 overlay |
