# Scanner — Phase 2

Discovers every AWS resource in the target account and normalizes it into
a `Resource` pydantic model. Each scanner covers one domain. The graph builder
downstream consumes this output — it doesn't talk to AWS directly.

---

## Architecture

<pre>
<a href="base.py"><b>BaseScanner</b></a> (abstract)
│   scan(regions)  ← orchestrates multi-region, error isolation, timing
│   _scan_region() ← implemented by each subclass
│
├── <a href="compute.py"><b>ComputeScanner</b></a>    EC2 instances + Lambda functions
├── <a href="networking.py"><b>NetworkingScanner</b></a>  VPC + subnets + SGs + ALBs
├── <a href="data.py"><b>DataScanner</b></a>       S3 buckets + RDS instances
└── <a href="identity.py"><b>IdentityScanner</b></a>   IAM roles + users + policy documents
</pre>

### BaseScanner contract

Every scanner subclass:
1. Declares a `domain: str` class attribute (used in logs and CLI `--domain` flag)
2. Implements `_scan_region(region: str) -> list[Resource]`
3. Optionally sets `is_global = True` for services that aren't regional (IAM)

The base class handles:
- Iterating across all enabled regions
- Catching per-region exceptions so one failed region doesn't kill the whole scan
- Collecting errors into `scanner.errors` (partial results beat nothing)
- Logging timing per region

---

## Scanners

### ComputeScanner — [`compute.py`](compute.py)

```
EC2 instances
  instance_id, instance_type, state
  vpc_id, subnet_id, private_ip, public_ip
  security_group_ids            ← drives attached_to_sg edges in graph
  iam_instance_profile_arn      ← drives has_instance_profile edges
  imds_v1_allowed               ← IMDSv1 is a known SSRF escalation vector
  ami_id, key_name

Lambda functions
  function_name, runtime, handler
  role_arn                      ← drives has_execution_role edges in graph
  vpc_id, subnet_ids, security_group_ids
  in_vpc
  env_var_keys                  ← keys only, values go to secrets scanner
  env_var_count
  layers, last_modified
```

Key design decision: Lambda environment variable **values** are not stored
at this layer. The keys are captured (to flag suspicious names like `DB_PASSWORD`)
but the values are only read by the dedicated secrets scanner to avoid
accidentally logging secrets.

---

### NetworkingScanner — [`networking.py`](networking.py)

```
VPCs
  vpc_id, cidr_block, is_default, state

Security Groups
  group_id, group_name, vpc_id
  ingress_rules[]               ← structured: protocol, from_port, to_port,
  egress_rules[]                   cidrs, ipv6_cidrs, referenced_sgs
  internet_exposed              ← True if ANY ingress rule has 0.0.0.0/0

Application Load Balancers
  LoadBalancerArn, scheme       ← "internet-facing" flags as entry point
  vpc_id, dns_name
  security_group_ids            ← drives attached_to_sg edges
  availability_zones, state
```

The `ingress_rules[].referenced_sgs` field is what enables `network_can_reach`
edge inference in the graph builder. When SG-B's ingress rule references SG-A,
instances in SG-A can reach instances in SG-B — a lateral movement path.

The `internet_exposed` boolean is pre-computed here so the graph builder can
find internet entry points in O(1) without reparsing every rule.

---

### DataScanner — [`data.py`](data.py)

```
S3 Buckets  (global — scanned once regardless of how many regions are targeted)
  bucket_name, region
  public_access_block           ← all 4 flags: BlockPublicAcls, IgnorePublicAcls,
                                   BlockPublicPolicy, RestrictPublicBuckets
  has_bucket_policy             ← boolean
  bucket_policy                 ← full parsed JSON document
  is_encrypted                  ← any SSE configured
  versioning_status

RDS Instances  (regional)
  db_instance_id, engine, engine_version, instance_class
  publicly_accessible           ← direct internet exposure flag
  storage_encrypted
  endpoint_address, endpoint_port
  vpc_id, vpc_security_group_ids ← drives attached_to_sg edges
  iam_database_auth_enabled
  deletion_protection
```

S3 is a global service but boto3's `list_buckets` call returns all buckets
regardless of region. The scanner resolves each bucket's actual region via
`get_bucket_location` and scans S3 exactly once using a `_s3_scanned` flag,
avoiding duplicate discovery when scanning multiple regions.

Per-bucket calls (`get_public_access_block`, `get_bucket_policy`, etc.) can
fail independently — e.g., `AccessDenied` on a cross-account bucket or
`NoSuchBucketPolicy` when no policy is set. These are treated as "absent",
not errors, so a partial S3 inventory is still returned.

---

### IdentityScanner — [`identity.py`](identity.py)

The most important scanner. IAM is the backbone of almost every attack chain.

```
IAM Roles
  role_name, role_id, path
  trust_policy                  ← full AssumeRolePolicyDocument (JSON)
                                   drives iam_can_assume edges
  managed_policies[]            ← name, ARN, is_aws_managed, document
                                   document = full policy version JSON,
                                   drives iam_can_access edges
  inline_policies[]             ← name, document
                                   drives iam_can_access edges
  max_session_duration

IAM Users
  user_name, user_id, path
  create_date
  access_keys[]                 ← metadata only: id, status, create_date
  has_active_access_keys        ← long-lived static credentials = risk
  mfa_enabled
  groups[]
```

**Policy document fetching:**
Managed policy documents are fetched at scan time (not deferred to the graph
builder). This requires two extra API calls per policy:
`iam:GetPolicy` → get default version ID, then `iam:GetPolicyVersion` → get document.

A per-scanner `_policy_doc_cache` dict ensures the same AWS-managed policy
(e.g., `AdministratorAccess`) is only fetched once even if it's attached to
hundreds of roles.

**Why we need the documents:**
Without the policy documents, the graph builder can only build `iam_can_assume`
edges (from trust policies). The `iam_can_access` edges — which show what each
role can *do* — require parsing the Allow statements in each policy document.
These are the edges that reveal "Role X can read S3 bucket Y", which is the
critical link in most attack chains.

---

## Running a Single Domain

```bash
# Scan only IAM identity (fast, global)
breakbot scan --profile breakbot --domain identity

# Scan only networking in one region
breakbot scan --profile breakbot --region eu-west-1 --domain networking

# Full scan of all regions
breakbot scan --profile breakbot --all-regions
```

---

## Output Format

Each scanner writes to `scans/{scan_id}/{resource_type}.json`:

```json
[
  {
    "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
    "resource_type": "ec2:instance",
    "name": "prod-web-server",
    "region": "us-east-1",
    "account_id": "123456789012",
    "tags": { "Env": "prod", "Team": "platform" },
    "properties": {
      "instance_type": "t3.medium",
      "public_ip": "54.1.2.3",
      "is_public": true,
      "security_group_ids": ["sg-111aaa"],
      "iam_instance_profile_arn": "arn:aws:iam::123456789012:instance-profile/AppRole",
      "imds_v1_allowed": true
    }
  }
]
```

---

## Error Handling

Errors are non-fatal by design:

- A single region failing (opt-in regions, transient throttle) doesn't stop the scan
- A single resource failing inspection (e.g., permission denied on one S3 bucket) doesn't skip the rest
- All errors are collected in `scanner.errors` and written to `scan.json`

This means you always get partial results. The LLM report will note coverage gaps.

---

## Adding a New Scanner

1. Create `scanner/newdomain.py`
2. Subclass [`BaseScanner`](base.py)
3. Implement `_scan_region(region) -> list[Resource]`
4. Add any new `ResourceType` variants to [`models/resource.py`](../models/resource.py)
5. Register in [`scanner/__init__.py`](__init__.py) and [`cli/main.py`](../cli/main.py)

See [`compute.py`](compute.py) as the reference implementation.
