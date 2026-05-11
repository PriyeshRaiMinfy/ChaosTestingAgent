# BreakBot

```
  ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗██████╗  ██████╗ ████████╗
  ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
  ██████╔╝██████╔╝█████╗  ███████║█████╔╝ ██████╔╝██║   ██║   ██║
  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══██╗██║   ██║   ██║
  ██████╔╝██║  ██║███████╗██║  ██║██║  ██╗██████╔╝╚██████╔╝   ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝    ╚═╝
```

> **Read-only AWS security agent.** Scans your account, builds a dependency graph,
> and uses Claude to reason like a red team engineer — finding the attack chains
> that GuardDuty, Inspector, and Config never surface because they look at
> resources in isolation.

---

## The Problem

AWS security tools are **reactive and isolated**:

| Tool | What it does | What it misses |
|---|---|---|
| GuardDuty | Detects known-bad patterns in logs | Doesn't chain findings together |
| Inspector | Finds CVEs in EC2/Lambda | Doesn't know if that instance has a broad IAM role |
| Config | Flags misconfigured resources | Can't say "this misconfiguration + that policy = breach path" |
| Security Hub | Aggregates findings | Still a list, not a graph |

A real attacker doesn't exploit one finding — they chain three mediocre ones.
BreakBot builds the chain.

---

## How It Works — Full Pipeline

```
╔══════════════════════════════════════════════════════════════════════════╗
║                          YOUR AWS ACCOUNT                                ║
║                                                                          ║
║   EC2  Lambda  IAM  S3  RDS  VPC  ALB  SG  Secrets  CloudTrail         ║
╚══════════════════════════╦═══════════════════════════════════════════════╝
                           ║  boto3  (read-only credentials — zero writes)
                           ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                        PHASE 2 — SCANNER                                 ║
║                                                                          ║
║  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────┐    ║
║  │    COMPUTE      │  │   NETWORKING    │  │        DATA          │    ║
║  │  EC2 instances  │  │   VPCs/Subnets  │  │    S3 buckets        │    ║
║  │  Lambda fns     │  │   Security grps │  │    RDS instances     │    ║
║  │  AMIs, ECS, EKS │  │   ALBs / NLBs  │  │    DynamoDB tables   │    ║
║  └─────────────────┘  └─────────────────┘  └──────────────────────┘    ║
║                                                                          ║
║  ┌──────────────────────────────────────────────────────────────────┐   ║
║  │                         IDENTITY                                  │   ║
║  │    IAM roles (trust policy + all attached policy documents)       │   ║
║  │    IAM users (access keys metadata, MFA status, group membership) │   ║
║  └──────────────────────────────────────────────────────────────────┘   ║
╚══════════════════════════╦═══════════════════════════════════════════════╝
                           ║  ScanResult  →  scans/{id}/*.json
                           ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                    PHASE 4 — GRAPH BUILDER                               ║
║                                                                          ║
║   Every resource becomes a NODE (keyed by ARN).                         ║
║   Relationships become typed directed EDGES:                             ║
║                                                                          ║
║   iam_can_assume      trust policy principal  ──►  IAM role             ║
║   iam_can_access      IAM role                ──►  S3 / RDS / secrets   ║
║   has_execution_role  Lambda / EC2            ──►  IAM role             ║
║   has_instance_profile  EC2                   ──►  IAM role             ║
║   attached_to_sg      EC2 / Lambda / RDS      ──►  Security group       ║
║   network_can_reach   Security group          ──►  Security group       ║
║   internet_exposes    INTERNET (virtual)      ──►  Security group       ║
║   in_vpc              Lambda / RDS / EC2      ──►  VPC                  ║
║                                                                          ║
║   Example attack chain encoded as a graph path:                         ║
║                                                                          ║
║   INTERNET ──[internet_exposes]──► sg-web                               ║
║       sg-web ──[network_can_reach]──► sg-app                            ║
║       sg-app  ◄──[attached_to_sg]── Lambda:api-handler                  ║
║       Lambda:api-handler ──[has_execution_role]──► IAM:AppRole          ║
║       IAM:AppRole ──[iam_can_access s3:*]──► S3:customer-data           ║
╚══════════════════════════╦═══════════════════════════════════════════════╝
                           ║  networkx.MultiDiGraph
                           ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                    PHASE 4 — SERIALIZER / FILTER                         ║
║                                                                          ║
║   1. Identify entry points  (internet-facing ALB, public EC2, open S3)  ║
║   2. Identify sinks         (RDS, S3 buckets, admin IAM roles)          ║
║   3. Find simple paths      (BFS entry → sink, cutoff = 5 hops)         ║
║   4. Emit compact text      (~10× token-efficient vs raw JSON)           ║
║                                                                          ║
║   NODE 'api-handler' [lambda:function] role=AppRole in_vpc=true         ║
║   NODE 'customer-data' [s3:bucket] public=true encrypted=false          ║
║   EDGE 'api-handler' --[has_execution_role]--> 'AppRole'                ║
║   EDGE 'AppRole' --[iam_can_access actions=[s3:*]]--> 'customer-data'   ║
╚══════════════════════════╦═══════════════════════════════════════════════╝
                           ║  attack_surface.txt  (LLM-ready)
                           ▼
╔══════════════════════════════════════════════════════════════════════════╗
║                      PHASE 5 — LLM BRAIN                                 ║
║                                                                          ║
║   Model:  claude-sonnet-4-6  /  opus-4-7                                ║
║   Persona: Senior red team cloud security engineer                       ║
║                                                                          ║
║   For each attack path, Claude outputs:                                  ║
║     • entry_point   — where the attacker gets in                        ║
║     • steps[]       — (from_node, to_node, technique, evidence)         ║
║     • blast_radius  — what can be reached / damaged                     ║
║     • severity      — 0-10 score                                        ║
║     • confidence    — how certain the reasoning is                      ║
║     • remediation   — specific fix with code/policy snippet             ║
╚══════════════════════════╦═══════════════════════════════════════════════╝
                           ║
               ┌───────────┴────────────┐
               ▼                        ▼
        report.md                  graph.html
    (Markdown report)        (interactive pyvis viz,
     entry points +           colour-coded by type,
     kill chains +             click-to-inspect nodes)
     remediation steps
```

---

## Project Layout

```
Phase1-VulnarabilitiReport/
│
├── pyproject.toml                  ← Package config, deps, CLI entry point
│
├── src/breakbot/
│   │
│   ├── models/                     ← Pydantic schemas (the data contracts)
│   │   └── resource.py             ← Resource, ResourceType, ScanResult
│   │
│   ├── utils/                      ← Shared infrastructure
│   │   └── aws_session.py          ← Boto3 session, client cache, retry config
│   │
│   ├── scanner/                    ← AWS resource discovery (Phase 2)
│   │   ├── base.py                 ← Abstract base — multi-region orchestration
│   │   ├── compute.py              ← EC2 instances + Lambda functions
│   │   ├── networking.py           ← VPC, subnets, security groups, ALBs
│   │   ├── data.py                 ← S3 buckets + RDS instances
│   │   └── identity.py             ← IAM roles, users, policy documents
│   │
│   ├── graph/                      ← Dependency graph construction (Phase 4)
│   │   ├── edges.py                ← EdgeType enum + INTERNET virtual node
│   │   ├── builder.py              ← GraphBuilder — infers all edges from scan
│   │   ├── serializer.py           ← GraphSerializer — compact LLM-ready text
│   │   └── visualize.py            ← pyvis HTML renderer (requires [viz] extra)
│   │
│   ├── brain/                      ← LLM attack-path reasoning (Phase 5 — TBD)
│   │   └── __init__.py
│   │
│   └── cli/
│       └── main.py                 ← typer CLI: `breakbot scan`, `breakbot graph`
│
└── tests/
    ├── unit/
    │   ├── test_compute_scanner.py ← moto-mocked scanner tests (3 tests)
    │   └── test_graph_builder.py   ← graph edge inference tests (14 tests)
    └── integration/                ← Real AWS tests (opt-in, needs creds)
```

---

## Quick Start

```bash
# 1. Install (uv recommended, or pip)
uv pip install -e ".[dev]"
# or: pip install -e ".[dev]"

# 2. Create a read-only IAM user in your AWS account
#    Attach the AWS-managed ReadOnlyAccess policy
#    Generate an access key + secret

# 3. Configure your AWS profile
aws configure --profile breakbot
# Enter: Access Key ID, Secret Access Key, region (e.g. us-east-1), output (json)

# 4. Validate the profile is actually read-only
breakbot validate --profile breakbot

# 5. Run a full scan
breakbot scan --profile breakbot --region us-east-1

# 6. Build the dependency graph from the scan
breakbot graph scans/scan-YYYYMMDD-HHMMSS-xxxxxx \
    --html graph.html \
    --serialize attack_surface.txt
```

---

## CLI Reference

```
breakbot scan      Run a read-only scan of the AWS account
  --profile   -p   AWS profile name (default: "default")
  --region    -r   Primary region (default: us-east-1)
  --all-regions    Scan every enabled region in the account
  --domain    -d   Restrict to one domain: compute | networking | data | identity
  --output    -o   Output directory (default: ./scans)
  --verbose   -v   Debug logging

breakbot graph     Build dependency graph from a completed scan
  SCAN_DIR         Path to scan output directory (required)
  --html           Save interactive HTML visualization
  --serialize -s   Save LLM-ready compact text
  --max-hops       Max path length for entry→sink search (default: 5)

breakbot validate  Verify credentials are actually read-only
  --profile   -p   AWS profile name
  --region    -r   Region to test
```

---

## Outputs

| File | What it is |
|---|---|
| `scans/{id}/scan.json` | Full scan result — all resources, all errors |
| `scans/{id}/ec2_instance.json` | Per-resource-type split for readability |
| `graph.html` | Interactive pyvis graph, colour-coded by resource type |
| `attack_surface.txt` | Compact text fed to the LLM |
| `report.md` | *(Phase 5)* Human-readable attack path report |

---

## Tech Stack

| Layer | Technology |
|---|---|
| AWS SDK | boto3 + botocore (adaptive retry, 10 attempts) |
| Data validation | Pydantic v2 |
| Graph | networkx.MultiDiGraph |
| CLI | typer + rich |
| LLM | Anthropic Claude API (claude-sonnet-4-6 / opus-4-7) |
| Visualization | pyvis (vis.js wrapper) |
| Testing | pytest + moto (AWS mocking) |
| Packaging | uv / pip, pyproject.toml |

---

## Status

- [x] Phase 1 — IAM read-only access + credential validation
- [x] Phase 2 — Scanners: compute, networking, data, identity
- [ ] Phase 3 — Observability: CloudTrail, VPC Flow Logs, X-Ray
- [x] Phase 4 — Dependency graph builder + serializer + visualizer
- [ ] Phase 5 — LLM brain: attack path reasoning via Claude API
- [ ] Phase 6 — Interfaces: FastAPI backend, React dashboard, MCP server
- [ ] Phase 7 — Testing & hardening: cost controls, LLM output validation

---

## Design Decisions

**Why read-only?** The scanner attaches only `ReadOnlyAccess`. It cannot create, modify,
or delete any resource. This makes it safe to run against production accounts.

**Why networkx?** The graph is built deterministically from API responses — no ML involved.
networkx gives us shortest-path algorithms, BFS, and subgraph extraction out of the box.

**Why not train a model?** Training needs labeled attack-path data that doesn't exist publicly.
Claude's reasoning over a well-structured graph outperforms fine-tuned smaller models for
this task. The "intelligence" is in the prompt pipeline, not the weights.

**Why compact text instead of JSON for the LLM?** A well-formatted flat text representation
is ~10× more token-efficient than nested JSON and produces better LLM reasoning because
the structure matches how a security engineer would describe a graph verbally.
