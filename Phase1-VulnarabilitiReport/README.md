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

## Project Layout

```
Phase1-VulnarabilitiReport/
│
├── pyproject.toml                   package config, deps, CLI entry point
├── uv.lock                          locked dependency versions
│
└── src/breakbot/
    ├── models/                      Pydantic data contracts
    ├── utils/                       shared AWS session infrastructure
    ├── scanner/                     Phase 2 — AWS resource discovery
    ├── graph/                       Phase 4 — dependency graph + serializer
    ├── brain/                       Phase 5 — LLM reasoning  [TBD]
    └── cli/                         CLI commands (scan, graph, validate)
```

### Module index

| Module | Phase | What it does | Docs |
|---|:---:|---|---|
| [`src/breakbot/scanner/`](src/breakbot/scanner/) | 2 | Discovers EC2, Lambda, IAM, S3, RDS, VPC, SGs across all regions | [README →](src/breakbot/scanner/README.md) |
| [`src/breakbot/graph/`](src/breakbot/graph/) | 4 | Builds networkx dependency graph, infers 8 edge types, serializes for LLM | [README →](src/breakbot/graph/README.md) |
| [`src/breakbot/cli/`](src/breakbot/cli/) | 1–5 | `breakbot scan`, `breakbot graph`, `breakbot validate` | [README →](src/breakbot/cli/README.md) |
| [`src/breakbot/models/`](src/breakbot/models/) | — | `Resource`, `ResourceType`, `ScanResult` — shared data contracts | [README →](src/breakbot/models/README.md) |
| [`src/breakbot/utils/`](src/breakbot/utils/) | — | Boto3 session, client caching, adaptive retry config | [README →](src/breakbot/utils/README.md) |
| [`src/breakbot/brain/`](src/breakbot/brain/) | 5 | Claude API prompt pipeline — attack path reasoning | TBD |
| [`tests/unit/`](tests/unit/) | — | Moto-mocked unit tests — no real AWS calls | — |
| [`tests/integration/`](tests/integration/) | — | Real AWS integration tests (opt-in, needs creds) | — |

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

## Quick Start

```bash
# 1. Install  (uv is faster; pip also works)
uv pip install -e ".[dev]"

# 2. Create a read-only IAM user in AWS Console
#    → Attach the AWS-managed ReadOnlyAccess policy
#    → Generate Access Key ID + Secret Access Key

# 3. Configure an AWS profile for BreakBot
aws configure --profile breakbot

# 4. Confirm the profile is actually read-only (runs a positive + negative test)
breakbot validate --profile breakbot

# 5. Scan a region
breakbot scan --profile breakbot --region us-east-1

# 6. Build the dependency graph and get LLM-ready output
breakbot graph scans/scan-YYYYMMDD-HHMMSS-xxxxxx \
    --html    graph.html         \
    --serialize attack_surface.txt
```

---

## CLI Reference

```
breakbot scan       Run a read-only scan of the AWS account
  --profile   -p    AWS profile name           (default: "default")
  --region    -r    Primary region             (default: us-east-1)
  --all-regions     Scan every enabled region in the account
  --domain    -d    Restrict scan: compute | networking | data | identity
  --output    -o    Output directory           (default: ./scans)
  --verbose   -v    Debug-level logging

breakbot graph      Build dependency graph from a completed scan
  SCAN_DIR          Path to scan output directory  (required)
  --html            Save interactive HTML visualization
  --serialize -s    Save LLM-ready compact text
  --max-hops        Max path length for entry→sink BFS  (default: 5)
  --verbose   -v    Debug-level logging

breakbot validate   Verify credentials are read-only before scanning
  --profile   -p    AWS profile name
  --region    -r    Region to test
```

Full command docs: [cli/README.md →](src/breakbot/cli/README.md)

---

## Outputs

| File | What it is |
|---|---|
| `scans/{id}/scan.json` | Full `ScanResult` — all resources + all errors |
| `scans/{id}/ec2_instance.json` | Per-type split for human inspection |
| `graph.html` | Interactive pyvis graph, colour-coded by risk level |
| `attack_surface.txt` | Compact text fed to the LLM brain |
| `report.md` | *(Phase 5)* Human-readable attack path report with remediation |

---

## Tech Stack

| Layer | Technology |
|---|---|
| AWS SDK | `boto3` + `botocore` — adaptive retry, 10 max attempts |
| Data validation | `pydantic` v2 |
| Graph | `networkx.MultiDiGraph` |
| CLI | `typer` + `rich` |
| LLM | Anthropic Claude API — `claude-sonnet-4-6` / `opus-4-7` |
| Visualization | `pyvis` (vis.js wrapper) |
| Testing | `pytest` + `moto` (AWS service mocking) |
| Packaging | `uv` / `pip`, `pyproject.toml` |

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

**Why read-only?**
The scanner attaches only `ReadOnlyAccess`. It cannot create, modify, or delete
any resource. Safe to run against production accounts without approval gates.

**Why networkx instead of a graph database?**
The graph is built in-memory from a single scan result, lives for one analysis
session, and is never persisted across runs. `networkx` gives BFS, shortest-path,
and subgraph extraction out of the box — no server, no schema migration, no ops.

**Why not train a model?**
Training requires labeled attack-path datasets that don't exist publicly and
GPUs that a solo project doesn't have. Claude's out-of-the-box reasoning over
a well-structured graph outperforms any fine-tuned smaller model for this task.
The intelligence is in the prompt pipeline, not the weights.

**Why compact text instead of JSON for the LLM context?**
A flat text representation is ~10× more token-efficient than nested JSON and
produces better reasoning because the format mirrors how a security engineer
would verbally describe a dependency graph — not a data serialization format.
