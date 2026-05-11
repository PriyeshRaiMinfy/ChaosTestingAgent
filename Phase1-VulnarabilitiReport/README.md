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

<pre>
Phase1-VulnarabilitiReport/
│
├── <a href="pyproject.toml">pyproject.toml</a>                   package config, deps, CLI entry point
├── <a href="uv.lock">uv.lock</a>                          locked dependency versions
│
└── src/breakbot/
    │
    ├── <a href="src/breakbot/models/"><b>models/</b></a>          ← Pydantic data contracts  (<a href="src/breakbot/models/README.md">README</a>)
    │   └── resource.py          Resource · ResourceType · ScanResult
    │
    ├── <a href="src/breakbot/utils/"><b>utils/</b></a>           ← shared AWS session infrastructure  (<a href="src/breakbot/utils/README.md">README</a>)
    │   └── aws_session.py       boto3 session · client cache · retry config
    │
    ├── <a href="src/breakbot/scanner/"><b>scanner/</b></a>         ← Phase 2 — AWS resource discovery  (<a href="src/breakbot/scanner/README.md">README</a>)
    │   ├── base.py              abstract base — multi-region orchestration
    │   ├── compute.py           EC2 instances · Lambda functions
    │   ├── networking.py        VPCs · subnets · security groups · ALBs
    │   ├── data.py              S3 buckets · RDS instances
    │   └── identity.py          IAM roles · users · policy documents
    │
    ├── <a href="src/breakbot/graph/"><b>graph/</b></a>           ← Phase 4 — dependency graph + serializer  (<a href="src/breakbot/graph/README.md">README</a>)
    │   ├── edges.py             EdgeType enum · INTERNET virtual node
    │   ├── builder.py           GraphBuilder — infers 8 edge types from scan
    │   ├── serializer.py        GraphSerializer — compact LLM-ready text
    │   └── visualize.py         pyvis HTML renderer
    │
    ├── <a href="src/breakbot/brain/"><b>brain/</b></a>           ← Phase 5 — LLM reasoning  [TBD]
    │
    └── <a href="src/breakbot/cli/"><b>cli/</b></a>             ← CLI entry points  (<a href="src/breakbot/cli/README.md">README</a>)
        └── main.py              breakbot scan · breakbot graph · breakbot validate
</pre>

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
