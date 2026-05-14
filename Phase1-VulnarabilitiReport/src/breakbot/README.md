# BreakBot

Read-only AWS attack-path scanner with LLM-powered threat reasoning.

```
        ┌────────────────────────────────────────────────────────────────┐
        │                                                                │
        │   ┌──────┐    scan     ┌────────┐   serialize    ┌──────────┐  │
        │   │ AWS  │ ──────────► │ graph  │ ─────────────► │  Claude  │  │
        │   │ APIs │   (boto3)   │ (nx)   │   (text)       │  (LLM)   │  │
        │   └──────┘             └────────┘                └──────────┘  │
        │      ▲                      ▲                          │       │
        │      │                      │                          ▼       │
        │   read-only             posture                  report.md     │
        │   creds only            findings                 / json / html │
        │                                                                │
        └────────────────────────────────────────────────────────────────┘
```

BreakBot finds **exploitable paths**, not just **misconfigurations**.
A flat list of "47 things are wrong" is noise. A short list of "here's how
an attacker walks from the internet to your customer database" is signal.

---

## The Five-Phase Pipeline

```
┌─────────┐   ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ Phase 1 │──►│ Phase 2 │──►│ Phase 3  │──►│ Phase 4  │──►│ Phase 5  │
│  scan   │   │  scan   │   │ posture  │   │  graph   │   │ analyst  │
│ (core)  │   │ (more)  │   │ + trail  │   │ + paths  │   │ (Claude) │
└─────────┘   └─────────┘   └──────────┘   └──────────┘   └──────────┘
   boto3        boto3          flag           networkx       anthropic
                              checks                          + Claude
```

| Phase | Module                                      | What it does |
|-------|---------------------------------------------|--------------|
| 1     | [scanner/](scanner/README.md)               | Core scanners — IAM, EC2, S3, RDS, Lambda, VPC |
| 2     | [scanner/](scanner/README.md)               | Extended — EKS, ECS, Secrets, KMS, DNS, WAF, etc. |
| 3a    | [posture/](posture/)                        | Deterministic flag-based misconfig checks |
| 3b    | [scanner/cloudtrail.py](scanner/cloudtrail.py) | Behavioral overlay — what *actually happened* |
| 4     | **[graph/](graph/README.md)**               | networkx graph + LLM-ready text serialization |
| 5     | **[brain/](brain/README.md)**               | Claude-powered attack-path reasoning |

The two **bolded** modules each have their own deep-dive READMEs:

- **[graph/README.md](graph/README.md)** — how the dependency graph is built with `networkx.MultiDiGraph`, the 9 inference passes, edge types, and the entry-point/sink BFS that produces the attack surface.
- **[brain/README.md](brain/README.md)** — how the `anthropic` SDK + Claude Opus 4.7 produce the structured report, with adaptive thinking, prompt caching, and streaming.

---

## End-to-End Data Flow

```
   ┌───────────────────────────────────────────────────────────────────┐
   │                          USER COMMAND                             │
   │                                                                   │
   │   breakbot scan --profile audit --org --all-regions --trail       │
   │                                                                   │
   └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │            cli/main.py    →    OrganizationScanner                │
   │                                                                   │
   │       Audit account ──assumes──► BreakBotReadOnly role            │
   │                                  in every member account          │
   └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │     scanner/   →  14 scanners run in parallel per account         │
   │                                                                   │
   │     compute  networking  data  identity  eks  secrets  ...        │
   │                                                                   │
   │     each emits  list[Resource]                                    │
   └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │              ScanResult  →  scans/scan-<id>/                      │
   │                                                                   │
   │              ├── scan.json        (every Resource, raw)           │
   │              ├── <type>.json      (split by ResourceType)         │
   │              ├── posture.json     (PostureAnalyzer output)        │
   │              └── trail.json       (CloudTrail behavioral events)  │
   └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │     breakbot graph scans/scan-<id> --serialize surface.txt        │
   │                                                                   │
   │     GraphBuilder   ──► networkx.MultiDiGraph                      │
   │     TrailOverlay   ──► behavioral edges added                     │
   │     GraphSerializer ──► attack_surface.txt                        │
   └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │     breakbot report scans/scan-<id> --format md                   │
   │                                                                   │
   │     SecurityAnalyst.analyze(attack_surface, posture_findings)     │
   │                                  │                                │
   │                                  ▼                                │
   │     ┌─────────────────────────────────────────────────────────┐   │
   │     │ Claude Opus 4.7 (adaptive thinking, cached prompt)      │   │
   │     └─────────────────────────────────────────────────────────┘   │
   │                                  │                                │
   │                                  ▼                                │
   │              AnalysisReport  →  report.md                         │
   └───────────────────────────────────────────────────────────────────┘
```

---

## Module Layout

```
src/breakbot/
│
├── README.md ───────────────── you are here
│
├── cli/                        Typer-based command-line interface
│   ├── main.py                 ─ scan, validate, graph, posture, report
│   └── README.md
│
├── models/                     Pydantic data models — Resource, ScanResult
│   ├── resource.py             ─ 40+ ResourceType enum entries
│   └── README.md
│
├── scanner/                    Per-service AWS scanners (read-only)
│   ├── base.py                 ─ Base class + boto3 paginator helpers
│   ├── compute.py              ─ EC2, EBS, AMI, snapshots
│   ├── identity.py             ─ IAM roles, users, policies
│   ├── data.py                 ─ S3, RDS, DynamoDB, ElastiCache
│   ├── networking.py           ─ VPC, SG, ALB, NLB, NAT
│   ├── eks.py / containers.py  ─ Kubernetes + ECS
│   ├── secrets.py              ─ Secrets Manager, SSM, KMS
│   ├── messaging.py            ─ SQS, SNS, MSK, Kinesis, EventBridge
│   ├── serverless.py           ─ Lambda, Step Functions
│   ├── apigateway.py / cdn.py  ─ API Gateway + CloudFront
│   ├── dns.py / cognito.py     ─ Route53 + Cognito
│   ├── waf.py                  ─ WAFv2 web ACLs
│   ├── cloudtrail.py           ─ behavioral event fetcher (Phase 3b)
│   └── README.md
│
├── org/                        Cross-account orchestration
│   └── cross_account.py        ─ OrganizationScanner + STS AssumeRole
│
├── posture/                    Phase 3 — deterministic flag checks
│   ├── analyzer.py             ─ PostureAnalyzer (no AWS calls)
│   └── findings.py             ─ PostureFinding, Severity
│
├── graph/             ★        Phase 4 — dependency graph
│   ├── builder.py              ─ GraphBuilder (9 inference passes)
│   ├── edges.py                ─ EdgeType enum + INTERNET node
│   ├── serializer.py           ─ GraphSerializer (text output for LLM)
│   ├── trail_overlay.py        ─ TrailOverlay (behavioral edges)
│   ├── visualize.py            ─ pyvis HTML rendering
│   └── README.md   ◄── deep-dive: networkx, edge types, BFS path-finding
│
├── brain/             ★        Phase 5 — LLM-powered reasoning
│   ├── analyst.py              ─ SecurityAnalyst (Claude Opus 4.7)
│   ├── report.py               ─ AnalysisReport, AttackPath
│   └── README.md   ◄── deep-dive: anthropic SDK, prompts, output schema
│
└── utils/                      AWSSession + paginator helpers
    └── README.md
```

★ = the two modules with dedicated subsystem READMEs.

---

## How a Path Becomes a Story

This is the loop that turns AWS API data into "an attacker can do X".

```
    AWS account                Graph (Phase 4)              Report (Phase 5)
    ───────────                ───────────────              ─────────────────

  prod-alb                    INTERNET                     ENTRY: prod-alb
   │ scheme=internet-          │                            │
   │ facing                    │ internet_exposes :443      │
   ▼                           ▼                            ▼
  sg-web                      sg-web                      STEPS:
   │ ingress 0.0.0.0/0         │                          1. Attacker hits
   │ → :443                    │ attached_to_sg              public ALB on
   ▼                           ▼                             port 443.
  EC2 web-01                  EC2 web-01                  2. ALB forwards to
   │ imds_v1_allowed           │                             EC2 web-01, which
   ▼                           │ has_instance_profile        allows IMDSv1.
  AppRole                      ▼                          3. Attacker steals
   │ s3:* on                  AppRole                        AppRole creds
   │ customer-data             │                             via SSRF →
   ▼                           │ iam_can_access              metadata service.
  S3 customer-data             │ actions=[s3:*]            4. AppRole has
                               ▼                             s3:* on the data
                              S3 customer-data               bucket.

                                                            BLAST RADIUS:
                                                            full read/write
                                                            of customer-data

                                                            SEVERITY: CRITICAL
                                                            CONFIDENCE: HIGH

                                                            REMEDIATION:
                                                            - enforce IMDSv2
                                                            - scope AppRole
                                                              s3:* to bucket
                                                              prefixes
                                                            - close SG :443
                                                              if not needed
```

The graph encodes the **what**. Claude produces the **so what**.

---

## Quick Start

```bash
# 1. Install
pip install -e ".[llm,viz,dev]"

# 2. Validate read-only credentials
breakbot validate --profile audit --org

# 3. Scan + posture + behavioral trail
breakbot scan --profile audit --org --all-regions --trail

# 4. Build the graph
breakbot graph scans/scan-<id> --serialize attack_surface.txt --html graph.html

# 5. Generate the LLM report
export ANTHROPIC_API_KEY=sk-...
breakbot report scans/scan-<id> --format md
```

Output goes to `scans/scan-<id>/report.md` (or `report.json`, `report.html`).

---

## Design Principles

```
1.  READ-ONLY.   The scanner role is read-only. The validate command
                 actively probes for write access and fails if it finds
                 any. Production AWS environments can be scanned safely.

2.  AWS-FREE LLM. The LLM never touches AWS. It only sees text serialized
                 from a static graph. The reasoning is non-deterministic;
                 the input to that reasoning is fully deterministic.

3.  STATIC + BEHAVIORAL. Static graph = what IAM and network policy
                 *allow*. CloudTrail overlay = what *actually happened*.
                 A static path that is also a behavioral path is a
                 confirmed attack surface, not a theoretical one.

4.  WEAK-LINK ANALYSIS. Every attack path is a chain. The report calls
                 out the single fix that would break it. Fewer fixes,
                 bigger impact.

5.  STRUCTURED OUTPUT. Claude returns JSON, not prose. Reports are
                 machine-readable first, human-readable second
                 (via to_markdown / to_html renderers).
```

---

## Subsystem Deep-Dives

| Module               | What to read                                                |
|----------------------|-------------------------------------------------------------|
| **Graph (Phase 4)**  | **[graph/README.md](graph/README.md)** — networkx model, edge types, path-finding |
| **Brain (Phase 5)**  | **[brain/README.md](brain/README.md)** — anthropic SDK, Claude features, output schema |
| Scanners (Phase 1-2) | [scanner/README.md](scanner/README.md)                      |
| CLI                  | [cli/README.md](cli/README.md)                              |
| Data models          | [models/README.md](models/README.md)                        |
| AWS session helpers  | [utils/README.md](utils/README.md)                          |
