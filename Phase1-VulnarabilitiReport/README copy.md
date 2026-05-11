# BreakBot

Read-only AWS security agent. Scans your account, builds a dependency graph, and uses an LLM to find multi-hop attack paths.

## Why

GuardDuty, Inspector, and Config find issues in isolation. They never chain them.
BreakBot reasons about chains: *"this internet-facing Lambda + this overly broad role + this unencrypted S3 = a real breach path."*

## Architecture

```
[ AWS Account ]
      │
      ▼  (boto3, read-only)
[ Scanner ]  ── compute, network, data, identity, messaging, secrets
      │
      ▼
[ Graph Builder ] ── networkx MultiDiGraph (nodes = resources, edges = relationships)
      │
      ▼
[ Brain ] ── Claude API reasons over graph → attack paths
      │
      ▼
[ CLI / Report ]
```

## Project Layout

```
src/breakbot/
  scanner/      # Per-domain AWS scanners (compute, network, data, identity)
  models/       # Pydantic schemas for resources & edges
  graph/        # networkx graph construction + serialization
  brain/        # LLM prompt pipeline (Phase 5)
  cli/          # typer CLI entry points
  utils/        # AWS session helpers, retry/backoff, logging
tests/
  unit/         # Mocked boto3 (moto) tests
  integration/  # Real AWS tests (opt-in, requires creds)
```

## Quick Start

```bash
# 1. Install
pip install -e .

# 2. Configure AWS profile (read-only IAM user)
aws configure --profile breakbot

# 3. Run a scan
breakbot scan --profile breakbot --region us-east-1

# Output: scans/{scan_id}/{compute,network,data,identity}.json
```

## Status

- [x] Phase 1 — IAM & Read-Only Access Setup
- [ ] Phase 2 — Scanner (in progress)
- [ ] Phase 3 — Observability
- [ ] Phase 4 — Dependency Graph
- [ ] Phase 5 — LLM Brain
