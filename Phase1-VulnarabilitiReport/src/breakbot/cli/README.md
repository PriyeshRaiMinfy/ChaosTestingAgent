# CLI

The `breakbot` CLI is the primary user-facing interface. Built with
[typer](https://typer.tiangolo.com/) and [rich](https://github.com/Textualize/rich)
for coloured terminal output and structured tables.

Entry point is registered in [`pyproject.toml`](../../../pyproject.toml):
```toml
[project.scripts]
breakbot = "breakbot.cli.main:app"
```

---

## Commands

### `breakbot discover`

Auto-detects account topology: single vs org, trail access, role availability.

```bash
breakbot discover --profile breakbot
breakbot discover --profile breakbot --output stackset-template.yaml
```

What it does:
1. Tries `organizations:ListAccounts` + `DescribeOrganization`
2. If org: finds Organization Trail + checks S3 bucket access
3. Tests `sts:AssumeRole` into each member account
4. Reports what's reachable and what's missing

If member accounts lack the scanning role, outputs a CloudFormation StackSet template.

---

### `breakbot validate`

Verifies that the configured AWS profile has **read** access and **no write** access.

```bash
breakbot validate --profile breakbot --region us-east-1
breakbot validate --profile breakbot --org   # validates every account
```

What it does:
1. Calls `ec2:DescribeInstances` — should succeed
2. Calls `ec2:CreateTags` on a dummy resource — should fail with `AccessDenied`

---

### `breakbot scan`

Runs a full read-only scan. Auto-detects org mode unless `--single` is passed.

```bash
# Single account
breakbot scan --profile breakbot --region us-east-1

# Force single even if org detected
breakbot scan --profile breakbot --single

# Org-wide with CloudTrail behavioral events
breakbot scan --profile breakbot --org --all-regions --trail

# Specific domains only
breakbot scan --profile breakbot --domain identity --domain networking

# Specific accounts in org
breakbot scan --profile breakbot --org --account-id 111111111111 --account-id 222222222222
```

**Options:**

```
--profile  -p     AWS profile name
--region   -r     Primary region (default: us-east-1)
--all-regions     Scan every enabled region
--org             Force org-wide scan
--single          Force single-account (skip auto-detection)
--account-id      Repeatable. Filter to specific accounts in org mode
--member-role     Role name in member accounts (default: BreakBotReadOnly)
--external-id     ExternalId for member role trust policy
--domain   -d     Restrict domains: compute, networking, data, identity,
                  eks, secrets, containers, messaging, waf, dns, cognito,
                  apigateway, cdn, serverless
--trail           Fetch CloudTrail behavioral events (free management events)
--trail-days      Lookback period (default: 90, max: 90)
--output   -o     Output directory (default: ./scans)
--verbose  -v     Debug logging
```

**Output:**

Creates `scans/scan-YYYYMMDD-HHMMSS-xxxxxx/` containing:
- `scan.json` — Full ScanResult
- `posture.json` — Posture findings
- `trail.json` — CloudTrail events (if `--trail`)
- Per-type resource files for inspection

---

### `breakbot graph`

Builds the dependency graph from a completed scan.

```bash
breakbot graph scans/scan-... --html graph.html --serialize attack_surface.txt
breakbot graph scans/scan-... --max-hops 7
```

**Options:**

```
SCAN_DIR          Path to scan output directory (required)
--html            Save interactive HTML visualization
--serialize  -s   Save LLM-ready compact text
--max-hops        Max path length for entry→sink BFS (default: 5)
--verbose    -v   Debug logging
```

Automatically applies CloudTrail behavioral overlay if `trail.json` exists.

---

### `breakbot report`

Generates an LLM-powered attack-path report from a completed scan.

```bash
# Default: Markdown via AWS Bedrock
breakbot report scans/scan-...

# JSON format, direct Anthropic API
breakbot report scans/scan-... --format json --no-bedrock

# Cap tokens for very large accounts
breakbot report scans/scan-... --token-budget 200000
```

**Options:**

```
SCAN_DIR          Path to scan output directory (required)
--format   -f     Output format: md, json, html (default: md)
--region   -r     AWS region for Bedrock (default: ap-south-1)
--bedrock/--no-bedrock  Use Bedrock (default) or direct Anthropic API
--token-budget    Cap tokens sent to Claude (0 = no cap)
--output   -o     Output file path
--verbose  -v     Debug logging
```

Requires: `pip install 'breakbot[llm]'`

Default backend: AWS Bedrock (uses same AWS credentials as scan).
Alternative: set `ANTHROPIC_API_KEY` env var and use `--no-bedrock`.

---

### `breakbot posture`

Re-runs posture analysis on a completed scan (no AWS calls).

```bash
breakbot posture scans/scan-...
breakbot posture scans/scan-... --severity HIGH --category identity --verbose
```

---

## Typical Workflow

```
  breakbot discover    →  Understand topology, deploy missing roles
         │
  breakbot validate    →  Confirm read-only access
         │
  breakbot scan --trail →  Discover resources + behavioral events
         │
  breakbot graph       →  Build graph, visualize, serialize
         │
  breakbot report      →  Claude reasons over attack surface → report.md
```

---

## Adding a New Command

1. Open [`main.py`](main.py)
2. Decorate a function with `@app.command()`
3. Use `typer.Option` / `typer.Argument` for parameters
4. Use `console.print(...)` for rich-formatted output

```python
@app.command()
def my_command(
    profile: str = typer.Option(None, "--profile", "-p"),
):
    """One-line description shown in breakbot --help."""
    session = AWSSession(profile=profile)
    ...
```
