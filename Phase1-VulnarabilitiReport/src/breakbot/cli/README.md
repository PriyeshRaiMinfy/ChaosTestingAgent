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

### `breakbot validate`

Verifies that the configured AWS profile has **read** access and **no write** access.
Run this before your first scan to catch misconfigured credentials early.

```bash
breakbot validate --profile breakbot --region us-east-1
```

What it does:
1. Calls `ec2:DescribeInstances` — should succeed
2. Calls `ec2:CreateTags` on a dummy resource — should fail with `AccessDenied`

```
Account: 123456789012
✔ Read access works (ec2:DescribeInstances)
✔ Write access correctly denied — profile is read-only
```

If step 2 **succeeds**, the profile has write permissions — the scan is aborted.
Do not run BreakBot with a profile that has write access.

---

### `breakbot scan`

Runs the full Phase 2 scanner against your AWS account.

```bash
# Scan a single region, all domains
breakbot scan --profile breakbot --region us-east-1

# Scan every enabled region in the account
breakbot scan --profile breakbot --all-regions

# Scan only one domain (fast, useful for targeted checks)
breakbot scan --profile breakbot --domain identity
breakbot scan --profile breakbot --domain networking

# Verbose logging (debug-level, shows each boto3 call)
breakbot scan --profile breakbot --region us-east-1 --verbose
```

**Options:**

```
--profile  -p   AWS profile name from ~/.aws/credentials  (default: "default")
--region   -r   Primary region to scan                    (default: us-east-1)
--all-regions   Scan all enabled regions in the account
--domain   -d   Restrict to one domain (repeatable):
                  compute | networking | data | identity
--output   -o   Output directory                          (default: ./scans)
--verbose  -v   Enable debug logging
```

**Output:**

Creates `scans/scan-YYYYMMDD-HHMMSS-xxxxxx/` containing:

```
scans/scan-20250511-142300-a3f9b1/
├── scan.json              ← Full ScanResult (all resources + errors)
├── ec2_instance.json      ← EC2 instances only
├── lambda_function.json   ← Lambda functions only
├── s3_bucket.json
├── rds_db-instance.json
├── iam_role.json
├── iam_user.json
├── ec2_vpc.json
├── ec2_security-group.json
└── elbv2_load-balancer.json
```

Terminal output shows a summary table:

```
╔══════════════════════════╗
║      Scan summary        ║
╠══════════╦═══════╦═══════╣
║ Domain   ║ Found ║ Errors║
╠══════════╬═══════╬═══════╣
║ compute  ║    12 ║     0 ║
║ networking║    8  ║     0 ║
║ data     ║     5 ║     1 ║
║ identity ║    23 ║     0 ║
║ TOTAL    ║    48 ║     1 ║
╚══════════╩═══════╩═══════╝
✔ Written to scans/scan-20250511-142300-a3f9b1
```

---

### `breakbot graph`

Takes the output of a completed scan and builds the dependency graph.

```bash
# Build graph, save HTML visualization and LLM-ready text
breakbot graph scans/scan-20250511-142300-a3f9b1 \
    --html graph.html \
    --serialize attack_surface.txt

# Just show the stats table (no files saved)
breakbot graph scans/scan-20250511-142300-a3f9b1

# Increase hop depth for larger accounts
breakbot graph scans/scan-... --serialize text.txt --max-hops 7
```

**Options:**

```
SCAN_DIR          Path to a scan output directory (required positional arg)
--html            Path to save interactive HTML visualization
--serialize  -s   Path to save LLM-ready compact text
--max-hops        Max path length for entry→sink BFS  (default: 5)
--verbose    -v   Enable debug logging
```

**Terminal output:**

```
Loading scan from scans/scan-.../scan.json
Loaded 48 resources from account 123456789012
Building dependency graph...

╔═════════════════════════════╗
║       Graph summary         ║
╠══════════════════════╦══════╣
║ Total Nodes          ║   49 ║  ← 48 resources + 1 INTERNET virtual node
║ Total Edges          ║   83 ║
║ Entry Points         ║    3 ║
║ Sinks                ║    7 ║
║ Internet Exposed Sgs ║    2 ║
╚══════════════════════╩══════╝

✔ Visualization saved to graph.html
✔ Serialization saved to attack_surface.txt
```

---

## Typical Workflow

```
                    ┌─────────────────────────────────────┐
                    │                                     │
  breakbot validate │  Check creds are read-only          │
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │                                     │
  breakbot scan     │  Discover all resources in account  │
                    │  Output: scans/{id}/scan.json        │
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │                                     │
  breakbot graph    │  Build dependency graph             │
                    │  Output: graph.html                 │
                    │          attack_surface.txt         │
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │                                     │
  Phase 5 (TBD)     │  Feed attack_surface.txt to Claude  │
                    │  Output: report.md                  │
                    │                                     │
                    └─────────────────────────────────────┘
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
    profile: str = typer.Option("default", "--profile", "-p"),
):
    """One-line description shown in breakbot --help."""
    session = AWSSession(profile=profile)
    ...
```
