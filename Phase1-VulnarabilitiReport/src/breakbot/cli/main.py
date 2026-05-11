"""
BreakBot CLI.

Commands:
  scan      Run a full scan of an AWS account, write JSON output to disk
  validate  Verify the configured credentials are read-only

Usage:
  breakbot scan --profile breakbot --region us-east-1
  breakbot validate --profile breakbot
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from breakbot.models import ScanResult
from breakbot.scanner import (
    ComputeScanner,
    DataScanner,
    IdentityScanner,
    NetworkingScanner,
)
from breakbot.utils import AWSSession

app = typer.Typer(
    help="BreakBot — read-only AWS attack-path scanner",
    no_args_is_help=True,
)
console = Console()


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )
    # Quiet the noisy boto3 retry logger
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


@app.command()
def scan(
    profile: str = typer.Option("default", "--profile", "-p", help="AWS profile name"),
    region: str = typer.Option("us-east-1", "--region", "-r", help="Default region"),
    output_dir: Path = typer.Option(Path("scans"), "--output", "-o", help="Output directory"),
    all_regions: bool = typer.Option(False, "--all-regions", help="Scan every enabled region"),
    domains: list[str] = typer.Option(
        None,
        "--domain", "-d",
        help="Restrict to specific domains: compute, networking, data, identity",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging"),
):
    """Run a full read-only scan of the configured AWS account."""
    _configure_logging(verbose)

    scan_id = f"scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    started_at = datetime.utcnow()
    console.rule(f"[bold cyan]BreakBot scan {scan_id}")

    # Session setup
    session = AWSSession(profile=profile, region=region)
    console.print(f"Account ID: [yellow]{session.account_id}[/yellow]")

    regions = session.enabled_regions() if all_regions else [region]
    console.print(f"Regions to scan: [yellow]{', '.join(regions)}[/yellow]")

    # Pick scanners
    available = {
        "compute": ComputeScanner,
        "networking": NetworkingScanner,
        "data": DataScanner,
        "identity": IdentityScanner,
    }
    selected = domains or list(available.keys())
    invalid = set(selected) - set(available)
    if invalid:
        console.print(f"[red]Unknown domains: {invalid}[/red]")
        raise typer.Exit(1)

    # Run scanners
    all_resources = []
    all_errors = []
    summary_rows = []

    for name in selected:
        scanner_cls = available[name]
        scanner = scanner_cls(session)
        console.print(f"\n[bold]▶ {name}[/bold]")
        resources = scanner.scan(regions=regions)
        all_resources.extend(resources)
        all_errors.extend(scanner.errors)
        summary_rows.append((name, len(resources), len(scanner.errors)))

    # Build & persist result
    result = ScanResult(
        scan_id=scan_id,
        account_id=session.account_id,
        started_at=started_at,
        completed_at=datetime.utcnow(),
        regions_scanned=regions,
        resources=all_resources,
        errors=all_errors,
    )

    scan_dir = output_dir / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    # Full result
    (scan_dir / "scan.json").write_text(result.model_dump_json(indent=2))

    # Per-domain split for human readability
    by_type: dict[str, list] = {}
    for r in all_resources:
        by_type.setdefault(r.resource_type.value, []).append(r.model_dump(mode="json"))
    for rtype, items in by_type.items():
        fname = rtype.replace(":", "_") + ".json"
        (scan_dir / fname).write_text(json.dumps(items, indent=2, default=str))

    # Summary table
    table = Table(title="Scan summary")
    table.add_column("Domain", style="cyan")
    table.add_column("Resources", justify="right", style="green")
    table.add_column("Errors", justify="right", style="red")
    for name, count, errors in summary_rows:
        table.add_row(name, str(count), str(errors))
    table.add_row("[bold]TOTAL[/bold]",
                  f"[bold]{len(all_resources)}[/bold]",
                  f"[bold]{len(all_errors)}[/bold]")
    console.print()
    console.print(table)
    console.print(f"\n[green]✔[/green] Written to [bold]{scan_dir}[/bold]")


@app.command()
def validate(
    profile: str = typer.Option("default", "--profile", "-p"),
    region: str = typer.Option("us-east-1", "--region", "-r"),
):
    """Verify the profile is read-only by attempting a positive and negative call."""
    _configure_logging(verbose=False)
    session = AWSSession(profile=profile, region=region)

    console.print(f"Account: [yellow]{session.account_id}[/yellow]")

    # Positive: should work
    ec2 = session.client("ec2", region=region)
    try:
        ec2.describe_instances(MaxResults=5)
        console.print("[green]✔[/green] Read access works (ec2:DescribeInstances)")
    except Exception as e:
        console.print(f"[red]✘[/red] Read access FAILED: {e}")
        raise typer.Exit(1)

    # Negative: should fail with AccessDenied
    try:
        ec2.create_tags(Resources=["i-0000000000000000"], Tags=[{"Key": "x", "Value": "y"}])
        console.print("[red]✘[/red] WRITE PERMISSION DETECTED — profile is NOT read-only!")
        raise typer.Exit(1)
    except Exception as e:
        if "AccessDenied" in str(e) or "UnauthorizedOperation" in str(e):
            console.print("[green]✔[/green] Write access correctly denied — profile is read-only")
        else:
            console.print(f"[yellow]?[/yellow] Unexpected error on write test: {e}")


if __name__ == "__main__":
    app()
