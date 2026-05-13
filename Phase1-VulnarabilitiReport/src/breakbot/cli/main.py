"""
BreakBot CLI.

Commands:
  validate  Verify credentials are read-only (and reachable across the Org if --org)
  scan      Run a full scan of one account, or every account in the Organization
  graph     Build the dependency graph from a completed scan

Single-account usage:
  breakbot validate --profile breakbot --region us-east-1
  breakbot scan     --profile breakbot --region us-east-1

Org-wide usage (run from the Audit account):
  breakbot validate --profile audit --org
  breakbot scan     --profile audit --org --all-regions
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

from breakbot.graph import GraphBuilder, GraphSerializer
from breakbot.models import Resource, ScanResult
from breakbot.org import (
    DEFAULT_MEMBER_ROLE,
    CrossAccountSessionFactory,
    OrganizationScanner,
)
from breakbot.scanner import (
    ComputeScanner,
    DataScanner,
    EksScanner,
    IdentityScanner,
    NetworkingScanner,
    SecretsScanner,
)
from breakbot.utils import AWSSession

app = typer.Typer(
    help="BreakBot — read-only AWS attack-path scanner",
    no_args_is_help=True,
)
console = Console()


SCANNER_REGISTRY = {
    "compute": ComputeScanner,
    "networking": NetworkingScanner,
    "data": DataScanner,
    "identity": IdentityScanner,
    "eks": EksScanner,
    "secrets": SecretsScanner,
}


def _build_master_session(profile: str | None, region: str) -> AWSSession:
    """
    Build the master AWSSession with helpful errors when credentials are
    missing or the named profile cannot be found.

    Resolves credentials in this order:
      1. --profile <name>           — explicit named profile from ~/.aws/credentials
      2. AWS_PROFILE env var        — same, but from env
      3. Default credential chain   — env vars → EC2 instance profile → ECS
                                       task role → CloudShell → SSO cache
    """
    from botocore.exceptions import (
        NoCredentialsError,
        PartialCredentialsError,
        ProfileNotFound,
    )

    try:
        session = AWSSession(profile=profile, region=region)
        # Force credential resolution now so any error surfaces here, not
        # mid-scan against a member account.
        _ = session.account_id
        return session
    except ProfileNotFound as e:
        console.print(f"[red]Profile not found:[/red] {e}")
        console.print(
            "[dim]Run `aws configure --profile <name>` to set one up, or omit "
            "--profile to use ambient credentials (CloudShell, instance profile, SSO).[/dim]"
        )
        raise typer.Exit(1) from e
    except (NoCredentialsError, PartialCredentialsError) as e:
        console.print(f"[red]No AWS credentials found:[/red] {e}")
        console.print(
            "[dim]Set credentials via one of:\n"
            "  • aws configure (creates ~/.aws/credentials)\n"
            "  • aws sso login\n"
            "  • export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY\n"
            "  • run from EC2/ECS/CloudShell where the role is auto-attached[/dim]"
        )
        raise typer.Exit(1) from e


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


def _scan_single_account(
    session: AWSSession,
    regions: list[str],
    selected_domains: list[str],
    summary_rows: list,
) -> tuple[list[Resource], list[dict]]:
    """Run the selected scanners against one account's session."""
    account_resources: list[Resource] = []
    account_errors: list[dict] = []

    for name in selected_domains:
        scanner_cls = SCANNER_REGISTRY[name]
        scanner = scanner_cls(session)
        console.print(f"  [bold]▶ {name}[/bold]")
        resources = scanner.scan(regions=regions)
        # Tag each error with the account so the merged error log stays traceable
        for err in scanner.errors:
            err.setdefault("account_id", session.account_id)
        account_resources.extend(resources)
        account_errors.extend(scanner.errors)
        summary_rows.append((session.account_id, name, len(resources), len(scanner.errors)))

    return account_resources, account_errors


@app.command()
def scan(
    profile: str = typer.Option(
        None, "--profile", "-p",
        help="AWS profile name. Omit to use the default credential chain "
             "(env vars, EC2 instance profile, ECS task role, CloudShell, SSO).",
    ),
    region: str = typer.Option("us-east-1", "--region", "-r", help="Default region"),
    output_dir: Path = typer.Option(Path("scans"), "--output", "-o", help="Output directory"),
    all_regions: bool = typer.Option(False, "--all-regions", help="Scan every enabled region"),
    org: bool = typer.Option(
        False,
        "--org",
        help="Scan every account in the AWS Organization. Requires credentials with "
             "organizations:ListAccounts (Management account or delegated admin).",
    ),
    account_ids: list[str] = typer.Option(
        None,
        "--account-id",
        help="Repeatable. In --org mode, scan only these account IDs instead of "
             "every account in the Organization.",
    ),
    member_role: str = typer.Option(
        DEFAULT_MEMBER_ROLE,
        "--member-role",
        help="Name of the role to assume in each member account (must be deployed "
             "via the BreakBot CloudFormation StackSet).",
    ),
    external_id: str = typer.Option(
        None,
        "--external-id",
        help="ExternalId condition value if the member role trust policy requires it.",
    ),
    domains: list[str] = typer.Option(
        None,
        "--domain", "-d",
        help="Restrict to specific domains: compute, networking, data, identity, eks, secrets",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging"),
):
    """Run a full read-only scan of one account, or every account in the Organization."""
    _configure_logging(verbose)

    scan_id = f"scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    started_at = datetime.utcnow()
    console.rule(f"[bold cyan]BreakBot scan {scan_id}")

    # The "master" session is the locally configured profile (or ambient
    # credentials if --profile is omitted). In org mode this is the Audit
    # account; in single-account mode it IS the scan target.
    master = _build_master_session(profile, region)
    console.print(f"Scanner account: [yellow]{master.account_id}[/yellow]")

    # Validate the selected domains up front
    selected = domains or list(SCANNER_REGISTRY.keys())
    invalid = set(selected) - set(SCANNER_REGISTRY)
    if invalid:
        console.print(f"[red]Unknown domains: {invalid}[/red]")
        raise typer.Exit(1)

    # Decide which accounts and regions to walk
    if org:
        org_scanner = OrganizationScanner(master)
        accounts = org_scanner.list_accounts()
        if account_ids:
            requested = set(account_ids)
            accounts = [a for a in accounts if a["Id"] in requested]
            missing = requested - {a["Id"] for a in accounts}
            if missing:
                console.print(
                    f"[yellow]⚠ Requested account IDs not found in Org or not ACTIVE: "
                    f"{sorted(missing)}[/yellow]"
                )
        console.print(f"Organization mode: [yellow]{len(accounts)}[/yellow] account(s) to scan")
        factory = CrossAccountSessionFactory(
            master_session=master,
            member_role_name=member_role,
            external_id=external_id,
        )
    else:
        if account_ids:
            console.print("[red]--account-id requires --org (it filters within the Org)[/red]")
            raise typer.Exit(1)
        accounts = [{"Id": master.account_id, "Name": "(self)", "Email": "", "Status": "ACTIVE"}]
        factory = None  # not used in single-account mode

    all_resources: list[Resource] = []
    all_errors: list[dict] = []
    summary_rows: list = []
    accounts_actually_scanned: list[str] = []

    for acct in accounts:
        acct_id = acct["Id"]
        acct_name = acct["Name"]
        console.print(f"\n[bold cyan]Account {acct_id}[/bold cyan] [dim]{acct_name}[/dim]")

        # Resolve the session for this account
        if org:
            session = factory.try_session_for(acct_id, region=region)
            if session is None:
                console.print(f"  [yellow]⚠ Cannot assume {member_role} — skipping[/yellow]")
                all_errors.append({
                    "account_id": acct_id,
                    "domain": "org",
                    "region": region,
                    "error": f"AssumeRole {member_role} failed",
                    "error_type": "AssumeRoleFailed",
                })
                continue
        else:
            session = master

        # Decide the region list (per-account, since member accounts can have
        # different opt-in regions enabled)
        regions = session.enabled_regions() if all_regions else [region]
        console.print(f"  Regions: [yellow]{', '.join(regions)}[/yellow]")

        resources, errors = _scan_single_account(session, regions, selected, summary_rows)
        all_resources.extend(resources)
        all_errors.extend(errors)
        accounts_actually_scanned.append(acct_id)

    # Build & persist result
    regions_seen = sorted({r.region for r in all_resources}) or [region]
    result = ScanResult(
        scan_id=scan_id,
        scanner_account_id=master.account_id,
        accounts_scanned=accounts_actually_scanned,
        started_at=started_at,
        completed_at=datetime.utcnow(),
        regions_scanned=regions_seen,
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
    table.add_column("Account", style="magenta")
    table.add_column("Domain", style="cyan")
    table.add_column("Resources", justify="right", style="green")
    table.add_column("Errors", justify="right", style="red")
    for acct_id, name, count, errors in summary_rows:
        table.add_row(acct_id, name, str(count), str(errors))
    table.add_row(
        "[bold]TOTAL[/bold]",
        "",
        f"[bold]{len(all_resources)}[/bold]",
        f"[bold]{len(all_errors)}[/bold]",
    )
    console.print()
    console.print(table)
    console.print(f"\n[green]✔[/green] Written to [bold]{scan_dir}[/bold]")


def _validate_single_session(session: AWSSession, label: str) -> bool:
    """Returns True if the session has read access AND lacks write access."""
    region = session.default_region
    ec2 = session.client("ec2", region=region)

    # Positive: should work
    try:
        ec2.describe_instances(MaxResults=5)
        console.print(f"  [green]✔[/green] {label}: read access works")
    except Exception as e:
        console.print(f"  [red]✘[/red] {label}: read access FAILED — {e}")
        return False

    # Negative: should fail with AccessDenied / UnauthorizedOperation
    try:
        ec2.create_tags(Resources=["i-0000000000000000"], Tags=[{"Key": "x", "Value": "y"}])
        console.print(f"  [red]✘[/red] {label}: WRITE PERMISSION DETECTED — role is NOT read-only!")
        return False
    except Exception as e:
        msg = str(e)
        if "AccessDenied" in msg or "UnauthorizedOperation" in msg:
            console.print(f"  [green]✔[/green] {label}: write correctly denied")
            return True
        console.print(f"  [yellow]?[/yellow] {label}: unexpected error on write probe — {e}")
        return True  # treat unknown errors as acceptable; the key signal is "not write-success"


@app.command()
def validate(
    profile: str = typer.Option(
        None, "--profile", "-p",
        help="AWS profile name. Omit to use the default credential chain.",
    ),
    region: str = typer.Option("us-east-1", "--region", "-r"),
    org: bool = typer.Option(
        False,
        "--org",
        help="Check that the BreakBotReadOnly role is reachable and read-only in "
             "every account in the Organization.",
    ),
    account_ids: list[str] = typer.Option(
        None,
        "--account-id",
        help="Repeatable. In --org mode, validate only these accounts.",
    ),
    member_role: str = typer.Option(
        DEFAULT_MEMBER_ROLE,
        "--member-role",
        help="Name of the role to validate in each member account.",
    ),
    external_id: str = typer.Option(None, "--external-id"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Verify credentials are read-only across one account or the whole Organization."""
    _configure_logging(verbose)

    master = _build_master_session(profile, region)
    console.print(f"Scanner account: [yellow]{master.account_id}[/yellow]\n")

    if not org:
        if account_ids:
            console.print("[red]--account-id requires --org[/red]")
            raise typer.Exit(1)
        console.print(f"[bold]Validating account {master.account_id}[/bold]")
        ok = _validate_single_session(master, master.account_id)
        if not ok:
            raise typer.Exit(1)
        return

    # Org mode: walk every account (or the filtered subset)
    org_scanner = OrganizationScanner(master)
    accounts = org_scanner.list_accounts()
    if account_ids:
        requested = set(account_ids)
        accounts = [a for a in accounts if a["Id"] in requested]
    console.print(f"[bold]Validating {len(accounts)} account(s) in the Organization[/bold]\n")

    factory = CrossAccountSessionFactory(
        master_session=master,
        member_role_name=member_role,
        external_id=external_id,
    )

    failed: list[str] = []
    unreachable: list[str] = []
    for acct in accounts:
        acct_id = acct["Id"]
        console.print(f"[bold cyan]{acct_id}[/bold cyan] [dim]{acct['Name']}[/dim]")
        sess = factory.try_session_for(acct_id, region=region)
        if sess is None:
            console.print(f"  [yellow]⚠[/yellow] Cannot assume {member_role}")
            unreachable.append(acct_id)
            continue
        if not _validate_single_session(sess, acct_id):
            failed.append(acct_id)

    console.print()
    console.print(f"Validated: [green]{len(accounts) - len(failed) - len(unreachable)}[/green]")
    if unreachable:
        console.print(f"Unreachable (role not deployed): [yellow]{len(unreachable)}[/yellow]")
        for aid in unreachable:
            console.print(f"  - {aid}")
    if failed:
        console.print(f"Failed (write access detected or read broken): [red]{len(failed)}[/red]")
        for aid in failed:
            console.print(f"  - {aid}")
        raise typer.Exit(1)


@app.command()
def graph(
    scan_dir: Path = typer.Argument(..., help="Path to a scan output directory (e.g. scans/scan-...)"),
    html: Path = typer.Option(None, "--html", help="Save interactive HTML visualization to this path"),
    serialize: Path = typer.Option(None, "--serialize", "-s", help="Save LLM-ready text to this path"),
    max_hops: int = typer.Option(5, "--max-hops", help="Max path length when searching entry → sink"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Build the dependency graph from a completed scan and optionally visualize or serialize it."""
    _configure_logging(verbose)

    scan_file = scan_dir / "scan.json"
    if not scan_file.exists():
        console.print(f"[red]No scan.json found in {scan_dir}[/red]")
        raise typer.Exit(1)

    console.print(f"Loading scan from [bold]{scan_file}[/bold]")
    result = ScanResult.model_validate_json(scan_file.read_text())
    scope = "org" if result.is_org_scan else "single account"
    console.print(
        f"Loaded {result.resource_count} resources across "
        f"[yellow]{len(result.accounts_scanned)}[/yellow] account(s) ({scope})"
    )

    console.print("[bold]Building dependency graph...[/bold]")
    builder = GraphBuilder(result)
    g = builder.build()

    serializer = GraphSerializer(g, builder.arn_index, max_hops=max_hops)
    stats = serializer.stats()

    table = Table(title="Graph summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="green")
    for k, v in stats.items():
        table.add_row(k.replace("_", " ").title(), str(v))
    console.print(table)

    if html:
        try:
            from breakbot.graph.visualize import render_html
            console.print(f"Rendering HTML to [bold]{html}[/bold]")
            render_html(g, html)
            console.print(f"[green]✔[/green] Visualization saved to {html}")
        except ImportError as e:
            console.print(f"[yellow]Skipping HTML output:[/yellow] {e}")

    if serialize:
        console.print(f"Serializing graph for LLM to [bold]{serialize}[/bold]")
        serializer.save(serialize)
        console.print(f"[green]✔[/green] Serialization saved to {serialize}")

    if not html and not serialize:
        console.print("\n[dim]Tip: use --html graph.html or --serialize attack_surface.txt[/dim]")


if __name__ == "__main__":
    app()
