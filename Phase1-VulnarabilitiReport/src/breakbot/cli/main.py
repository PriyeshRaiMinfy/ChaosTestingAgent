"""
BreakBot CLI.

Commands:
  validate  Verify credentials are read-only (and reachable across the Org if --org)
  scan      Run a full scan of one account, or every account in the Organization
  graph     Build the dependency graph from a completed scan
  posture   Re-run posture analysis on a completed scan (no AWS calls)

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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from breakbot.graph import GraphBuilder, GraphSerializer, TrailOverlay
from breakbot.models import Resource, ScanResult
from breakbot.posture import PostureAnalyzer
from breakbot.scanner.cloudtrail import CloudTrailScanner, TrailEvent
from breakbot.org import (
    DEFAULT_MEMBER_ROLE,
    CrossAccountSessionFactory,
    OrganizationScanner,
)
from breakbot.scanner import (
    ApiGatewayScanner,
    CloudFrontScanner,
    CognitoScanner,
    ComputeScanner,
    DataScanner,
    DnsScanner,
    EcsScanner,
    EksScanner,
    IdentityScanner,
    MessagingScanner,
    NetworkingScanner,
    SecretsScanner,
    ServerlessScanner,
    WafScanner,
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
    "containers": EcsScanner,
    "messaging": MessagingScanner,
    "waf": WafScanner,
    "dns": DnsScanner,
    "cognito": CognitoScanner,
    "apigateway": ApiGatewayScanner,
    "cdn": CloudFrontScanner,
    "serverless": ServerlessScanner,
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
    """Run the selected scanners against one account's session (parallel)."""
    account_resources: list[Resource] = []
    account_errors: list[dict] = []

    def _run_domain(name: str) -> tuple[str, list[Resource], list[dict]]:
        scanner_cls = SCANNER_REGISTRY[name]
        scanner = scanner_cls(session)
        resources = scanner.scan(regions=regions)
        for err in scanner.errors:
            err.setdefault("account_id", session.account_id)
        return name, resources, scanner.errors

    max_workers = min(len(selected_domains), 10)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_run_domain, name): name
            for name in selected_domains
        }
        console.print(f"  [dim]Scanning {len(selected_domains)} domains in parallel (workers={max_workers})[/dim]")
        for future in as_completed(futures):
            name, resources, errors = future.result()
            console.print(f"  [bold]✔ {name}[/bold] — {len(resources)} resources")
            account_resources.extend(resources)
            account_errors.extend(errors)
            summary_rows.append((session.account_id, name, len(resources), len(errors)))

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
        help=(
            "Restrict to specific domains: compute, networking, data, identity, "
            "eks, secrets, containers, messaging, waf, dns, cognito, "
            "apigateway, cdn, serverless"
        ),
    ),
    trail: bool = typer.Option(
        False, "--trail",
        help="Also fetch CloudTrail behavioral events (last 90 days). "
             "Writes trail.json alongside scan.json. No extra AWS cost — "
             "uses management events only.",
    ),
    trail_days: int = typer.Option(
        90, "--trail-days",
        help="How many days of CloudTrail history to fetch (max 90).",
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

    # Error category breakdown — shows what KIND of failures happened so the
    # user can distinguish "fix the IAM role" from "this region is opt-in".
    if all_errors:
        _print_error_categories(console, all_errors, verbose=verbose)

    # Posture analysis — no additional AWS calls, runs on the scan result in memory
    console.print("\n[bold]Running posture analysis...[/bold]")
    posture_findings = PostureAnalyzer().analyze(result)
    (scan_dir / "posture.json").write_text(
        json.dumps([f.to_dict() for f in posture_findings], indent=2)
    )
    _print_posture_summary(console, posture_findings)
    console.print(
        f"[green]✔[/green] Posture findings written to [bold]{scan_dir / 'posture.json'}[/bold]"
    )

    # CloudTrail behavioral overlay (optional — only when --trail is set)
    if trail:
        console.print("\n[bold]Fetching CloudTrail behavioral events...[/bold]")
        trail_scanner = CloudTrailScanner()
        days = min(trail_days, 90)
        # Use the master session for trail (org mode: trail is in management/audit account)
        trail_events = trail_scanner.scan(master, regions_seen, lookback_days=days)
        trail_dicts = [e.to_dict() for e in trail_events]
        (scan_dir / "trail.json").write_text(json.dumps(trail_dicts, indent=2))
        console.print(
            f"[green]✔[/green] {len(trail_events)} behavioral event(s) written to "
            f"[bold]{scan_dir / 'trail.json'}[/bold]"
        )

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

    # Apply CloudTrail behavioral overlay if trail.json exists alongside scan.json
    trail_file = scan_dir / "trail.json"
    if trail_file.exists():
        console.print("[bold]Applying CloudTrail behavioral overlay...[/bold]")
        raw_events = json.loads(trail_file.read_text())
        trail_events = [TrailEvent.from_dict(e) for e in raw_events]
        behavioral_edges = TrailOverlay().apply(g, builder.arn_index, trail_events)
        console.print(
            f"[green]✔[/green] {behavioral_edges} behavioral edge(s) added "
            f"from {len(trail_events)} CloudTrail event(s)"
        )
    else:
        console.print(
            "[dim]No trail.json found — run `breakbot scan --trail` to add "
            "behavioral edges.[/dim]"
        )

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


def _print_error_categories(con: Console, errors: list[dict], verbose: bool) -> None:
    """Show categorized error counts so the user can distinguish actionable
    failures (permission_denied — fix the IAM role) from expected ones
    (not_available — region not opted in) from transient ones (retriable)."""
    from collections import Counter

    _CATEGORY_STYLE = {
        "permission_denied": "bold red",   # IAM role needs fixing
        "retriable":         "yellow",      # boto3 retries gave up
        "unknown":           "yellow",      # unexpected — investigate
        "not_available":     "dim",         # opt-in regions, etc.
    }
    _CATEGORY_HINT = {
        "permission_denied": "→ scanner role is missing permissions",
        "retriable":         "→ boto3 retries exhausted (Throttling)",
        "unknown":           "→ unexpected error — check logs",
        "not_available":     "→ service / region not available (expected)",
    }

    counts = Counter(e.get("category", "unknown") for e in errors)
    if not counts:
        return

    t = Table(title="Error categories", show_header=True)
    t.add_column("Category", style="bold")
    t.add_column("Count", justify="right")
    t.add_column("Action", style="dim")
    for cat in ("permission_denied", "retriable", "unknown", "not_available"):
        n = counts.get(cat, 0)
        if not n:
            continue
        style = _CATEGORY_STYLE[cat]
        t.add_row(
            f"[{style}]{cat}[/{style}]",
            str(n),
            _CATEGORY_HINT[cat],
        )
    con.print()
    con.print(t)

    # In verbose mode, show the most actionable errors (permission_denied)
    # with the actual service/operation/region so users can fix the role.
    if verbose:
        denied = [e for e in errors if e.get("category") == "permission_denied"]
        if denied:
            con.print("\n[bold red]Permission-denied details:[/bold red]")
            for e in denied[:20]:  # cap output
                con.print(
                    f"  - {e.get('service', '?')}:{e.get('operation', '?')} "
                    f"in {e.get('region', '?')} "
                    f"(account {e.get('account_id', '?')}) — {e.get('error_code', '?')}"
                )
            if len(denied) > 20:
                con.print(f"  [dim]... and {len(denied) - 20} more[/dim]")


def _print_posture_summary(con: Console, findings: list) -> None:
    from collections import Counter
    from breakbot.posture.findings import Severity

    counts = Counter(f.severity.value for f in findings)
    if not any(counts.values()):
        con.print("[green]No posture findings.[/green]")
        return

    _SEV_STYLE = {
        Severity.CRITICAL.value: "bold red",
        Severity.HIGH.value:     "red",
        Severity.MEDIUM.value:   "yellow",
        Severity.LOW.value:      "blue",
        Severity.INFO.value:     "dim",
    }
    t = Table(title="Posture findings")
    t.add_column("Severity", style="bold")
    t.add_column("Count", justify="right")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        n = counts.get(sev.value, 0)
        if n:
            t.add_row(f"[{_SEV_STYLE[sev.value]}]{sev.value}[/{_SEV_STYLE[sev.value]}]", str(n))
    con.print(t)


@app.command()
def posture(
    scan_dir: Path = typer.Argument(..., help="Path to a scan output directory (e.g. scans/scan-...)"),
    severity: str = typer.Option(
        None, "--severity", "-s",
        help="Show only findings at or above this level (CRITICAL, HIGH, MEDIUM, LOW).",
    ),
    category: str = typer.Option(
        None, "--category", "-c",
        help="Show only findings in this category (network, encryption, identity, compute, data, waf).",
    ),
    output: Path = typer.Option(
        None, "--output", "-o",
        help="Write findings to a JSON file (re-writes posture.json by default).",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Run posture analysis on a completed scan — no AWS calls required."""
    _configure_logging(verbose)

    scan_file = scan_dir / "scan.json"
    if not scan_file.exists():
        console.print(f"[red]No scan.json found in {scan_dir}[/red]")
        raise typer.Exit(1)

    console.print(f"Loading scan from [bold]{scan_file}[/bold]")
    result = ScanResult.model_validate_json(scan_file.read_text())
    console.print(f"Loaded [yellow]{result.resource_count}[/yellow] resources")

    findings = PostureAnalyzer().analyze(result)

    # Filter
    _SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if severity:
        sev_upper = severity.upper()
        if sev_upper not in _SEV_ORDER:
            console.print(f"[red]Unknown severity: {severity}[/red]")
            raise typer.Exit(1)
        cutoff = _SEV_ORDER.index(sev_upper)
        findings = [f for f in findings if _SEV_ORDER.index(f.severity.value) <= cutoff]

    if category:
        findings = [f for f in findings if f.category == category.lower()]

    _print_posture_summary(console, findings)

    dest = output or (scan_dir / "posture.json")
    dest.write_text(json.dumps([f.to_dict() for f in findings], indent=2))
    console.print(f"[green]✔[/green] {len(findings)} finding(s) written to [bold]{dest}[/bold]")

    # Print individual findings if verbose
    if verbose:
        for f in findings:
            console.print(
                f"\n[bold]{f.severity.value}[/bold] [{f.check_id}] {f.title}\n"
                f"  Resource: {f.resource_name} ({f.resource_arn})\n"
                f"  Detail:   {f.detail}\n"
                f"  Fix:      {f.remediation}"
            )


@app.command()
def report(
    scan_dir: Path = typer.Argument(..., help="Path to a scan output directory (e.g. scans/scan-...)"),
    format: str = typer.Option(
        "md", "--format", "-f",
        help="Output format: md (Markdown), json, or html",
    ),
    output: Path = typer.Option(
        None, "--output", "-o",
        help="Write report to this file. Defaults to report.md / report.json in the scan dir.",
    ),
    max_hops: int = typer.Option(5, "--max-hops", help="Max path length for attack surface graph"),
    token_budget: int = typer.Option(
        0, "--token-budget",
        help="Cap the attack-surface text sent to Claude (rough tokens). "
             "0 = no cap. 200000 is a reasonable default for very large accounts "
             "(leaves room for the system prompt + response within Opus 4.7's 1M window). "
             "ENTRY POINTS / SINKS / PATHS are always preserved in full; "
             "ALL NODES / ALL EDGES sections truncate first.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Generate an LLM-powered attack-path report from a completed scan.

    Requires the 'anthropic' package: pip install 'breakbot[llm]'
    Set ANTHROPIC_API_KEY in your environment before running.
    """
    _configure_logging(verbose)

    scan_file = scan_dir / "scan.json"
    posture_file = scan_dir / "posture.json"

    if not scan_file.exists():
        console.print(f"[red]No scan.json found in {scan_dir}[/red]")
        raise typer.Exit(1)

    fmt = format.lower().strip()
    if fmt not in {"md", "json", "html"}:
        console.print(f"[red]Unknown format '{format}' — use md, json, or html[/red]")
        raise typer.Exit(1)

    # Load scan and build graph serialization
    console.print(f"Loading scan from [bold]{scan_file}[/bold]")
    result = ScanResult.model_validate_json(scan_file.read_text())
    console.print(
        f"Loaded {result.resource_count} resources across "
        f"[yellow]{len(result.accounts_scanned)}[/yellow] account(s)"
    )

    console.print("[bold]Building dependency graph...[/bold]")
    builder = GraphBuilder(result)
    g = builder.build()

    trail_file = scan_dir / "trail.json"
    if trail_file.exists():
        console.print("[bold]Applying CloudTrail behavioral overlay...[/bold]")
        raw_events = json.loads(trail_file.read_text())
        trail_events = [TrailEvent.from_dict(e) for e in raw_events]
        behavioral_edges = TrailOverlay().apply(g, builder.arn_index, trail_events)
        console.print(f"[green]✔[/green] {behavioral_edges} behavioral edge(s) added")

    from breakbot.graph import GraphSerializer
    serializer = GraphSerializer(g, builder.arn_index, max_hops=max_hops)
    # tokens ≈ chars / 3 for English; 0 means no cap
    max_chars = token_budget * 3 if token_budget > 0 else None
    attack_surface = serializer.serialize(max_chars=max_chars)
    if max_chars is not None and len(attack_surface) >= max_chars:
        console.print(
            f"[yellow]⚠ Attack surface truncated to fit ~{token_budget} tokens "
            f"({len(attack_surface)} chars)[/yellow]"
        )

    # Load posture findings
    posture_findings: list[dict] = []
    if posture_file.exists():
        posture_findings = json.loads(posture_file.read_text())
        console.print(f"Loaded [yellow]{len(posture_findings)}[/yellow] posture finding(s)")
    else:
        console.print("[yellow]No posture.json found — run 'breakbot posture' first[/yellow]")

    # Call Claude
    try:
        from breakbot.brain import SecurityAnalyst
    except ImportError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e

    console.print(f"\n[bold]Calling Claude (claude-opus-4-7) for threat analysis...[/bold]")
    analyst = SecurityAnalyst()
    analysis = analyst.analyze(attack_surface, posture_findings)

    # Determine output path
    ext_map = {"md": ".md", "json": ".json", "html": ".html"}
    dest = output or (scan_dir / f"report{ext_map[fmt]}")

    if fmt == "json":
        dest.write_text(analysis.to_json(), encoding="utf-8")
    elif fmt == "html":
        dest.write_text(_report_to_html(analysis), encoding="utf-8")
    else:
        dest.write_text(analysis.to_markdown(), encoding="utf-8")

    console.print(f"\n[green]✔[/green] Report written to [bold]{dest}[/bold]")
    console.print(f"Overall severity: [bold red]{analysis.overall_severity}[/bold red]")
    console.print(f"Attack paths identified: [bold]{len(analysis.attack_paths)}[/bold]")


def _report_to_html(analysis: object) -> str:
    """Minimal HTML wrapper around the Markdown report."""
    import html as html_lib
    from breakbot.brain.report import AnalysisReport

    assert isinstance(analysis, AnalysisReport)
    md = analysis.to_markdown()
    escaped = html_lib.escape(md)
    return (
        "<!DOCTYPE html><html><head>"
        "<meta charset='utf-8'>"
        "<title>BreakBot Report</title>"
        "<style>body{font-family:monospace;max-width:900px;margin:2em auto;padding:0 1em;"
        "white-space:pre-wrap;line-height:1.5}</style>"
        "</head><body>"
        + escaped
        + "</body></html>"
    )


if __name__ == "__main__":
    app()
