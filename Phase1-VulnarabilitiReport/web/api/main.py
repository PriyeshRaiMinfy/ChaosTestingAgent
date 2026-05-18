"""
BreakBot Web API — thin FastAPI wrapper around the CLI/scanner logic.

Endpoints:
  POST /api/validate-credentials  — check AWS creds, return account info
  POST /api/discover              — run org discovery
  GET  /api/regions               — list enabled regions
  POST /api/scan                  — start a scan (returns scan_id)
  GET  /api/scan/{scan_id}/status — poll scan status
  WS   /api/scan/{scan_id}/ws    — live scan progress stream
  GET  /api/scans                 — list past scans
  GET  /api/scan/{scan_id}/report — get generated report
  GET  /api/scan/{scan_id}/posture — get posture findings
  GET  /api/scan/{scan_id}/graph  — get graph HTML
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

logger = logging.getLogger(__name__)

app = FastAPI(title="BreakBot API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCANS_DIR = Path(os.environ.get("SCANS_DIR", str(Path(__file__).resolve().parents[2] / "scans")))

# In-memory scan state (PoC — no database)
_active_scans: dict[str, dict[str, Any]] = {}


# ─────────────────── Request/Response Models ───────────────────────────


class CredentialInput(BaseModel):
    access_key_id: str | None = None
    secret_access_key: str | None = None
    profile: str | None = "default"
    region: str = "ap-south-1"


class ScanConfig(BaseModel):
    region: str = "ap-south-1"
    all_regions: bool = False
    trail_enabled: bool = False
    trail_mode: str = "fast"
    trail_days: int = 14
    trail_regions: str = ""
    trail_max_pages: int = 20
    access_key_id: str | None = None
    secret_access_key: str | None = None
    profile: str | None = "default"


class ScanStatus(BaseModel):
    scan_id: str
    status: str  # "running", "completed", "failed"
    progress: int  # 0-100
    resources_found: int
    errors: int
    current_domain: str | None = None
    started_at: str
    completed_at: str | None = None


class AccountInfo(BaseModel):
    account_id: str
    is_org: bool
    org_id: str | None = None
    account_count: int = 1
    regions_enabled: list[str] = []
    org_trail_accessible: bool = False


# ─────────────────── Endpoints ─────────────────────────────────────────


@app.post("/api/validate-credentials", response_model=AccountInfo)
async def validate_credentials(creds: CredentialInput):
    """Validate AWS credentials and return account info."""
    def _validate():
        from breakbot.utils import AWSSession
        if creds.access_key_id and creds.secret_access_key:
            session = AWSSession(
                region=creds.region,
                credentials={
                    "AccessKeyId": creds.access_key_id,
                    "SecretAccessKey": creds.secret_access_key,
                },
            )
        else:
            session = AWSSession(region=creds.region, profile=creds.profile)
        return session.account_id, session.enabled_regions()

    try:
        loop = asyncio.get_event_loop()
        account_id, regions = await asyncio.wait_for(
            loop.run_in_executor(None, _validate), timeout=20
        )
        return AccountInfo(account_id=account_id, is_org=False, regions_enabled=regions)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="AWS STS timed out. Check network/credentials.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/discover", response_model=AccountInfo)
async def discover(creds: CredentialInput):
    """Run environment discovery — single vs org, trail access."""
    def _discover():
        from breakbot.utils import AWSSession
        from breakbot.org.discovery import EnvironmentDiscovery
        if creds.access_key_id and creds.secret_access_key:
            session = AWSSession(
                region=creds.region,
                credentials={
                    "AccessKeyId": creds.access_key_id,
                    "SecretAccessKey": creds.secret_access_key,
                },
            )
        else:
            session = AWSSession(region=creds.region, profile=creds.profile)
        disc = EnvironmentDiscovery(session)
        result = disc.detect(check_assume=False)
        return AccountInfo(
            account_id=result.current_account_id,
            is_org=result.is_org,
            org_id=result.org_id,
            account_count=len(result.accounts) if result.accounts else 1,
            regions_enabled=session.enabled_regions(),
            org_trail_accessible=result.has_org_trail_access,
        )

    try:
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, _discover), timeout=25
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="AWS discovery timed out. Check network/credentials.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/regions")
async def list_regions(profile: str = "default", region: str = "ap-south-1"):
    """List enabled AWS regions for the account."""
    try:
        from breakbot.utils import AWSSession
        session = AWSSession(region=region, profile=profile)
        return {"regions": session.enabled_regions()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/scan")
async def start_scan(config: ScanConfig):
    """Start a new scan. Returns scan_id immediately, runs in background."""
    scan_id = f"scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    _active_scans[scan_id] = {
        "status": "running",
        "progress": 0,
        "resources_found": 0,
        "errors": 0,
        "current_domain": None,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "logs": [],
    }

    # Set trail from trail_mode
    if config.trail_mode == 'deep':
        config.trail_days = 90
        config.trail_max_pages = 100
    elif config.trail_mode == 'fast':
        config.trail_days = 14
        config.trail_max_pages = 20

    asyncio.get_event_loop().run_in_executor(None, _run_scan_sync, scan_id, config)

    return {"scan_id": scan_id, "status": "running"}


@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get current scan status including logs."""
    if scan_id in _active_scans:
        state = _active_scans[scan_id]
        return {
            "scan_id": scan_id,
            "status": state["status"],
            "progress": state["progress"],
            "resources_found": state["resources_found"],
            "errors": state["errors"],
            "current_domain": state["current_domain"],
            "started_at": state["started_at"],
            "completed_at": state["completed_at"],
            "logs": state["logs"],
        }

    scan_dir = SCANS_DIR / scan_id
    if scan_dir.exists():
        return {
            "scan_id": scan_id,
            "status": "completed",
            "progress": 100,
            "resources_found": 0,
            "errors": 0,
            "current_domain": None,
            "started_at": "",
            "completed_at": None,
            "logs": [],
        }

    raise HTTPException(status_code=404, detail="Scan not found")


@app.websocket("/api/scan/{scan_id}/ws")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket for live scan progress."""
    await websocket.accept()
    last_log_idx = 0

    try:
        while True:
            if scan_id not in _active_scans:
                await websocket.send_json({"type": "error", "message": "Scan not found"})
                break

            state = _active_scans[scan_id]

            # Send new logs
            new_logs = state["logs"][last_log_idx:]
            for log in new_logs:
                await websocket.send_json({"type": "log", "message": log})
            last_log_idx = len(state["logs"])

            # Send status update
            await websocket.send_json({
                "type": "status",
                "progress": state["progress"],
                "resources_found": state["resources_found"],
                "errors": state["errors"],
                "current_domain": state["current_domain"],
                "status": state["status"],
            })

            if state["status"] in ("completed", "failed"):
                await websocket.send_json({"type": "done", "status": state["status"]})
                break

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass


@app.get("/api/scans")
async def list_scans():
    """List all past scans."""
    scans = []
    if SCANS_DIR.exists():
        for scan_dir in sorted(SCANS_DIR.iterdir(), reverse=True):
            if not scan_dir.is_dir() or not scan_dir.name.startswith("scan-"):
                continue
            scan_file = scan_dir / "scan.json"
            if scan_file.exists():
                try:
                    data = json.loads(scan_file.read_text())
                    scans.append({
                        "scan_id": scan_dir.name,
                        "started_at": data.get("started_at", ""),
                        "resource_count": data.get("resource_count", 0),
                        "accounts_scanned": data.get("accounts_scanned", []),
                        "has_trail": (scan_dir / "trail.json").exists(),
                        "has_report": (scan_dir / "report.md").exists(),
                        "has_posture": (scan_dir / "posture.json").exists(),
                    })
                except (json.JSONDecodeError, KeyError):
                    pass
    return {"scans": scans}


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    """Get the generated report."""
    report_file = SCANS_DIR / scan_id / "report.md"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Report not found. Run 'report' first.")
    return {"content": report_file.read_text(encoding="utf-8"), "format": "markdown"}


@app.get("/api/scan/{scan_id}/posture")
async def get_posture(scan_id: str):
    """Get posture findings."""
    posture_file = SCANS_DIR / scan_id / "posture.json"
    if not posture_file.exists():
        raise HTTPException(status_code=404, detail="Posture data not found")
    return json.loads(posture_file.read_text())


@app.get("/api/scan/{scan_id}/graph")
async def get_graph(scan_id: str):
    """Get graph visualization HTML."""
    # Build graph on-the-fly from scan data
    scan_file = SCANS_DIR / scan_id / "scan.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="Scan not found")

    graph_file = SCANS_DIR / scan_id / "graph.html"
    if graph_file.exists():
        return {"html": graph_file.read_text(encoding="utf-8")}

    raise HTTPException(status_code=404, detail="Graph not generated. Run 'graph --html' first.")


@app.get("/api/scan/{scan_id}/summary")
async def get_scan_summary(scan_id: str):
    """Get scan summary stats."""
    scan_file = SCANS_DIR / scan_id / "scan.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="Scan not found")

    data = json.loads(scan_file.read_text())
    posture_file = SCANS_DIR / scan_id / "posture.json"
    trail_file = SCANS_DIR / scan_id / "trail.json"

    posture_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if posture_file.exists():
        findings = json.loads(posture_file.read_text())
        for f in findings:
            sev = f.get("severity", "LOW")
            posture_summary[sev] = posture_summary.get(sev, 0) + 1

    trail_count = 0
    if trail_file.exists():
        trail_data = json.loads(trail_file.read_text())
        trail_count = len(trail_data)

    return {
        "scan_id": scan_id,
        "resource_count": data.get("resource_count", 0),
        "accounts_scanned": data.get("accounts_scanned", []),
        "regions_scanned": data.get("regions_scanned", []),
        "posture_summary": posture_summary,
        "trail_event_count": trail_count,
        "has_report": (SCANS_DIR / scan_id / "report.md").exists(),
    }


# ─────────────────── Background Scan Runner ────────────────────────────


def _run_scan_sync(scan_id: str, config: ScanConfig):
    """Run the scan in a thread, updating _active_scans state."""
    try:
        from breakbot.utils import AWSSession
        from breakbot.scanner import (
            IdentityScanner, NetworkingScanner, ComputeScanner,
            ServerlessScanner, DataScanner, EksScanner, EcsScanner,
            SecretsScanner, MessagingScanner, DnsScanner,
            CloudFrontScanner, WafScanner, ApiGatewayScanner, CognitoScanner,
        )
        from breakbot.models import ScanResult
        from breakbot.posture import PostureAnalyzer
        from breakbot.scanner.cloudtrail import CloudTrailScanner, TrailEvent

        SCANNERS = [
            IdentityScanner, NetworkingScanner, ComputeScanner,
            ServerlessScanner, DataScanner, EksScanner, EcsScanner,
            SecretsScanner, MessagingScanner, DnsScanner,
            CloudFrontScanner, WafScanner, ApiGatewayScanner, CognitoScanner,
        ]

        state = _active_scans[scan_id]

        # Create session
        if config.access_key_id and config.secret_access_key:
            session = AWSSession(
                region=config.region,
                credentials={
                    "AccessKeyId": config.access_key_id,
                    "SecretAccessKey": config.secret_access_key,
                },
            )
        else:
            session = AWSSession(region=config.region, profile=config.profile)

        state["logs"].append(f"Account: {session.account_id}")

        # Determine regions
        regions = session.enabled_regions() if config.all_regions else [config.region]
        state["logs"].append(f"Regions: {', '.join(regions)}")

        # Run scanners in parallel (same as CLI)
        all_resources = []
        all_errors = []
        total_scanners = len(SCANNERS)
        completed_count = 0
        max_workers = min(total_scanners, 10)

        def _run_domain(scanner_cls):
            scanner = scanner_cls(session)
            resources = scanner.scan(regions)
            return scanner.domain, resources, scanner.errors

        state["logs"].append(f"Scanning {total_scanners} domains in parallel (workers={max_workers})")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_run_domain, cls): cls for cls in SCANNERS
            }
            for future in as_completed(futures):
                completed_count += 1
                state["progress"] = int((completed_count / total_scanners) * 80)
                try:
                    domain_name, resources, errors = future.result()
                    all_resources.extend(resources)
                    all_errors.extend(errors)
                    state["resources_found"] = len(all_resources)
                    state["errors"] = len(all_errors)
                    state["current_domain"] = domain_name
                    state["logs"].append(
                        f"[{domain_name}] Evaluated {len(resources)} assets in target regions"
                    )
                except Exception as e:
                    scanner_cls_ref = futures[future]
                    state["logs"].append(f"[{scanner_cls_ref.__name__}] ERROR: {e}")
                    all_errors.append({"domain": "unknown", "error": str(e)})

        state["progress"] = 80
        state["current_domain"] = None

        # Save scan result
        scan_dir = SCANS_DIR / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        started_at = datetime.fromisoformat(state["started_at"])
        regions_seen = sorted({r.region for r in all_resources}) or [config.region]

        result = ScanResult(
            scan_id=scan_id,
            scanner_account_id=session.account_id,
            accounts_scanned=[session.account_id],
            started_at=started_at,
            completed_at=datetime.utcnow(),
            regions_scanned=regions_seen,
            resources=all_resources,
            errors=all_errors,
        )
        (scan_dir / "scan.json").write_text(result.model_dump_json(indent=2))
        state["logs"].append(f"Scan saved: {len(all_resources)} resources")

        # Posture analysis
        state["progress"] = 85
        state["logs"].append("Running posture analysis...")
        posture_findings = PostureAnalyzer().analyze(result)
        (scan_dir / "posture.json").write_text(
            json.dumps([f.to_dict() for f in posture_findings], indent=2)
        )
        state["logs"].append(f"Posture: {len(posture_findings)} findings")

        # CloudTrail (if enabled)
        if config.trail_enabled:
            state["progress"] = 90
            state["logs"].append("Fetching CloudTrail events...")

            trail_regions_str = config.trail_regions.strip()
            if trail_regions_str.lower() == "all":
                ct_regions = session.enabled_regions()
            elif trail_regions_str:
                ct_regions = [r.strip() for r in trail_regions_str.split(",") if r.strip()]
            else:
                ct_regions = sorted(set([config.region, "us-east-1"]))

            scanner = CloudTrailScanner()
            trail_events = scanner.scan(
                session, ct_regions,
                lookback_days=config.trail_days,
                max_pages=config.trail_max_pages,
            )
            trail_dicts = [e.to_dict() for e in trail_events]
            (scan_dir / "trail.json").write_text(json.dumps(trail_dicts, indent=2))
            state["logs"].append(f"CloudTrail: {len(trail_events)} events")

        # Build graph + generate report
        state["progress"] = 95
        state["logs"].append("Building graph and generating report...")

        from breakbot.graph import GraphBuilder, GraphSerializer, TrailOverlay

        builder = GraphBuilder(result)
        g = builder.build()

        # Apply trail overlay if available
        trail_file = scan_dir / "trail.json"
        if trail_file.exists():
            raw_events = json.loads(trail_file.read_text())
            trail_evts = [TrailEvent.from_dict(e) for e in raw_events]
            TrailOverlay().apply(g, builder.arn_index, trail_evts)

        # Save graph HTML
        try:
            from breakbot.graph.visualize import render_html
            render_html(g, str(scan_dir / "graph.html"))
        except ImportError:
            pass

        # Generate report via Claude
        try:
            from breakbot.brain import SecurityAnalyst
            serializer = GraphSerializer(g, builder.arn_index)
            attack_surface = serializer.serialize_for_llm()

            _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            posture_dicts = [f.to_dict() for f in posture_findings]
            posture_dicts.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "INFO"), 9))
            top_posture = posture_dicts[:50]

            analyst = SecurityAnalyst(use_bedrock=True, region=config.region)
            analysis = analyst.analyze(attack_surface, top_posture)
            (scan_dir / "report.md").write_text(analysis.to_markdown(), encoding="utf-8")
            state["logs"].append(f"Report: {len(analysis.attack_paths)} attack paths")
        except Exception as e:
            state["logs"].append(f"Report generation failed: {e}")

        state["progress"] = 100
        state["status"] = "completed"
        state["completed_at"] = datetime.utcnow().isoformat()
        state["logs"].append("Scan complete!")

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        state = _active_scans.get(scan_id, {})
        state["status"] = "failed"
        state["logs"].append(f"FATAL: {e}")


# ─────────────────── Entry Point ───────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
