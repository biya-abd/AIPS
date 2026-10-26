"""
AIPS FastAPI application.

Wires together: config validation -> database -> audit trail -> background
tasks (log collector, synthetic event generator, honeypot, expired-block
sweeper) -> REST API -> SSE live stream -> static dashboard.

Run with:  uvicorn app.main:app --host 127.0.0.1 --port 8080
(or use ./start.sh, which does exactly this inside the venv)
"""
from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .ai import openrouter_client
from .audit import AuditTrail
from .collectors.log_collector import run_collector
from .config import require_valid_config
from .database import Database
from .detection.rules import evaluate_event
from .honeypot.honeypot_server import run_honeypot
from .response import enforcement
from .simulator import run_simulator
from .ws_manager import broadcaster, sse_event_stream

cfg = require_valid_config()
db = Database(cfg.db_path)
audit = AuditTrail(db, cfg.audit_log_path)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

_background_tasks: list[asyncio.Task] = []
_stop_event = asyncio.Event()


def _on_live_event(event: dict) -> None:
    broadcaster.publish({"type": "event", "data": {k: v for k, v in event.items() if k != "raw_line"}})
    detections = evaluate_event(db, event, cfg)
    for d in detections:
        broadcaster.publish({"type": "detection", "data": d})
        audit.record("rules_engine", "detection", f"{d['rule_name']} ip={d['source_ip']} score={d['risk_score']}", "ok")


def _on_honeypot_event(event: dict) -> None:
    broadcaster.publish({"type": "honeypot", "data": event})


async def _sweeper_loop():
    while not _stop_event.is_set():
        removed = enforcement.sweep_expired_blocks(db, audit, cfg)
        if removed:
            broadcaster.publish({"type": "sweep", "data": {"expired_removed": removed}})
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.set_setting("started_at", str(time.time()))
    db.set_setting("mode", cfg.mode)
    db.set_setting("ai_enabled", "true" if cfg.ai_enabled else "false")
    audit.record("system", "startup", f"mode={cfg.mode} ai_enabled={cfg.ai_enabled} host={cfg.host}:{cfg.port}", "ok")

    _background_tasks.append(asyncio.create_task(
        run_simulator(db, cfg, on_event=broadcaster.publish, stop_event=_stop_event)
    ))
    _background_tasks.append(asyncio.create_task(run_collector(db, cfg, on_event=_on_live_event, stop_event=_stop_event)))
    if cfg.honeypot_enabled:
        _background_tasks.append(asyncio.create_task(run_honeypot(cfg, db, audit, on_event=_on_honeypot_event, stop_event=_stop_event)))
    _background_tasks.append(asyncio.create_task(_sweeper_loop()))

    yield

    _stop_event.set()
    audit.record("system", "shutdown", "AIPS stopping", "ok")
    for t in _background_tasks:
        t.cancel()


app = FastAPI(title="AIPS", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _label_or_none(request: Request) -> str | None:
    label = request.query_params.get("label")
    if label and label.upper() in ("REAL", "SIMULATED", "TEST"):
        return label.upper()
    return None


def _row_to_dict(row) -> dict:
    return {k: row[k] for k in row.keys()}


# ---------------------------------------------------------------- pages ----
@app.get("/")
async def dashboard_page():
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.get("/health")
async def health():
    return {"status": "ok", "mode": cfg.mode, "db": "ok"}


# ------------------------------------------------------------- overview ----
@app.get("/api/overview")
async def overview():
    started_at = float(db.get_setting("started_at", str(time.time())))
    uptime_seconds = int(time.time() - started_at)
    last_ai = db.last_ai_status()
    recent = db.recent_events(limit=1, label_filter="REAL")
    last_event_ts = recent[0]["ts"] if recent else None

    collector_configured = bool(cfg.target_access_log_path)
    sensor_status = "online_real" if collector_configured else "no_real_sensor_configured"

    return {
        "name": "AIPS",
        "project": "INSA CTC Project",
        "mode": cfg.mode,
        "sensor_status": sensor_status,
        "collector_configured": collector_configured,
        "target_bind_scope": cfg.target_bind_scope,
        "backend_status": "healthy",
        "events_per_minute": db.event_count_last_minute("REAL"),
        "last_event_ts": last_event_ts,
        "ai_provider": "OpenRouter",
        "ai_model": cfg.openrouter_model,
        "ai_last_status": _row_to_dict(last_ai) if last_ai else None,
        "uptime_seconds": uptime_seconds,
        "event_generator_running": db.get_setting("event_generator_running", "false") == "true",
        "honeypot_enabled": cfg.honeypot_enabled,
        "current_threat_score": db.current_threat_score("REAL"),
        "total_events_real": db.total_event_count("REAL"),
        "total_events_simulated": db.total_event_count("SIMULATED"),
        "severity_distribution": db.severity_distribution("REAL"),
    }


@app.get("/api/series/events-per-minute")
async def events_per_minute_series(minutes: int = 60, label: str = "REAL"):
    return db.events_per_minute_series(minutes=minutes, label_filter=label)


@app.get("/api/series/risk-trend")
async def risk_trend_series(hours: int = 1, label: str = "REAL"):
    return db.risk_trend_series(hours=hours, label_filter=label)


# ---------------------------------------------------------------- events ----
@app.get("/api/events")
async def list_events(request: Request, limit: int = 100):
    label = _label_or_none(request)
    rows = db.recent_events(limit=limit, label_filter=label)
    return [_row_to_dict(r) for r in rows]


# ------------------------------------------------------------ detections ----
@app.get("/api/detections")
async def list_detections(request: Request, limit: int = 100):
    label = _label_or_none(request)
    rows = db.recent_detections(limit=limit, label_filter=label)
    out = []
    for r in rows:
        d = _row_to_dict(r)
        try:
            d["evidence"] = json.loads(d.pop("evidence_json"))
        except (json.JSONDecodeError, TypeError):
            d["evidence"] = {}
        out.append(d)
    return out


@app.post("/api/detections/{detection_id}/status")
async def set_detection_status(detection_id: str, payload: dict):
    status = payload.get("status")
    if status not in ("new", "investigating", "analyzed", "closed"):
        raise HTTPException(400, "status must be one of new|investigating|analyzed|closed")
    db.update_detection_status(detection_id, status)
    audit.record("operator", "detection_status_change", f"{detection_id} -> {status}", "ok")
    return {"detection_id": detection_id, "status": status}


@app.post("/api/detections/{detection_id}/analyze")
async def analyze_detection_endpoint(detection_id: str):
    rows = db.recent_detections(limit=1000)
    row = next((r for r in rows if r["detection_id"] == detection_id), None)
    if not row:
        raise HTTPException(404, "detection not found")
    detection = _row_to_dict(row)
    result = await openrouter_client.analyze_detection(detection, cfg, db)
    audit.record("ai_analysis", "analyze_requested", f"{detection_id} ok={result['ok']}", "ok" if result["ok"] else "error")
    return result


# --------------------------------------------------------------- respond ----
@app.get("/api/responses")
async def list_responses(limit: int = 100):
    return [_row_to_dict(r) for r in db.recent_responses(limit=limit)]


@app.post("/api/responses/block")
async def request_block(payload: dict):
    """Requests (and, only in enforcement mode with approved=true, applies)
    a block. In monitor mode or without approval, this records what WOULD
    happen without changing anything -- see enforcement.apply_block."""
    target_ip = payload.get("target_ip")
    if not target_ip:
        raise HTTPException(400, "target_ip is required")
    try:
        result = enforcement.apply_block(
            db, audit, cfg,
            target_ip=target_ip,
            reason=payload.get("reason", "manual request"),
            rule_applied=payload.get("rule_applied", "manual"),
            requested_by=payload.get("requested_by", "dashboard_operator"),
            approved=bool(payload.get("approved", False)),
            duration_minutes=payload.get("duration_minutes"),
            detection_id=payload.get("detection_id"),
            source_label=payload.get("source_label", "REAL"),
        )
    except enforcement.EnforcementError as exc:
        raise HTTPException(400, str(exc))
    broadcaster.publish({"type": "response", "data": result})
    return result


@app.post("/api/responses/{response_id}/rollback")
async def rollback_response(response_id: str, payload: dict = None):
    try:
        result = enforcement.rollback_block(
            db, audit, cfg, response_id=response_id,
            requested_by=(payload or {}).get("requested_by", "dashboard_operator"),
        )
    except enforcement.EnforcementError as exc:
        raise HTTPException(404, str(exc))
    broadcaster.publish({"type": "response", "data": result})
    return result


# -------------------------------------------------------------- honeypot ----
@app.get("/api/honeypot/events")
async def honeypot_events(limit: int = 50):
    return [_row_to_dict(r) for r in db.recent_honeypot_events(limit=limit)]


@app.get("/api/honeypot/stats")
async def honeypot_stats():
    since = time.time() - 86400
    return {
        "enabled": cfg.honeypot_enabled,
        "interactions_24h": len(db.recent_honeypot_events(limit=10000)),
        "unique_ips_24h": db.honeypot_unique_ip_count(since),
    }


# ------------------------------------------------------------------ audit ----
@app.get("/api/audit")
async def audit_log(limit: int = 200):
    return [_row_to_dict(r) for r in db.recent_audit(limit=limit)]


@app.get("/api/audit/verify")
async def audit_verify():
    ok, message = audit.verify()
    return {"ok": ok, "message": message}


# -------------------------------------------------------------- ai status ----
@app.get("/api/ai/status")
async def ai_status():
    result = await openrouter_client.health_check(cfg, db)
    return result


# ------------------------------------------------------------- settings ----
@app.get("/api/settings")
async def get_settings():
    return {
        "mode": db.get_setting("mode", cfg.mode),
        "ai_enabled": db.get_setting("ai_enabled", "true" if cfg.ai_enabled else "false") == "true",
        "event_generator_running": db.get_setting("event_generator_running", "false") == "true",
        "honeypot_enabled": cfg.honeypot_enabled,
        "target_bind_scope": cfg.target_bind_scope,
        "target_access_log_path": cfg.target_access_log_path,
    }


@app.post("/api/settings/event-generator")
async def toggle_event_generator(payload: dict):
    running = bool(payload.get("running", False))
    db.set_setting("event_generator_running", "true" if running else "false")
    audit.record("operator", "event_generator_toggled", f"running={running}", "ok")
    return {"event_generator_running": running}


@app.post("/api/settings/mode")
async def change_mode(payload: dict):
    """NOTE: changing AIPS_MODE here only affects the running process's
    in-memory/db setting used for display + the enforcement gate check;
    the authoritative startup value still comes from .env. This lets you
    demo monitor vs enforcement without restarting, while keeping the
    default on every fresh start equal to whatever is in .env."""
    mode = payload.get("mode")
    if mode not in ("monitor", "enforcement"):
        raise HTTPException(400, "mode must be monitor or enforcement")
    cfg.mode = mode
    db.set_setting("mode", mode)
    audit.record("operator", "mode_changed", f"mode={mode}", "ok")
    return {"mode": mode}


# ---------------------------------------------------------------- stream ----
@app.get("/api/stream")
async def stream():
    q = broadcaster.subscribe()

    async def gen():
        try:
            async for chunk in sse_event_stream(q):
                yield chunk
        finally:
            broadcaster.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream")
