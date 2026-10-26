"""
Synthetic event generator for AIPS demos.

This exists because a project demo needs *something* happening on screen
without requiring a live attack against your own box during a presentation.
Every event and detection produced here carries source_label='SIMULATED'
and is:
  - excluded from the REAL aggregate counters (events/min, total events,
    severity distribution) used elsewhere on the dashboard,
  - visually distinguished in the UI,
  - run through the exact same detection/risk-scoring code path as real
    events (so what you demo is representative of real behavior, not a
    separately-faked "looks right" number),
  - NEVER eligible to trigger an actual enforcement action -- the
    enforcement module is only ever called with real, human-approved
    detections from app/main.py's response endpoints.

Toggle on/off via the "Event Generator" control in Quick Controls, which
sets the `event_generator_running` setting this loop polls.
"""
from __future__ import annotations

import asyncio
import random
import time
import uuid

from .detection.rules import evaluate_event

FAKE_SOURCE_IPS = [
    "192.168.1.45", "192.168.1.10", "192.168.1.33",
    "10.0.2.8", "10.0.2.9",
    "203.0.113.12", "198.51.100.23",
]
FAKE_DEST = "10.0.2.5"
NORMAL_PATHS = ["/", "/about", "/images/logo.png", "/favicon.ico", "/api/health"]
LOGIN_PATHS = ["/login", "/admin/login"]
SCAN_PATHS = ["/.env", "/.git/config", "/wp-admin", "/phpmyadmin", "/admin", "/backup.zip"]
TRAVERSAL_PATHS = ["/../../etc/passwd", "/files?name=..%2f..%2fetc%2fpasswd"]
USER_AGENTS = ["Mozilla/5.0", "curl/8.4.0", "python-requests/2.31", "Nmap Scripting Engine"]

SCENARIOS = ["normal", "brute_force", "port_scan", "web_attack"]
SCENARIO_WEIGHTS = [0.55, 0.15, 0.15, 0.15]


def _make_event(source_ip: str, method: str, path: str, status: int) -> dict:
    return {
        "event_id": f"SIM-{uuid.uuid4().hex[:12]}",
        "ts": time.time(),
        "source_ip": source_ip,
        "destination": FAKE_DEST,
        "method": method,
        "path": path,
        "status_code": status,
        "bytes_sent": random.randint(100, 5000),
        "user_agent": random.choice(USER_AGENTS),
        "raw_line": f"[SIMULATED] {method} {path} -> {status}",
        "event_type": "http_request",
        "source_label": "SIMULATED",
    }


def _generate_one() -> dict:
    scenario = random.choices(SCENARIOS, weights=SCENARIO_WEIGHTS, k=1)[0]
    ip = random.choice(FAKE_SOURCE_IPS)
    if scenario == "normal":
        return _make_event(ip, "GET", random.choice(NORMAL_PATHS), random.choice([200, 200, 200, 304]))
    if scenario == "brute_force":
        return _make_event(ip, "POST", random.choice(LOGIN_PATHS), random.choice([401, 401, 403]))
    if scenario == "port_scan":
        return _make_event(ip, "GET", f"/{uuid.uuid4().hex[:6]}", 404)
    # web_attack: mix of suspicious-path probing and traversal
    path = random.choice(SCAN_PATHS + TRAVERSAL_PATHS)
    return _make_event(ip, "GET", path, random.choice([403, 404, 400]))


async def run_simulator(db, cfg, on_event=None, stop_event: asyncio.Event | None = None, interval_seconds: float = 2.0):
    while True:
        if stop_event and stop_event.is_set():
            return
        running = db.get_setting("event_generator_running", "false") == "true"
        if running:
            event = _generate_one()
            db.insert_event(event)
            detections = evaluate_event(db, event, cfg)
            if on_event:
                on_event({"type": "event", "data": event})
                for d in detections:
                    on_event({"type": "detection", "data": d})
        await asyncio.sleep(interval_seconds)
