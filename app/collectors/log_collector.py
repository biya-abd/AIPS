"""
Tails the configured web-server access log and turns each new line into a
structured event. This is the ONLY source of REAL events in AIPS -- nothing
in this file ever fabricates data.

Supports Apache/Nginx "combined" and "common" log formats. If a line does
not match either pattern, it is still stored (raw_line preserved, fields
best-effort/None) so nothing is silently dropped, and the malformed-request
rule has a chance to flag it.

Log rotation handling: if the file shrinks or its inode changes between
polls, the tailer assumes rotation and reopens from the start of the new
file rather than crashing or blocking forever.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator, Callable

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

COMMON_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
)

# e.g. 25/Oct/2026:14:37:21 +0300
APACHE_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(raw_line: str, log_format_hint: str = "combined") -> dict:
    raw_line = raw_line.rstrip("\n")
    patterns = [COMBINED_RE, COMMON_RE] if log_format_hint != "common" else [COMMON_RE, COMBINED_RE]
    for pattern in patterns:
        m = pattern.match(raw_line)
        if m:
            gd = m.groupdict()
            try:
                ts = datetime.strptime(gd["ts"], APACHE_TS_FMT).timestamp()
            except ValueError:
                ts = time.time()
            try:
                bytes_sent = int(gd["bytes"]) if gd["bytes"] not in ("-", "") else 0
            except ValueError:
                bytes_sent = 0
            return {
                "event_id": f"EVT-{uuid.uuid4().hex[:12]}",
                "ts": ts,
                "source_ip": gd["ip"],
                "destination": None,
                "method": gd["method"],
                "path": gd["path"],
                "status_code": int(gd["status"]) if gd["status"].isdigit() else None,
                "bytes_sent": bytes_sent,
                "user_agent": gd.get("ua"),
                "raw_line": raw_line,
                "event_type": "http_request",
            }
    # Unparsed -- preserve the raw line, don't fabricate fields.
    return {
        "event_id": f"EVT-{uuid.uuid4().hex[:12]}",
        "ts": time.time(),
        "source_ip": None,
        "destination": None,
        "method": None,
        "path": raw_line[:200],
        "status_code": None,
        "bytes_sent": 0,
        "user_agent": None,
        "raw_line": raw_line,
        "event_type": "unparsed_log_line",
    }


async def tail_file(path: str, poll_interval: float = 1.0) -> AsyncIterator[str]:
    """Async generator yielding new lines appended to `path`, handling rotation."""
    p = Path(path)
    while not p.exists():
        await asyncio.sleep(poll_interval)
    inode = p.stat().st_ino
    f = open(path, "r", errors="replace")
    f.seek(0, os.SEEK_END)
    try:
        while True:
            line = f.readline()
            if line:
                yield line
                continue
            await asyncio.sleep(poll_interval)
            try:
                st = p.stat()
            except FileNotFoundError:
                continue
            if st.st_ino != inode or st.st_size < f.tell():
                # rotated or truncated -- reopen from the start of the new file
                f.close()
                f = open(path, "r", errors="replace")
                inode = st.st_ino
    finally:
        f.close()


async def run_collector(db, cfg, on_event: Callable[[dict], None], stop_event: asyncio.Event):
    """Main collector loop. `on_event` is called with every parsed event dict
    (already inserted into the DB) so the caller can run detection + broadcast."""
    path = cfg.target_access_log_path
    if not path:
        db.write_audit(
            "system", "collector_not_started",
            "TARGET_ACCESS_LOG_PATH is not set -- run app.collectors.log_discovery and set it in .env",
            "skipped",
        )
        return
    if not Path(path).exists():
        db.write_audit("system", "collector_not_started", f"log path does not exist: {path}", "error")
        return

    db.write_audit("system", "collector_started", f"tailing {path}", "ok")
    async for raw_line in tail_file(path):
        if stop_event.is_set():
            break
        event = parse_line(raw_line, cfg.target_log_format)
        event["source_label"] = "REAL"
        db.insert_event(event)
        on_event(event)
