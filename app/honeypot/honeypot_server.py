"""
Low-interaction HTTP honeypot for AIPS.

Deliberately minimal:
  - Listens on its OWN configurable port (HONEYPOT_PORT), never shares
    port 80 with the real protected server.
  - Reads and logs the request line + headers (metadata only -- no body
    processing, no file access, no credential harvesting beyond what the
    client sends unprompted in a login-looking path, which is stored as
    opaque text, never parsed/used/forwarded anywhere).
  - ALWAYS returns a generic canned response. Never executes, evals, or
    shells out based on anything in the request.
  - Every connection is written to the honeypot_events table, source_label
    'REAL' (a real TCP client actually connected to it) and kept entirely
    separate from protected-server traffic and statistics.
"""
from __future__ import annotations

import asyncio
import time
import uuid

CANNED_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 13\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"Not Found.\r\n\r\n"
)

MAX_REQUEST_BYTES = 8192  # refuse to buffer unbounded input from a hostile client
READ_TIMEOUT_SECONDS = 5


async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, db):
    peer = writer.get_extra_info("peername")
    source_ip, source_port = (peer[0], peer[1]) if peer else (None, None)
    method, path = None, None
    raw_request = b""
    try:
        raw_request = await asyncio.wait_for(reader.read(MAX_REQUEST_BYTES), timeout=READ_TIMEOUT_SECONDS)
        first_line = raw_request.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        parts = first_line.split(" ")
        if len(parts) >= 2:
            method, path = parts[0][:16], parts[1][:512]
    except (asyncio.TimeoutError, ConnectionError, UnicodeDecodeError):
        pass
    finally:
        try:
            writer.write(CANNED_RESPONSE)
            await writer.drain()
        except ConnectionError:
            pass
        writer.close()

    event = {
        "event_id": f"HP-{uuid.uuid4().hex[:12]}",
        "ts": time.time(),
        "source_ip": source_ip,
        "source_port": source_port,
        "method": method,
        "path": path,
        "raw_request": raw_request[:2048].decode("utf-8", errors="replace"),
        "source_label": "REAL",
    }
    db.insert_honeypot_event(event)
    return event


async def run_honeypot(cfg, db, audit, on_event=None, stop_event: asyncio.Event | None = None):
    if not cfg.honeypot_enabled:
        return

    async def handler(reader, writer):
        event = await _handle_client(reader, writer, db)
        if on_event:
            on_event(event)

    try:
        server = await asyncio.start_server(handler, cfg.host, cfg.honeypot_port)
    except OSError as exc:
        audit.record("aips_honeypot", "start_failed", f"port={cfg.honeypot_port} error={exc}", "error")
        return

    audit.record("aips_honeypot", "started", f"listening on {cfg.host}:{cfg.honeypot_port}", "ok")
    async with server:
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass
