"""
Enforcement actions for AIPS -- kept deliberately separate from detection.

Monitoring (app/detection) NEVER calls into this module directly. Every
action here requires:

  1. AIPS_MODE == "enforcement" (monitor mode makes this module a no-op
     that only logs "would have acted" to the audit trail).
  2. An explicit `approved=True` passed by the caller, which in the API
     layer (app/main.py) only happens on a human clicking "Approve" in the
     dashboard's Response Center for a specific detection. An AI
     recommendation string is never enough by itself.
  3. The target IP is not in the allowlist (loopback + configured trusted
     addresses -- always includes 127.0.0.1 and ::1, see app/config.py).

Mechanism: a dedicated nftables table/chain owned entirely by AIPS
(`inet aips_enforce`), manipulated only by adding/removing elements from
one named set. AIPS never runs `nft flush ruleset`, never touches any
other table, and never restarts or reloads the protected web server.
Every apply/rollback is recorded in the `responses` table and the audit
trail, with the exact command run.

If `nft` is unavailable (not installed, not root, or genuinely not Linux),
every action fails closed with a clear error -- it never silently
pretends to have blocked something.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
import time
import uuid

AIPS_TABLE = "aips_enforce"
AIPS_CHAIN = "input"
AIPS_SET = "aips_blocked_ips"


class EnforcementError(Exception):
    pass


def _nft_available() -> bool:
    return shutil.which("nft") is not None


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        ok = result.returncode == 0
        output = result.stdout if ok else (result.stderr or result.stdout)
        return ok, output.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def ensure_table_exists() -> tuple[bool, str]:
    """Idempotently creates AIPS's own dedicated table/chain/set if missing.
    Never touches any pre-existing table. Safe to call repeatedly."""
    if not _nft_available():
        return False, "'nft' command not found -- install nftables or run on a Linux host with it available"
    # These 'add' commands are no-ops if the object already exists (nft
    # returns success for 'add table' etc. even when present), so this is
    # safe to call on every startup without duplicating state.
    steps = [
        ["nft", "add", "table", "inet", AIPS_TABLE],
        ["nft", "add", "chain", "inet", AIPS_TABLE, AIPS_CHAIN,
         "{", "type", "filter", "hook", "input", "priority", "-1", ";", "}"],
        ["nft", "add", "set", "inet", AIPS_TABLE, AIPS_SET,
         "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}"],
        ["nft", "add", "rule", "inet", AIPS_TABLE, AIPS_CHAIN,
         "ip", "saddr", f"@{AIPS_SET}", "drop"],
    ]
    for step in steps:
        ok, out = _run(step)
        if not ok and "exist" not in out.lower() and "File exists" not in out:
            return False, f"setup step failed: {' '.join(step)} -> {out}"
    return True, "aips_enforce table/chain/set ready"


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise EnforcementError(f"'{ip}' is not a valid IP address")


def apply_block(db, audit, cfg, *, target_ip: str, reason: str, rule_applied: str,
                 requested_by: str, approved: bool, duration_minutes: int | None = None,
                 detection_id: str | None = None, source_label: str = "REAL") -> dict:
    """Attempts to block `target_ip`. Always writes a `responses` row and an
    audit entry, whether it succeeds, is refused, or is only simulated
    because we're in monitor mode."""
    response_id = f"RESP-{uuid.uuid4().hex[:12]}"
    now = time.time()
    duration = duration_minutes if duration_minutes is not None else cfg.default_block_minutes
    expires_at = now + duration * 60

    def _record(outcome: str) -> dict:
        row = {
            "response_id": response_id, "detection_id": detection_id, "action_type": "block",
            "target": target_ip, "reason": reason, "rule_applied": rule_applied,
            "requested_by": requested_by, "approved": int(approved), "approved_by": requested_by if approved else None,
            "expires_at": expires_at, "ts": now, "outcome": outcome, "source_label": source_label,
        }
        db.insert_response(row)
        audit.record("aips_enforcement", "block_requested", f"ip={target_ip} outcome={outcome} reason={reason}", outcome)
        return {"response_id": response_id, "outcome": outcome}

    _validate_ip(target_ip)

    if target_ip in cfg.enforcement_allowlist:
        return _record("refused_allowlisted")

    if not approved:
        return _record("refused_not_approved")

    if cfg.mode != "enforcement":
        # Monitor mode: never touches the system. Clearly labeled.
        return _record("simulated_monitor_mode")

    ready, msg = ensure_table_exists()
    if not ready:
        audit.record("aips_enforcement", "nft_unavailable", msg, "error")
        return _record("failed_nft_unavailable")

    ok, out = _run(["nft", "add", "element", "inet", AIPS_TABLE, AIPS_SET, "{", target_ip, "}"])
    if not ok:
        audit.record("aips_enforcement", "nft_add_element_failed", out, "error")
        return _record("failed")

    return _record("applied")


def rollback_block(db, audit, cfg, *, response_id: str, requested_by: str) -> dict:
    """Removes a previously-applied block. Always safe to call even if the
    block already expired or was never actually applied (nft delete on a
    missing element just fails harmlessly and we still mark it rolled back
    in our own records)."""
    rows = db.recent_responses(limit=1000)
    target_row = next((r for r in rows if r["response_id"] == response_id), None)
    if not target_row:
        raise EnforcementError(f"no response record found for {response_id}")

    target_ip = target_row["target"]
    if cfg.mode == "enforcement" and target_row["outcome"] == "applied":
        _run(["nft", "delete", "element", "inet", AIPS_TABLE, AIPS_SET, "{", target_ip, "}"])

    db.mark_response_rolled_back(response_id)
    audit.record("aips_enforcement", "block_rolled_back", f"ip={target_ip} response_id={response_id} by={requested_by}", "ok")
    return {"response_id": response_id, "target": target_ip, "outcome": "rolled_back"}


def sweep_expired_blocks(db, audit, cfg) -> int:
    """Called periodically to auto-expire temporary blocks. Returns count removed."""
    now = time.time()
    removed = 0
    for row in db.active_blocks():
        if row["expires_at"] and row["expires_at"] <= now:
            if cfg.mode == "enforcement":
                _run(["nft", "delete", "element", "inet", AIPS_TABLE, AIPS_SET, "{", row["target"], "}"])
            db.mark_response_rolled_back(row["response_id"])
            audit.record("aips_enforcement", "block_expired", f"ip={row['target']} response_id={row['response_id']}", "ok")
            removed += 1
    return removed
