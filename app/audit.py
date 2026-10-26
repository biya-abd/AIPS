"""
Audit logging for AIPS.

Writes every audit event to two places:
  1. the `audit_log` SQLite table (queryable from the dashboard), and
  2. an append-only, hash-chained text file on disk.

The hash chain (`prev_hash` of each line is the SHA-256 of the previous
line) means that if an ordinary application user -- i.e. someone without
direct filesystem/root access -- edits or deletes a past line through the
app, the chain breaks and `verify_audit_file()` will say so. This is
"tamper-resistant to ordinary application users", NOT tamper-proof against
someone with root or direct disk access; the project requirements ask for
the former, and claiming the latter would be dishonest.

The file is created with 0600 permissions (owner read/write only).
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path


class AuditTrail:
    def __init__(self, db, file_path: str):
        self.db = db
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.file_path.exists():
            self.file_path.touch()
        try:
            os.chmod(self.file_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # best-effort on filesystems that don't support it (e.g. some test envs)

    def _last_hash(self) -> str:
        if self.file_path.stat().st_size == 0:
            return "0" * 64
        with open(self.file_path, "rb") as f:
            lines = f.readlines()
        if not lines:
            return "0" * 64
        try:
            last = json.loads(lines[-1].decode("utf-8"))
            return last["this_hash"]
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
            return "CHAIN_READ_ERROR"

    def record(self, actor: str, action: str, details: str, outcome: str) -> None:
        self.db.write_audit(actor, action, details, outcome)
        prev_hash = self._last_hash()
        entry = {
            "ts": time.time(),
            "actor": actor,
            "action": action,
            "details": details,
            "outcome": outcome,
            "prev_hash": prev_hash,
        }
        this_hash = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode("utf-8")
        ).hexdigest()
        entry["this_hash"] = this_hash
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    def verify(self) -> tuple[bool, str]:
        """Walks the chain and returns (ok, message)."""
        if not self.file_path.exists() or self.file_path.stat().st_size == 0:
            return True, "empty audit file -- nothing to verify"
        expected_prev = "0" * 64
        with open(self.file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"line {i}: not valid JSON -- file corrupted or tampered"
                if entry.get("prev_hash") != expected_prev:
                    return False, f"line {i}: chain broken (prev_hash mismatch)"
                recomputed = {k: v for k, v in entry.items() if k != "this_hash"}
                recomputed_hash = hashlib.sha256(
                    json.dumps(recomputed, sort_keys=True).encode("utf-8")
                ).hexdigest()
                if recomputed_hash != entry.get("this_hash"):
                    return False, f"line {i}: hash mismatch -- content modified after write"
                expected_prev = entry["this_hash"]
        return True, "chain verified OK"
