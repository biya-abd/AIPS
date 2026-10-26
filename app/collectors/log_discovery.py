"""
Read-only discovery of the service on port 80.

This script makes NO changes to the system. It only reads process and
socket tables to answer:

  1. Is anything listening on port 80?
  2. Is it bound to 127.0.0.1 only (loopback), 0.0.0.0/a LAN interface
     (lan_exposed), or does something upstream suggest a reverse proxy?
  3. What process owns it, and what are the likely access/error log paths?

Run it directly:
    python3 -m app.collectors.log_discovery

It will NOT guess that the server is Apache or Nginx -- it reports what
it actually finds and tells you to confirm manually if it's uncertain.
Fill the TARGET_* values in your .env based on this script's output.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

KNOWN_LOG_LOCATIONS = {
    "nginx": [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
    ],
    "apache": [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
    ],
}


def run(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return out.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return f"<could not run {' '.join(cmd)}: {e}>"


def find_listeners_on_port_80() -> list[dict]:
    """Parses `ss -ltnp` output for anything on :80. Falls back to `netstat`."""
    listeners = []
    output = run(["ss", "-ltnp"])
    if "<could not run" in output:
        output = run(["netstat", "-ltnp"])

    for line in output.splitlines():
        if ":80 " not in line and not line.rstrip().endswith(":80"):
            continue
        bind_match = re.search(r"((?:\d{1,3}\.){3}\d{1,3}|\[::\]|\*|127\.0\.0\.1):80", line)
        pid_match = re.search(r'pid=(\d+)', line) or re.search(r"(\d+)/(\S+)", line)
        listeners.append({
            "raw_line": line.strip(),
            "bind_address": bind_match.group(1) if bind_match else "unknown",
            "pid": pid_match.group(1) if pid_match else "unknown",
            "process_hint": pid_match.group(2) if pid_match and pid_match.lastindex and pid_match.lastindex >= 2 else "unknown",
        })
    return listeners


def classify_bind_scope(listeners: list[dict]) -> str:
    if not listeners:
        return "unknown"
    addrs = {l["bind_address"] for l in listeners}
    if addrs == {"127.0.0.1"}:
        return "loopback_only"
    if any(a in ("0.0.0.0", "*", "[::]") for a in addrs):
        return "lan_exposed"
    return "unknown"


def guess_process_name(pid: str) -> str:
    if pid in ("unknown", ""):
        return "unknown"
    comm_path = Path(f"/proc/{pid}/comm")
    if comm_path.exists():
        try:
            return comm_path.read_text().strip()
        except OSError:
            return "unknown"
    return "unknown"


def find_candidate_logs(process_name: str) -> list[str]:
    candidates = []
    pname = process_name.lower()
    if "nginx" in pname:
        candidates += KNOWN_LOG_LOCATIONS["nginx"]
    elif "apache" in pname or "httpd" in pname:
        candidates += KNOWN_LOG_LOCATIONS["apache"]
    else:
        # Don't assume -- check both common locations and report what exists.
        candidates += KNOWN_LOG_LOCATIONS["nginx"] + KNOWN_LOG_LOCATIONS["apache"]
    existing = [c for c in candidates if Path(c).exists()]
    return existing


def main():
    print("=" * 70)
    print("AIPS target discovery (read-only -- no changes made)")
    print("=" * 70)

    listeners = find_listeners_on_port_80()
    if not listeners:
        print("\nNo process appears to be listening on port 80 right now.")
        print("Start your web server, then re-run this script.")
        sys.exit(0)

    scope = classify_bind_scope(listeners)
    print(f"\nFound {len(listeners)} listener(s) on port 80:")
    all_logs = set()
    for l in listeners:
        pname = guess_process_name(l["pid"])
        logs = find_candidate_logs(pname)
        all_logs.update(logs)
        print(f"  - bind={l['bind_address']}  pid={l['pid']}  process={pname}")
        print(f"      raw: {l['raw_line']}")

    print(f"\nBind scope classification: {scope}")
    if scope == "loopback_only":
        print("  -> Bound to 127.0.0.1 only. Other computers on your network")
        print("     cannot reach it directly. A firewall rule on this box would")
        print("     NOT add protection against local processes that already")
        print("     have loopback access -- say so honestly in your demo.")
    elif scope == "lan_exposed":
        print("  -> Bound to a non-loopback address (0.0.0.0 or similar).")
        print("     Other hosts on the network CAN reach this service.")
    else:
        print("  -> Could not classify bind scope automatically. Confirm manually")
        print("     (e.g. `ss -ltnp | grep :80`) before relying on this.")

    if all_logs:
        print(f"\nCandidate access/error logs found on disk:")
        for p in sorted(all_logs):
            print(f"  - {p}")
        print("\nSet TARGET_ACCESS_LOG_PATH (and TARGET_ERROR_LOG_PATH, if applicable)")
        print("in your .env to the correct path(s) above.")
    else:
        print("\nNo known nginx/apache log files found at common locations.")
        print("If you're running something else (a Python dev server, etc.),")
        print("it may not produce a standard access log at all -- AIPS cannot")
        print("observe requests it has no log or sensor for. Document this")
        print("limitation rather than faking data.")

    print("\nThis was a read-only check. Nothing was modified.")


if __name__ == "__main__":
    main()
