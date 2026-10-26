"""
Deterministic detection rules for AIPS.

Each rule is a plain Python function: (db, event, cfg) -> evidence dict | None.
No ML, no black boxes -- every rule's trigger condition is readable here and
every detection stores the exact evidence that caused it.

IMPORTANT per the project's honesty requirements: these rules work from
observable web-server access-log fields (IP, method, path, status code,
timestamp, user agent). They do NOT by themselves prove a successful
compromise -- `confirmed_attack` stays false unless a human investigator
(or a later correlated signal) sets it. See docs/LIMITATIONS.md for what
these rules cannot see (encrypted payload bodies, application-level auth
outcomes if not logged, etc).

RULE_VERSION is bumped whenever a rule's trigger LOGIC changes, so stored
detections remain auditable against the version that produced them.
"""
from __future__ import annotations

import json
import time
import uuid

from .risk import compute_risk_score, severity_from_score

RULE_VERSION = "1.0.0"

# Paths commonly probed by scanners/attackers looking for secrets, admin
# panels, or framework internals. Not exhaustive -- documented as such.
SENSITIVE_PATH_MARKERS = (
    "/.env", "/.git", "/.ssh", "/wp-admin", "/wp-login", "/phpmyadmin",
    "/admin", "/.aws", "/config.php", "/.htpasswd", "/server-status",
    "/actuator", "/.well-known/security.txt", "/xmlrpc.php", "/.docker",
)

TRAVERSAL_MARKERS = ("../", "..%2f", "%2e%2e", "..\\", "%2e%2e%2f", "%c0%ae%c0%ae")

VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

# Login-like paths for the brute-force rule. A real deployment should
# override this via the target's actual auth endpoint once known --
# documented as a tunable, not a hardcoded assumption about the app.
LOGIN_PATH_MARKERS = ("/login", "/signin", "/sign-in", "/wp-login.php", "/admin/login")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _is_repeat_offender(db, source_ip: str, cfg, exclude_rule: str) -> bool:
    if not source_ip:
        return False
    since = time.time() - cfg.repeat_offender_window_seconds
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT rule_name FROM detections WHERE source_ip = ? AND last_seen >= ?",
            (source_ip, since),
        ).fetchall()
    distinct_rules = {r["rule_name"] for r in rows} | {exclude_rule}
    return len(distinct_rules) >= cfg.repeat_offender_rule_count


def _build_detection(db, cfg, rule_name: str, source_ip: str, evidence: dict,
                       recommended_action: str, source_label: str, event_id: str | None) -> dict:
    is_offender = _is_repeat_offender(db, source_ip, cfg, rule_name)
    # occurrence_count for scoring purposes is looked up optimistically as 1
    # here; database.upsert_detection increments it for existing open groups
    # and the caller re-scores on update. For the initial insert this is correct.
    score = compute_risk_score(rule_name, occurrence_count=1, is_repeat_offender=is_offender)
    severity = severity_from_score(score)
    now = time.time()
    return {
        "detection_id": _new_id("AIPS"),
        "group_key": f"{rule_name}:{source_ip or 'unknown'}",
        "event_id": event_id,
        "rule_name": rule_name,
        "rule_version": RULE_VERSION,
        "severity": severity,
        "risk_score": score,
        "evidence_json": json.dumps(evidence, default=str),
        "source_ip": source_ip,
        "first_seen": now,
        "last_seen": now,
        "investigation_status": "new",
        "recommended_action": recommended_action,
        "response_action": None,
        "response_result": None,
        "source_label": source_label,
    }


def rule_brute_force(db, event: dict, cfg) -> dict | None:
    path = (event.get("path") or "").lower()
    status = event.get("status_code")
    if not any(m in path for m in LOGIN_PATH_MARKERS):
        return None
    if status not in (401, 403):
        return None
    since = time.time() - cfg.failed_login_window_seconds
    rows = db.events_in_window(event["source_ip"], "http_request", since, label_filter=event["source_label"])
    failures = [r for r in rows if r["status_code"] in (401, 403) and any(m in (r["path"] or "").lower() for m in LOGIN_PATH_MARKERS)]
    if len(failures) < cfg.failed_login_threshold:
        return None
    evidence = {
        "window_seconds": cfg.failed_login_window_seconds,
        "threshold": cfg.failed_login_threshold,
        "observed_failures": len(failures),
        "sample_paths": list({r["path"] for r in failures})[:5],
    }
    return _build_detection(
        db, cfg, "BRUTE_FORCE", event["source_ip"], evidence,
        recommended_action="Investigate source; consider temporary rate limit on login endpoint (requires approval)",
        source_label=event["source_label"], event_id=event.get("event_id"),
    )


def rule_excess_rate(db, event: dict, cfg) -> dict | None:
    since = time.time() - cfg.rate_window_seconds
    rows = db.events_in_window(event["source_ip"], "http_request", since, label_filter=event["source_label"])
    if len(rows) < cfg.rate_threshold:
        return None
    evidence = {
        "window_seconds": cfg.rate_window_seconds,
        "threshold": cfg.rate_threshold,
        "observed_requests": len(rows),
    }
    return _build_detection(
        db, cfg, "EXCESS_RATE", event["source_ip"], evidence,
        recommended_action="Review traffic pattern; consider rate limit (requires approval)",
        source_label=event["source_label"], event_id=event.get("event_id"),
    )


def rule_repeat_404(db, event: dict, cfg) -> dict | None:
    if event.get("status_code") != 404:
        return None
    since = time.time() - cfg.repeat_404_window_seconds
    rows = db.events_in_window(event["source_ip"], "http_request", since, label_filter=event["source_label"])
    not_founds = [r for r in rows if r["status_code"] == 404]
    if len(not_founds) < cfg.repeat_404_threshold:
        return None
    evidence = {
        "window_seconds": cfg.repeat_404_window_seconds,
        "threshold": cfg.repeat_404_threshold,
        "observed_404s": len(not_founds),
        "sample_paths": list({r["path"] for r in not_founds})[:8],
    }
    return _build_detection(
        db, cfg, "REPEAT_404", event["source_ip"], evidence,
        recommended_action="Likely resource enumeration/scanning; monitor, consider block if it continues",
        source_label=event["source_label"], event_id=event.get("event_id"),
    )


def rule_path_traversal(db, event: dict, cfg) -> dict | None:
    path = (event.get("path") or "").lower()
    if not any(m in path for m in TRAVERSAL_MARKERS):
        return None
    evidence = {"path": event.get("path"), "matched_markers": [m for m in TRAVERSAL_MARKERS if m in path]}
    return _build_detection(
        db, cfg, "PATH_TRAVERSAL", event["source_ip"], evidence,
        recommended_action="High-confidence attack pattern; investigate immediately, consider block",
        source_label=event["source_label"], event_id=event.get("event_id"),
    )


def rule_suspicious_path(db, event: dict, cfg) -> dict | None:
    path = (event.get("path") or "").lower()
    matched = [m for m in SENSITIVE_PATH_MARKERS if m in path]
    if not matched:
        return None
    evidence = {"path": event.get("path"), "matched_markers": matched}
    return _build_detection(
        db, cfg, "SUSPICIOUS_PATH", event["source_ip"], evidence,
        recommended_action="Request for sensitive/admin path; verify this is not expected internal traffic",
        source_label=event["source_label"], event_id=event.get("event_id"),
    )


def rule_malformed_request(db, event: dict, cfg) -> dict | None:
    method = (event.get("method") or "").upper()
    path = event.get("path") or ""
    problems = []
    if method and method not in VALID_METHODS:
        problems.append(f"unrecognized method '{method}'")
    if path and not path.startswith("/") and not path.startswith("http"):
        problems.append("path does not start with '/'")
    if len(path) > 2048:
        problems.append("path exceeds 2048 characters")
    if not problems:
        return None
    evidence = {"method": method, "path_length": len(path), "problems": problems}
    return _build_detection(
        db, cfg, "MALFORMED_REQUEST", event["source_ip"], evidence,
        recommended_action="Inspect raw request; may indicate a fuzzer or malformed client",
        source_label=event["source_label"], event_id=event.get("event_id"),
    )


# Order matters only for evaluation sequence, not for correctness -- each
# rule is independent and a single event can trigger more than one.
ALL_RULES = [
    rule_path_traversal,
    rule_suspicious_path,
    rule_malformed_request,
    rule_brute_force,
    rule_repeat_404,
    rule_excess_rate,
]


def evaluate_event(db, event: dict, cfg) -> list[dict]:
    """Run every rule against a freshly-inserted event. Returns the list of
    NEW or UPDATED detection dicts produced (may be empty)."""
    detections = []
    for rule_fn in ALL_RULES:
        try:
            result = rule_fn(db, event, cfg)
        except Exception as exc:  # a single bad rule must never crash the collector
            result = None
            db.write_audit("system", "rule_error", f"{rule_fn.__name__}: {exc}", "error")
        if result:
            db.upsert_detection(result)
            detections.append(result)
    return detections
