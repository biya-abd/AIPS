"""
SQLite persistence layer for AIPS.

Design notes:
- One connection per request via a context manager (SQLite handles this fine
  at the low concurrency a single-host dashboard needs).
- WAL mode is enabled so the dashboard can read while the collector writes.
- Every table that holds security-relevant data carries a `source_label`
  column constrained to REAL / SIMULATED / TEST so the dashboard and any
  aggregate statistic can filter synthetic data out of real incident counts.
- All queries are parameterized. No string-formatted SQL anywhere.
"""
from __future__ import annotations

import contextlib
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT UNIQUE NOT NULL,
    ts              REAL NOT NULL,
    source_ip       TEXT,
    destination     TEXT,
    method          TEXT,
    path            TEXT,
    status_code     INTEGER,
    bytes_sent      INTEGER,
    user_agent      TEXT,
    raw_line        TEXT,
    event_type      TEXT NOT NULL,
    source_label    TEXT NOT NULL CHECK (source_label IN ('REAL','SIMULATED','TEST')),
    created_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_label ON events(source_label);

CREATE TABLE IF NOT EXISTS detections (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id        TEXT UNIQUE NOT NULL,
    group_key           TEXT NOT NULL,
    event_id            TEXT,
    rule_name           TEXT NOT NULL,
    rule_version        TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    risk_score          INTEGER NOT NULL,
    evidence_json        TEXT NOT NULL,
    source_ip           TEXT,
    occurrence_count     INTEGER NOT NULL DEFAULT 1,
    first_seen           REAL NOT NULL,
    last_seen            REAL NOT NULL,
    investigation_status TEXT NOT NULL DEFAULT 'new',
    recommended_action   TEXT,
    response_action      TEXT,
    response_result       TEXT,
    source_label         TEXT NOT NULL CHECK (source_label IN ('REAL','SIMULATED','TEST')),
    confirmed_attack      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_detections_group ON detections(group_key);
CREATE INDEX IF NOT EXISTS idx_detections_last_seen ON detections(last_seen);
CREATE INDEX IF NOT EXISTS idx_detections_label ON detections(source_label);

CREATE TABLE IF NOT EXISTS responses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    response_id      TEXT UNIQUE NOT NULL,
    detection_id     TEXT,
    action_type      TEXT NOT NULL,
    target           TEXT NOT NULL,
    reason           TEXT,
    rule_applied     TEXT,
    requested_by     TEXT NOT NULL,
    approved         INTEGER NOT NULL DEFAULT 0,
    approved_by      TEXT,
    expires_at       REAL,
    ts               REAL NOT NULL,
    outcome          TEXT NOT NULL DEFAULT 'pending',
    rolled_back      INTEGER NOT NULL DEFAULT 0,
    rollback_ts      REAL,
    source_label     TEXT NOT NULL CHECK (source_label IN ('REAL','SIMULATED','TEST'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    details     TEXT,
    outcome     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_status_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    status      TEXT NOT NULL,
    latency_ms  INTEGER,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS honeypot_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT UNIQUE NOT NULL,
    ts              REAL NOT NULL,
    source_ip       TEXT,
    source_port     INTEGER,
    method          TEXT,
    path            TEXT,
    raw_request     TEXT,
    source_label    TEXT NOT NULL CHECK (source_label IN ('REAL','SIMULATED','TEST'))
);
CREATE INDEX IF NOT EXISTS idx_honeypot_ts ON honeypot_events(ts);
"""

DEFAULT_SETTINGS = {
    "mode": "monitor",
    "ai_enabled": "true",
    "event_generator_running": "false",
    "started_at": "",
}


class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextlib.contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self):
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            for k, v in DEFAULT_SETTINGS.items():
                conn.execute(
                    "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v)
                )

    # ---- settings ----
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # ---- events ----
    def insert_event(self, event: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO events
                   (event_id, ts, source_ip, destination, method, path, status_code,
                    bytes_sent, user_agent, raw_line, event_type, source_label, created_at)
                   VALUES (:event_id, :ts, :source_ip, :destination, :method, :path,
                           :status_code, :bytes_sent, :user_agent, :raw_line, :event_type,
                           :source_label, :created_at)""",
                {**event, "created_at": time.time()},
            )

    def recent_events(self, limit: int = 100, label_filter: str | None = None) -> list[sqlite3.Row]:
        with self.connect() as conn:
            if label_filter:
                return conn.execute(
                    "SELECT * FROM events WHERE source_label = ? ORDER BY ts DESC LIMIT ?",
                    (label_filter, limit),
                ).fetchall()
            return conn.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()

    def events_in_window(self, source_ip: str, event_type: str, since_ts: float, label_filter: str | None = None):
        with self.connect() as conn:
            if label_filter:
                return conn.execute(
                    "SELECT * FROM events WHERE source_ip = ? AND event_type = ? AND ts >= ? AND source_label = ? ORDER BY ts",
                    (source_ip, event_type, since_ts, label_filter),
                ).fetchall()
            return conn.execute(
                "SELECT * FROM events WHERE source_ip = ? AND event_type = ? AND ts >= ? ORDER BY ts",
                (source_ip, event_type, since_ts),
            ).fetchall()

    # ---- detections ----
    def upsert_detection(self, detection: dict) -> bool:
        """Insert a new detection, or if group_key already has a recent open
        detection, increment its occurrence_count instead (dedup). Returns
        True if a new row was inserted, False if an existing one was updated."""
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT * FROM detections WHERE group_key = ? AND investigation_status != 'closed' "
                "ORDER BY last_seen DESC LIMIT 1",
                (detection["group_key"],),
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE detections SET occurrence_count = occurrence_count + 1,
                       last_seen = ?, risk_score = ?, severity = ?, evidence_json = ?
                       WHERE id = ?""",
                    (detection["last_seen"], detection["risk_score"], detection["severity"],
                     detection["evidence_json"], existing["id"]),
                )
                return False
            conn.execute(
                """INSERT INTO detections
                   (detection_id, group_key, event_id, rule_name, rule_version, severity,
                    risk_score, evidence_json, source_ip, occurrence_count, first_seen, last_seen,
                    investigation_status, recommended_action, response_action, response_result,
                    source_label, confirmed_attack)
                   VALUES (:detection_id, :group_key, :event_id, :rule_name, :rule_version,
                           :severity, :risk_score, :evidence_json, :source_ip, 1, :first_seen,
                           :last_seen, :investigation_status, :recommended_action, :response_action,
                           :response_result, :source_label, 0)""",
                detection,
            )
            return True

    def recent_detections(self, limit: int = 100, label_filter: str | None = None):
        with self.connect() as conn:
            if label_filter:
                return conn.execute(
                    "SELECT * FROM detections WHERE source_label = ? ORDER BY last_seen DESC LIMIT ?",
                    (label_filter, limit),
                ).fetchall()
            return conn.execute(
                "SELECT * FROM detections ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()

    def update_detection_status(self, detection_id: str, status: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE detections SET investigation_status = ? WHERE detection_id = ?",
                (status, detection_id),
            )

    # ---- responses ----
    def insert_response(self, response: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO responses
                   (response_id, detection_id, action_type, target, reason, rule_applied,
                    requested_by, approved, approved_by, expires_at, ts, outcome, rolled_back,
                    source_label)
                   VALUES (:response_id, :detection_id, :action_type, :target, :reason,
                           :rule_applied, :requested_by, :approved, :approved_by, :expires_at,
                           :ts, :outcome, 0, :source_label)""",
                response,
            )

    def recent_responses(self, limit: int = 100):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM responses ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()

    def mark_response_rolled_back(self, response_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE responses SET rolled_back = 1, rollback_ts = ? WHERE response_id = ?",
                (time.time(), response_id),
            )

    def active_blocks(self):
        with self.connect() as conn:
            now = time.time()
            return conn.execute(
                "SELECT * FROM responses WHERE action_type = 'block' AND outcome = 'applied' "
                "AND rolled_back = 0 AND (expires_at IS NULL OR expires_at > ?)",
                (now,),
            ).fetchall()

    # ---- audit ----
    def write_audit(self, actor: str, action: str, details: str, outcome: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, actor, action, details, outcome) VALUES (?, ?, ?, ?, ?)",
                (time.time(), actor, action, details, outcome),
            )

    def recent_audit(self, limit: int = 200):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()

    # ---- ai status ----
    def log_ai_status(self, provider: str, model: str, status: str, latency_ms: int | None, error: str | None):
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO ai_status_log (ts, provider, model, status, latency_ms, error) VALUES (?, ?, ?, ?, ?, ?)",
                (time.time(), provider, model, status, latency_ms, error),
            )

    def last_ai_status(self):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM ai_status_log ORDER BY ts DESC LIMIT 1"
            ).fetchone()

    # ---- honeypot ----
    def insert_honeypot_event(self, event: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO honeypot_events
                   (event_id, ts, source_ip, source_port, method, path, raw_request, source_label)
                   VALUES (:event_id, :ts, :source_ip, :source_port, :method, :path, :raw_request, :source_label)""",
                event,
            )

    def recent_honeypot_events(self, limit: int = 50):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM honeypot_events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()

    def honeypot_unique_ip_count(self, since_ts: float) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) AS c FROM honeypot_events WHERE ts >= ?",
                (since_ts,),
            ).fetchone()
            return row["c"] if row else 0

    # ---- aggregate stats (REAL-only by default, matches dashboard integrity rule) ----
    def event_count_last_minute(self, label_filter: str = "REAL") -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE ts >= ? AND source_label = ?",
                (time.time() - 60, label_filter),
            ).fetchone()
            return row["c"] if row else 0

    def total_event_count(self, label_filter: str = "REAL") -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE source_label = ?", (label_filter,)
            ).fetchone()
            return row["c"] if row else 0

    def events_per_minute_series(self, minutes: int = 60, label_filter: str = "REAL") -> list[dict]:
        """Returns one point per minute bucket for the last `minutes` minutes,
        counting actual stored events -- never randomly generated."""
        now = time.time()
        start = now - minutes * 60
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT CAST((ts - ?) / 60 AS INTEGER) AS bucket, COUNT(*) AS c "
                "FROM events WHERE ts >= ? AND source_label = ? GROUP BY bucket",
                (start, start, label_filter),
            ).fetchall()
        counts = {r["bucket"]: r["c"] for r in rows}
        return [{"minute_offset": i, "count": counts.get(i, 0)} for i in range(minutes)]

    def risk_trend_series(self, hours: int = 1, label_filter: str = "REAL") -> list[dict]:
        """Average risk_score per 5-minute bucket over the window, from stored
        detections only -- a flat/empty result honestly means no detections,
        not a fabricated curve."""
        now = time.time()
        start = now - hours * 3600
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT CAST((last_seen - ?) / 300 AS INTEGER) AS bucket, AVG(risk_score) AS avg_score, COUNT(*) AS c "
                "FROM detections WHERE last_seen >= ? AND source_label = ? GROUP BY bucket",
                (start, start, label_filter),
            ).fetchall()
        buckets = (hours * 3600) // 300
        by_bucket = {r["bucket"]: (r["avg_score"], r["c"]) for r in rows}
        out = []
        for i in range(buckets):
            avg_score, c = by_bucket.get(i, (None, 0))
            out.append({"bucket_offset": i, "avg_risk_score": round(avg_score, 1) if avg_score is not None else None, "count": c})
        return out

    def current_threat_score(self, label_filter: str = "REAL") -> int:
        """The single current risk gauge: the highest risk_score among
        detections still open (not closed) in the last hour, or 0."""
        since = time.time() - 3600
        with self.connect() as conn:
            row = conn.execute(
                "SELECT MAX(risk_score) AS m FROM detections "
                "WHERE source_label = ? AND last_seen >= ? AND investigation_status != 'closed'",
                (label_filter, since),
            ).fetchone()
            return row["m"] if row and row["m"] is not None else 0

    def severity_distribution(self, label_filter: str = "REAL") -> dict:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS c FROM detections WHERE source_label = ? GROUP BY severity",
                (label_filter,),
            ).fetchall()
            dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for r in rows:
                dist[r["severity"]] = r["c"]
            return dist
