import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from app.database import Database
from app.detection.rules import evaluate_event


@dataclass
class FakeConfig:
    rate_window_seconds: int = 60
    rate_threshold: int = 5
    failed_login_window_seconds: int = 300
    failed_login_threshold: int = 3
    repeat_404_window_seconds: int = 120
    repeat_404_threshold: int = 4
    repeat_offender_rule_count: int = 2
    repeat_offender_window_seconds: int = 600


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "rules_test.db"))


@pytest.fixture
def cfg():
    return FakeConfig()


def _event(source_ip, path, method="GET", status=200, label="TEST"):
    return {
        "event_id": f"EVT-{uuid.uuid4().hex[:8]}", "ts": time.time(), "source_ip": source_ip,
        "destination": None, "method": method, "path": path, "status_code": status,
        "bytes_sent": 100, "user_agent": "pytest", "raw_line": "raw",
        "event_type": "http_request", "source_label": label,
    }


def _feed(db, cfg, source_ip, path, method, status, n):
    """Inserts the same shaped event n times and returns detections from the last one."""
    detections = []
    for _ in range(n):
        ev = _event(source_ip, path, method, status)
        db.insert_event(ev)
        detections = evaluate_event(db, ev, cfg)
    return detections


def test_brute_force_triggers_at_threshold(db, cfg):
    dets = _feed(db, cfg, "1.1.1.1", "/login", "POST", 401, n=cfg.failed_login_threshold)
    assert any(d["rule_name"] == "BRUTE_FORCE" for d in dets)


def test_brute_force_does_not_trigger_below_threshold(db, cfg):
    dets = _feed(db, cfg, "1.1.1.2", "/login", "POST", 401, n=cfg.failed_login_threshold - 1)
    assert not any(d["rule_name"] == "BRUTE_FORCE" for d in dets)


def test_brute_force_ignores_successful_logins(db, cfg):
    dets = _feed(db, cfg, "1.1.1.3", "/login", "POST", 200, n=10)
    assert not any(d["rule_name"] == "BRUTE_FORCE" for d in dets)


def test_excess_rate_triggers_at_threshold(db, cfg):
    dets = _feed(db, cfg, "2.2.2.1", "/", "GET", 200, n=cfg.rate_threshold)
    assert any(d["rule_name"] == "EXCESS_RATE" for d in dets)


def test_repeat_404_triggers_at_threshold(db, cfg):
    dets = _feed(db, cfg, "3.3.3.1", "/nope", "GET", 404, n=cfg.repeat_404_threshold)
    assert any(d["rule_name"] == "REPEAT_404" for d in dets)


def test_path_traversal_triggers_immediately(db, cfg):
    ev = _event("4.4.4.1", "/files?name=../../etc/passwd")
    db.insert_event(ev)
    dets = evaluate_event(db, ev, cfg)
    assert any(d["rule_name"] == "PATH_TRAVERSAL" for d in dets)


def test_suspicious_path_triggers_immediately(db, cfg):
    ev = _event("5.5.5.1", "/.env")
    db.insert_event(ev)
    dets = evaluate_event(db, ev, cfg)
    assert any(d["rule_name"] == "SUSPICIOUS_PATH" for d in dets)


def test_normal_request_triggers_nothing(db, cfg):
    ev = _event("6.6.6.1", "/about", status=200)
    db.insert_event(ev)
    dets = evaluate_event(db, ev, cfg)
    assert dets == []


def test_malformed_method_triggers(db, cfg):
    ev = _event("7.7.7.1", "/", method="FOOBAR")
    db.insert_event(ev)
    dets = evaluate_event(db, ev, cfg)
    assert any(d["rule_name"] == "MALFORMED_REQUEST" for d in dets)


def test_repeated_detections_increment_occurrence_not_duplicate_rows(db, cfg):
    ip = "8.8.8.1"
    _feed(db, cfg, ip, "/.env", "GET", 403, n=1)
    _feed(db, cfg, ip, "/.env", "GET", 403, n=1)
    rows = [r for r in db.recent_detections() if r["rule_name"] == "SUSPICIOUS_PATH" and r["source_ip"] == ip]
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 2


def test_repeat_offender_raises_score_on_new_rule(db, cfg):
    ip = "9.9.9.1"
    # Trigger two distinct rules from the same IP within the offender window.
    _feed(db, cfg, ip, "/.env", "GET", 403, n=1)  # SUSPICIOUS_PATH
    dets = _feed(db, cfg, ip, "/files?x=../../etc/passwd", "GET", 403, n=1)  # PATH_TRAVERSAL, 2nd distinct rule
    traversal = next(d for d in dets if d["rule_name"] == "PATH_TRAVERSAL")
    # With repeat_offender_rule_count=2, the 2nd distinct rule from this IP
    # should receive the +20 offender bonus on top of the base score.
    from app.detection.risk import RULE_BASE_SCORE
    assert traversal["risk_score"] >= RULE_BASE_SCORE["PATH_TRAVERSAL"] + 20


def test_events_isolated_by_label(db, cfg):
    ip = "10.10.10.1"
    real_ev = _event(ip, "/login", "POST", 401, label="REAL")
    db.insert_event(real_ev)
    evaluate_event(db, real_ev, cfg)
    # SIMULATED events for the same IP should not count toward the REAL brute-force window
    for _ in range(cfg.failed_login_threshold):
        sim_ev = _event(ip, "/login", "POST", 401, label="SIMULATED")
        db.insert_event(sim_ev)
        evaluate_event(db, sim_ev, cfg)
    real_detections = [d for d in db.recent_detections() if d["source_label"] == "REAL"]
    assert not any(d["rule_name"] == "BRUTE_FORCE" for d in real_detections)
