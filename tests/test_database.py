import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from app.database import Database


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test_aips.db"))


def _event(event_id="EVT-1", source_ip="1.2.3.4", status=200, ts=None, label="REAL"):
    return {
        "event_id": event_id, "ts": ts or time.time(), "source_ip": source_ip,
        "destination": None, "method": "GET", "path": "/", "status_code": status,
        "bytes_sent": 100, "user_agent": "test", "raw_line": "raw", "event_type": "http_request",
        "source_label": label,
    }


def test_insert_and_read_event(db):
    db.insert_event(_event())
    rows = db.recent_events(limit=10)
    assert len(rows) == 1
    assert rows[0]["source_ip"] == "1.2.3.4"


def test_duplicate_event_id_is_ignored(db):
    db.insert_event(_event(event_id="DUP"))
    db.insert_event(_event(event_id="DUP"))
    rows = db.recent_events(limit=10)
    assert len(rows) == 1


def test_label_filter_isolates_simulated_from_real(db):
    db.insert_event(_event(event_id="REAL-1", label="REAL"))
    db.insert_event(_event(event_id="SIM-1", label="SIMULATED"))
    real_rows = db.recent_events(limit=10, label_filter="REAL")
    sim_rows = db.recent_events(limit=10, label_filter="SIMULATED")
    assert len(real_rows) == 1 and real_rows[0]["event_id"] == "REAL-1"
    assert len(sim_rows) == 1 and sim_rows[0]["event_id"] == "SIM-1"


def test_total_event_count_respects_label(db):
    db.insert_event(_event(event_id="R1", label="REAL"))
    db.insert_event(_event(event_id="R2", label="REAL"))
    db.insert_event(_event(event_id="S1", label="SIMULATED"))
    assert db.total_event_count("REAL") == 2
    assert db.total_event_count("SIMULATED") == 1


def _detection(detection_id="D-1", group_key="RULE:1.2.3.4", score=40, severity="medium", label="REAL"):
    return {
        "detection_id": detection_id, "group_key": group_key, "event_id": None,
        "rule_name": "RULE", "rule_version": "1.0.0", "severity": severity, "risk_score": score,
        "evidence_json": "{}", "source_ip": "1.2.3.4", "first_seen": time.time(), "last_seen": time.time(),
        "investigation_status": "new", "recommended_action": "investigate", "response_action": None,
        "response_result": None, "source_label": label,
    }


def test_upsert_detection_inserts_new(db):
    inserted = db.upsert_detection(_detection())
    assert inserted is True
    assert len(db.recent_detections()) == 1


def test_upsert_detection_dedups_same_group_key(db):
    db.upsert_detection(_detection(detection_id="D-1"))
    inserted_again = db.upsert_detection(_detection(detection_id="D-2"))  # same group_key
    assert inserted_again is False
    rows = db.recent_detections()
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 2


def test_closed_detection_does_not_dedupe_into(db):
    db.upsert_detection(_detection(detection_id="D-1", group_key="RULE:5.5.5.5"))
    db.update_detection_status("D-1", "closed")
    inserted = db.upsert_detection(_detection(detection_id="D-2", group_key="RULE:5.5.5.5"))
    assert inserted is True
    assert len(db.recent_detections()) == 2


def test_audit_write_and_read(db):
    db.write_audit("tester", "did_a_thing", "details here", "ok")
    rows = db.recent_audit()
    assert len(rows) == 1
    assert rows[0]["action"] == "did_a_thing"


def test_settings_roundtrip(db):
    db.set_setting("mode", "enforcement")
    assert db.get_setting("mode") == "enforcement"


def test_response_insert_and_active_blocks(db):
    db.insert_response({
        "response_id": "R-1", "detection_id": "D-1", "action_type": "block", "target": "9.9.9.9",
        "reason": "test", "rule_applied": "RULE", "requested_by": "tester", "approved": 1,
        "approved_by": "tester", "expires_at": time.time() + 3600, "ts": time.time(),
        "outcome": "applied", "source_label": "TEST",
    })
    active = db.active_blocks()
    assert len(active) == 1
    assert active[0]["target"] == "9.9.9.9"


def test_rolled_back_block_not_active(db):
    db.insert_response({
        "response_id": "R-2", "detection_id": "D-1", "action_type": "block", "target": "9.9.9.8",
        "reason": "test", "rule_applied": "RULE", "requested_by": "tester", "approved": 1,
        "approved_by": "tester", "expires_at": time.time() + 3600, "ts": time.time(),
        "outcome": "applied", "source_label": "TEST",
    })
    db.mark_response_rolled_back("R-2")
    assert len(db.active_blocks()) == 0


def test_severity_distribution_counts_only_requested_label(db):
    db.upsert_detection(_detection(detection_id="D1", group_key="A", severity="high", label="REAL"))
    db.upsert_detection(_detection(detection_id="D2", group_key="B", severity="high", label="SIMULATED"))
    dist = db.severity_distribution("REAL")
    assert dist["high"] == 1
