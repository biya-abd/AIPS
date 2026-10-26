import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from app.ai import openrouter_client
from app.database import Database


@dataclass
class FakeConfig:
    ai_enabled: bool = True
    openrouter_api_key: str = "sk-fake-test-key"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "nvidia/nemotron-3-ultra-550b-a55b"
    ai_timeout_seconds: int = 5
    ai_max_retries: int = 0


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "ai_test.db"))


class FakeResponse:
    def __init__(self, status_code, json_body=None, text=""):
        self.status_code = status_code
        self._json = json_body
        self.text = text

    def json(self):
        return self._json


class FakeAsyncClient:
    """Stand-in for httpx.AsyncClient that returns a pre-set canned response
    instead of making a real network call."""
    _next_response = None
    _raise = None

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        if FakeAsyncClient._raise:
            raise FakeAsyncClient._raise
        return FakeAsyncClient._next_response


def _mock_success(monkeypatch, parsed_content: dict):
    body = {"choices": [{"message": {"content": json.dumps(parsed_content)}}]}
    FakeAsyncClient._next_response = FakeResponse(200, json_body=body)
    FakeAsyncClient._raise = None
    monkeypatch.setattr(openrouter_client.httpx, "AsyncClient", FakeAsyncClient)


@pytest.mark.asyncio
async def test_analyze_detection_success(db, monkeypatch):
    _mock_success(monkeypatch, {
        "summary": "Repeated failed logins from one source.",
        "investigative_steps": ["Check source reputation", "Review login endpoint rate limit"],
        "recommendation": "Consider a temporary rate limit.",
    })
    cfg = FakeConfig()
    detection = {
        "rule_name": "BRUTE_FORCE", "severity": "high", "risk_score": 70,
        "occurrence_count": 5, "source_ip": "1.2.3.4", "evidence_json": "{}",
    }
    result = await openrouter_client.analyze_detection(detection, cfg, db)
    assert result["ok"] is True
    assert "failed logins" in result["summary"]
    assert len(result["investigative_steps"]) == 2


@pytest.mark.asyncio
async def test_analyze_detection_disabled(db):
    cfg = FakeConfig(ai_enabled=False)
    result = await openrouter_client.analyze_detection({}, cfg, db)
    assert result["ok"] is False
    assert "AI_ENABLED" in result["error"]


@pytest.mark.asyncio
async def test_analyze_detection_no_key(db):
    cfg = FakeConfig(openrouter_api_key="")
    result = await openrouter_client.analyze_detection({}, cfg, db)
    assert result["ok"] is False
    assert "API_KEY" in result["error"] or "key" in result["error"].lower()


@pytest.mark.asyncio
async def test_analyze_detection_http_error_does_not_raise(db, monkeypatch):
    FakeAsyncClient._next_response = FakeResponse(500, text="server error")
    FakeAsyncClient._raise = None
    monkeypatch.setattr(openrouter_client.httpx, "AsyncClient", FakeAsyncClient)
    cfg = FakeConfig()
    result = await openrouter_client.analyze_detection({"evidence_json": "{}"}, cfg, db)
    assert result["ok"] is False
    assert "500" in result["error"]


@pytest.mark.asyncio
async def test_health_check_success(db, monkeypatch):
    body = {"choices": [{"message": {"content": "OK"}}]}
    FakeAsyncClient._next_response = FakeResponse(200, json_body=body)
    FakeAsyncClient._raise = None
    monkeypatch.setattr(openrouter_client.httpx, "AsyncClient", FakeAsyncClient)
    cfg = FakeConfig()
    result = await openrouter_client.health_check(cfg, db)
    assert result["ok"] is True
    assert result["status"] == "connected"


def test_redact_evidence_strips_banned_fields():
    detection = {
        "rule_name": "BRUTE_FORCE", "severity": "high", "risk_score": 70,
        "occurrence_count": 3, "source_ip": "9.9.9.9",
        "evidence_json": json.dumps({"authorization": "secret-token", "sample_paths": ["/login"]}),
    }
    redacted = openrouter_client._redact_evidence(detection)
    assert "authorization" not in redacted["evidence"]
    assert redacted["source_ip_masked"] == "9.9.x.x"
