"""
OpenRouter AI integration for AIPS.

Hard rules enforced in this file:
  - The AI is given a redacted summary of a detection, never raw request
    bodies, headers, cookies, or API keys.
  - The AI's output is treated purely as TEXT to display (summary,
    suggested steps, recommendation). It is never eval'd, never used to
    construct a shell command, and never used to automatically trigger an
    enforcement action -- app/response/enforcement.py requires an explicit
    human-approved call regardless of what the AI says.
  - Every call is time-bounded (AI_TIMEOUT_SECONDS) and limited to
    AI_MAX_RETRIES retries. The rule-based detector in app/detection never
    depends on this module succeeding.
  - Every call (success or failure) is logged via db.log_ai_status so the
    dashboard can show real provider/connection state, never a hardcoded
    "Connected" label.
"""
from __future__ import annotations

import json
import time

import httpx

SYSTEM_PROMPT = (
    "You are a defensive security analyst assistant embedded in a student "
    "intrusion-detection dashboard called AIPS. You are given a single "
    "redacted detection record (rule triggered, severity, evidence, counts). "
    "Respond ONLY with a JSON object with exactly these keys: "
    '"summary" (1-2 plain-English sentences), '
    '"investigative_steps" (a list of 2-4 short, concrete steps a human should '
    "take to verify or dismiss this), and "
    '"recommendation" (one short sentence; this is ADVISORY ONLY and will '
    "never be auto-executed). "
    "Do not include markdown fences, commentary, or any other keys. "
    "You have no ability to take action yourself -- you are producing text "
    "for a human analyst to read."
)


def _redact_evidence(detection: dict) -> dict:
    """Strip anything that could plausibly be sensitive before it leaves the
    machine. Detections here are built from access-log fields only (no
    headers/cookies/bodies are ever stored), but we defensively strip a few
    field names anyway in case evidence shape changes later."""
    evidence = detection.get("evidence_json")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            evidence = {"raw": "<unparsable evidence, omitted>"}
    evidence = dict(evidence) if isinstance(evidence, dict) else {}
    for banned in ("authorization", "cookie", "api_key", "password", "set-cookie"):
        evidence.pop(banned, None)
    return {
        "rule_name": detection.get("rule_name"),
        "severity": detection.get("severity"),
        "risk_score": detection.get("risk_score"),
        "occurrence_count": detection.get("occurrence_count", 1),
        "source_ip_masked": _mask_ip(detection.get("source_ip")),
        "evidence": evidence,
    }


def _mask_ip(ip: str | None) -> str:
    if not ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return ip[:8] + "…"  # best-effort for IPv6 / non-dotted-quad


async def analyze_detection(detection: dict, cfg, db) -> dict:
    """Returns {"ok": bool, "summary":..., "investigative_steps":[...],
    "recommendation":..., "error": str|None}. Never raises."""
    if not cfg.ai_enabled:
        return {"ok": False, "error": "AI_ENABLED is false in configuration"}
    if not cfg.openrouter_api_key:
        return {"ok": False, "error": "OPENROUTER_API_KEY is not set"}

    payload_record = _redact_evidence(detection)
    body = {
        "model": cfg.openrouter_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload_record)},
        ],
        "max_tokens": 400,
        "temperature": 0.2,
    }
    headers = {
        "Authorization": f"Bearer {cfg.openrouter_api_key}",
        "Content-Type": "application/json",
    }

    last_error = None
    for attempt in range(cfg.ai_max_retries + 1):
        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=cfg.ai_timeout_seconds) as client:
                resp = await client.post(
                    f"{cfg.openrouter_base_url}/chat/completions",
                    headers=headers,
                    json=body,
                )
            latency_ms = int((time.time() - start) * 1000)
            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code}: {resp.text[:300]}"
                db.log_ai_status("openrouter", cfg.openrouter_model, "error", latency_ms, last_error)
                continue
            data = resp.json()
            content = data["choices"][0]["message"]["content"].strip()
            content = content.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            parsed = json.loads(content)
            db.log_ai_status("openrouter", cfg.openrouter_model, "ok", latency_ms, None)
            return {
                "ok": True,
                "summary": parsed.get("summary", ""),
                "investigative_steps": parsed.get("investigative_steps", []),
                "recommendation": parsed.get("recommendation", ""),
                "error": None,
            }
        except httpx.TimeoutException:
            latency_ms = int((time.time() - start) * 1000)
            last_error = f"timeout after {cfg.ai_timeout_seconds}s"
            db.log_ai_status("openrouter", cfg.openrouter_model, "timeout", latency_ms, last_error)
        except (httpx.HTTPError, KeyError, json.JSONDecodeError, IndexError) as exc:
            latency_ms = int((time.time() - start) * 1000)
            last_error = f"{type(exc).__name__}: {exc}"
            db.log_ai_status("openrouter", cfg.openrouter_model, "error", latency_ms, last_error)

    return {"ok": False, "error": last_error or "unknown error", "summary": None,
            "investigative_steps": [], "recommendation": None}


async def health_check(cfg, db) -> dict:
    """A minimal, cheap call to confirm the provider/model are reachable.
    Returns {"ok": bool, "status": str, "latency_ms": int|None, "error": str|None}."""
    if not cfg.ai_enabled:
        return {"ok": False, "status": "disabled", "latency_ms": None, "error": "AI_ENABLED=false"}
    if not cfg.openrouter_api_key:
        return {"ok": False, "status": "unconfigured", "latency_ms": None, "error": "no API key set"}

    body = {
        "model": cfg.openrouter_model,
        "messages": [{"role": "user", "content": "Reply with the single word: OK"}],
        "max_tokens": 5,
    }
    headers = {"Authorization": f"Bearer {cfg.openrouter_api_key}", "Content-Type": "application/json"}
    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=cfg.ai_timeout_seconds) as client:
            resp = await client.post(f"{cfg.openrouter_base_url}/chat/completions", headers=headers, json=body)
        latency_ms = int((time.time() - start) * 1000)
        if resp.status_code == 200:
            db.log_ai_status("openrouter", cfg.openrouter_model, "ok", latency_ms, None)
            return {"ok": True, "status": "connected", "latency_ms": latency_ms, "error": None}
        err = f"HTTP {resp.status_code}: {resp.text[:200]}"
        db.log_ai_status("openrouter", cfg.openrouter_model, "error", latency_ms, err)
        return {"ok": False, "status": "error", "latency_ms": latency_ms, "error": err}
    except httpx.HTTPError as exc:
        latency_ms = int((time.time() - start) * 1000)
        err = f"{type(exc).__name__}: {exc}"
        db.log_ai_status("openrouter", cfg.openrouter_model, "error", latency_ms, err)
        return {"ok": False, "status": "unreachable", "latency_ms": latency_ms, "error": err}
