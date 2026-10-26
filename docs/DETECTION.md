# AIPS Detection Rules & Risk Scoring Reference

This is the human-readable companion to `app/detection/rules.py` and
`app/detection/risk.py`. If the two ever disagree, the code is authoritative —
this document is for your presentation and for tuning thresholds.

## What AIPS can and cannot see

Every REAL event comes from one source: the web server's access log, tailed
line by line (`app/collectors/log_collector.py`). That means AIPS can see,
per request: client IP, timestamp, HTTP method, path, status code, bytes
sent, and user-agent (if the log format includes it).

It CANNOT see: request/response bodies, headers beyond what's logged,
whether a login attempt was *application-level* successful (only the HTTP
status code the server returned), encrypted payload contents, or anything
that never reached the web server's log (e.g. a request blocked earlier by
something else). Say this plainly in your demo rather than implying
blanket visibility.

## Detection rules

| Rule | Trigger condition | Base score |
|---|---|---|
| `BRUTE_FORCE` | ≥ `FAILED_LOGIN_THRESHOLD` requests to a login-like path (`/login`, `/admin/login`, etc.) with status 401/403 from the same IP within `FAILED_LOGIN_WINDOW_SECONDS` | 40 |
| `EXCESS_RATE` | ≥ `RATE_THRESHOLD` total requests from the same IP within `RATE_WINDOW_SECONDS` | 30 |
| `REPEAT_404` | ≥ `REPEAT_404_THRESHOLD` 404 responses to the same IP within `REPEAT_404_WINDOW_SECONDS` (resource enumeration / scanning) | 25 |
| `PATH_TRAVERSAL` | request path contains a traversal marker (`../`, `%2e%2e`, etc.) — fires on the single request, no window | 50 |
| `SUSPICIOUS_PATH` | request path matches a known sensitive-path marker (`/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, ...) — fires on the single request | 35 |
| `MALFORMED_REQUEST` | unrecognized HTTP method, path not starting with `/`, or path > 2048 chars | 30 |

All thresholds are environment variables (see `.env.example`) — nothing is
hardcoded as a Python constant that requires a code change to tune.

## Risk scoring formula

```
risk_score = min(100, BASE[rule] + FREQUENCY_BONUS + OFFENDER_BONUS)

FREQUENCY_BONUS = min(30, (occurrence_count - 1) * 3)
OFFENDER_BONUS  = 20 if this source IP has triggered >= REPEAT_OFFENDER_RULE_COUNT
                       DISTINCT rules within REPEAT_OFFENDER_WINDOW_SECONDS, else 0
```

Severity bands (fixed):

| Score | Severity |
|---|---|
| 0–29 | low |
| 30–59 | medium |
| 60–84 | high |
| 85–100 | critical |

Every number here is deterministic and reproducible from the evidence
stored with the detection (`evidence_json` in the `detections` table) — no
randomness, no ML model, no hidden state.

## Deduplication

Detections are grouped by `group_key = f"{rule_name}:{source_ip}"`. A new
matching event against an *open* (non-closed) detection with the same
group key increments `occurrence_count` and refreshes `last_seen` instead
of creating a new row — this is what the dashboard's "Investigation status"
workflow (new → investigating → analyzed → closed) is for: closing a
detection lets a genuinely new incident from the same rule+IP start a fresh
group.

## What a detection does NOT mean

A detection means the deterministic rule's condition was met by the
evidence available. It does **not** by itself mean a successful compromise,
and `confirmed_attack` stays `false` on every detection unless a human
investigator sets it after review. The dashboard's distinction between
"suspicious event" and "confirmed attack" is enforced at the data level, not
just in wording.

## AI layer

The OpenRouter/Nemotron integration (`app/ai/openrouter_client.py`) is
purely additive: given a redacted detection record, it returns a short
natural-language summary, 2-4 investigative steps, and one advisory
recommendation. It never changes `risk_score`, `severity`, or triggers an
enforcement action on its own — see `docs/LIMITATIONS.md`.
