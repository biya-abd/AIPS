# AIPS — Agentic Intrusion Prevention System

INSA CTC Project. A lightweight, native (no Docker) defensive monitoring
and detection dashboard for your own local web server, with optional
AI-assisted analysis (OpenRouter / Nemotron) and optional, explicitly
approved, reversible enforcement.

**Read `docs/LIMITATIONS.md` before your demo.** This is a one-day MVP,
not a production security product, and the limitations doc says exactly
where the edges are.

## Project Information
AIPS is a defensive host-based and web-traffic monitoring system built
for the INSA CTC project. It observes a local web server's access
logs, applies deterministic detection rules (brute force, excess
request rate, repeated 404s, path traversal, suspicious-path probing,
malformed requests), scores risk with a documented reproducible
formula, displays everything on a live dashboard, and optionally
requests AI-assisted analysis via OpenRouter/Nemotron. Any firewall
enforcement is monitor-mode-safe by default, allowlisted, time-limited,
and requires explicit human approval before anything is applied.

## Team Information
- [FULL NAME] — [CTC ID]
- Biyansa Abdurahman — CTC-3810-26


## What this actually does

- Tails your real web server's access log (nginx/apache "combined" or
  "common" format) and parses each request.
- Runs 6 deterministic detection rules (brute force, excess rate, repeat
  404, path traversal, suspicious path, malformed request) with a
  documented, reproducible risk-scoring formula — see `docs/DETECTION.md`.
- Shows everything on a live-updating dashboard (REAL data only drives the
  real counters; a separate, clearly labeled SIMULATED event generator
  exists purely for safe demos and never touches real statistics).
- Can optionally ask OpenRouter/Nemotron for a plain-English summary and
  investigative steps on a detection you select — advisory only, never
  auto-executed.
- Can optionally apply a reversible, allowlisted, time-limited firewall
  block via its own dedicated `nftables` table — only in "enforcement"
  mode, and only when you explicitly approve it in the dashboard.
- Everything is logged to a queryable audit trail with tamper-evidence
  (hash-chained file + DB table).

## 1. Requirements

- Kali Linux (or any recent Debian-based Linux) with Python 3.9+.
- A web server already running locally that you're allowed to monitor
  (this does not start one for you).
- Optional: `nftables` installed and the ability to run it as root, if you
  want to try enforcement mode.
- Optional: an OpenRouter API key, if you want the AI analysis feature.

## 2. Setup (run once)

```bash
cd aips
chmod +x setup.sh start.sh stop.sh   # already executable, but just in case
./setup.sh
```

This creates a Python virtual environment, installs the pinned
dependencies from `requirements.txt`, creates `./data/` for the database
and audit log, and copies `.env.example` to `.env` (chmod 600). It makes
**no** firewall or network changes and does not touch anything outside
this project directory.

## 3. Find your target server (read-only)

```bash
./venv/bin/python3 -m app.collectors.log_discovery
```

This inspects `ss -ltnp` and `/proc` to tell you what's listening on port
80, whether it's loopback-only or LAN-exposed, and tries to find its
access log on disk. It makes no changes. Take its output and fill in
`.env`:

```
TARGET_BIND_SCOPE=loopback_only        # or lan_exposed / behind_proxy / unknown
TARGET_ACCESS_LOG_PATH=/var/log/nginx/access.log
TARGET_LOG_FORMAT=combined             # or common
```

If the discovery script finds nothing, your server may not be running, or
it may not produce a standard access log (e.g. a bare Python dev server)
— in which case AIPS has nothing to observe and you should say so plainly
in your demo rather than fabricating data.

## 4. Configure AI (optional)

Edit `.env`:

```
OPENROUTER_API_KEY=sk-...your key...
AI_ENABLED=true
```

Leave `AI_ENABLED=false` (or the key blank) if you don't want this —
detection and the dashboard work fully without it.

## 5. Start

```bash
./start.sh
```

Starts the dashboard on `http://127.0.0.1:8080` (or whatever you set
`AIPS_HOST`/`AIPS_PORT` to in `.env` — it refuses to start on a non-
loopback host by default, on purpose). Logs go to `data/aips.out.log`.
Open the URL in a browser.

## 6. Stop

```bash
./stop.sh
```

Stops the process. It does **not** remove any active enforcement blocks —
roll those back from the Response Center first if you want them gone
immediately, otherwise they expire on their own schedule.

## 7. Run the automated tests

```bash
source venv/bin/activate
pytest
```

Covers risk scoring, the rules engine, database operations, and the AI
client (mocked HTTP — no real API calls or charges). See
`docs/ACCEPTANCE_TEST_REPORT.md` for exactly what's been verified already
versus what this run confirms for the first time on your machine.

## 8. Demonstration procedure for your presentation

1. **Show it's real, not fake.** Open Configuration, point at
   `TARGET_ACCESS_LOG_PATH` and bind scope. Open a second terminal and
   `curl` your own server a few times (including something like
   `curl http://localhost/.env` and `curl http://localhost/this-does-not-exist`
   a handful of times) — watch those exact requests appear in Live
   Events labeled REAL, in real time, with no page reload.
2. **Show detection working.** After enough repeated 404s/suspicious
   paths, point out the new entry under Threats, open its detail panel,
   and show the evidence JSON that produced its score — walk through the
   formula in `docs/DETECTION.md` so the scoring isn't a black box.
3. **Show the AI layer (if configured).** Click "Ask AI to analyze" on a
   detection; show the summary/steps/recommendation, and explicitly point
   out it's advisory-only — nothing happened to the system because of it.
4. **Show safe demo mode.** Switch to Live Events with the Simulation
   source filter, start the Event Generator from Quick Controls, and
   point out these are clearly labeled SIMULATED and excluded from the
   real counters — contrast with step 1's REAL traffic.
5. **Show enforcement, carefully.** If you've set up `nftables` and
   switched to enforcement mode: pick a detection from a test/simulated
   source (never block an IP you need to keep demoing from), request a
   block with a short duration, show it applied in Response Center, then
   roll it back manually to show the reversibility.
6. **Show the audit trail.** Open Audit Logs, click "Verify integrity" to
   show the hash chain is intact, and point out every action taken during
   the demo — including AI calls and the block/rollback — is there with a
   timestamp.
7. **Be upfront about limitations.** Reference `docs/LIMITATIONS.md` —
   showing you know exactly what this does and doesn't do is a stronger
   submission than overclaiming.

## Project layout

```
aips/
  app/
    main.py                FastAPI app, routes, startup wiring
    config.py               .env loading + validation
    database.py              SQLite schema + all queries
    audit.py                 hash-chained audit trail
    simulator.py             SIMULATED event generator (demo only)
    ws_manager.py             SSE live-update broadcaster
    collectors/
      log_discovery.py        read-only port-80/log discovery
      log_collector.py         log tailing + parsing (REAL events)
    detection/
      rules.py                 6 deterministic detection rules
      risk.py                   risk scoring formula
    ai/
      openrouter_client.py      OpenRouter/Nemotron client (redacted, bounded)
    response/
      enforcement.py            allowlisted/approved/reversible nft blocking
    honeypot/
      honeypot_server.py         low-interaction honeypot (optional)
  static/
    dashboard.html / .css / .js  the dashboard UI (vanilla JS, no CDN deps)
  tests/                        pytest suite
  docs/
    DETECTION.md                 rules + scoring reference
    LIMITATIONS.md                 honest gaps + hardening roadmap
    ACCEPTANCE_TEST_REPORT.md       what's been verified vs what you must run
  setup.sh / start.sh / stop.sh
  requirements.txt / .env.example / .gitignore
```
