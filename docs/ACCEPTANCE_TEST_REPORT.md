# AIPS Acceptance Test Report

Generated during development, before this project ever ran on your Kali
machine. The build environment I had access to while writing this had
**no internet access** and did not have `fastapi`, `uvicorn`, or `httpx`
installed, and no `nftables`/root access — so I could not start the actual
AIPS server or make real network calls. What follows is a precise,
honest account of what I actually executed and verified versus what
still requires you to run it.

Legend: ✅ Executed and verified here · ⬜ Written, not executed here — you
must run/verify this yourself.

## Mapped to your 14 acceptance criteria

1. **App starts in Kali without Docker** — ⬜ Not run here (no uvicorn in
   this sandbox). Verify with `./setup.sh && ./start.sh`.
2. **Database initializes and retains events after a restart** — ✅ Partial:
   `Database.__init__`'s schema creation, and insert/read persistence
   through the SQLite file across separate connections, were executed and
   verified directly (`tests/test_database.py` mirrors exactly what I ran).
   ⬜ A full process restart via `./stop.sh` + `./start.sh` with the real
   server was not exercised — do this once before your demo.
3. **Dashboard loads and updates from backend data** — ⬜ Not run here (no
   browser, no running server). The frontend JS was syntax-checked with
   `node --check` and its `getElementById` calls were cross-referenced
   against the HTML (5 apparent mismatches turned out to be elements
   created dynamically via `innerHTML` immediately before their listeners
   are attached — verified by reading the surrounding code, not a bug).
   Open it in a real browser and click through every nav item before your
   demo.
4. **A controlled TEST event appears in the feed, correctly labelled** —
   ✅ Partial: event insertion + `source_label` isolation logic (REAL vs
   SIMULATED vs TEST) was executed directly against the database and rules
   engine. ⬜ Seeing it rendered live in the dashboard via SSE was not
   exercised — verify by starting the Event Generator from Quick Controls
   and watching the Live Event Feed.
5. **Detection rules produce expected severity and reproducible risk
   score** — ✅ Executed directly. I ran the equivalent of every test in
   `tests/test_rules.py` and `tests/test_risk.py` against the real code
   (not a reimplementation) in this sandbox: brute-force threshold
   trigger/non-trigger, excess-rate, repeat-404, path-traversal and
   suspicious-path immediate triggers, malformed-method detection, normal
   traffic producing zero detections, dedup via `occurrence_count`
   instead of duplicate rows, the repeat-offender +20 bonus, and REAL/
   SIMULATED isolation. All passed. Also confirmed `risk_score` is
   identical across repeated calls with identical inputs (reproducibility)
   and capped at 100.
6. **OpenRouter configuration is read from `.env`** — ✅ Executed: built a
   real `.env` from `.env.example`, loaded it through `app/config.py`, and
   confirmed `openrouter_model`/`openrouter_api_key`/etc. populate
   correctly and `validate()` returns no problems for a well-formed file.
7. **AI integration reports real success/failure without crashing the
   detector** — ⬜ **Not executed** — `httpx` is not installed in this
   sandbox, so `app/ai/openrouter_client.py` could not be imported or run
   here, not even with mocks. It was syntax-checked (`py_compile`) and
   manually reviewed, and `tests/test_ai_mock.py` is written and ready,
   but you must run `pytest tests/test_ai_mock.py` yourself to get a real
   pass/fail. I'm flagging this clearly rather than implying it was
   tested. What I CAN confirm by code inspection: the rules engine
   (`evaluate_event`) never calls into the AI client at all — detection
   runs independently, so even a total AI outage cannot block it.
8. **Monitors actual configured web-server logs** — ✅ Partial: the
   Apache/Nginx "combined" and "common" log-line parser (`parse_line`) was
   executed against real sample log lines (including a malformed line)
   and produced correct structured output. The async file tailer
   (`tail_file`) was executed end-to-end with real file I/O, including
   simulating log rotation (file removed and recreated with a new inode
   mid-tail) — it correctly picked up new lines before and after rotation
   with no gaps or duplicates. ⬜ Running it against your actual nginx/
   apache log file on Kali was not exercised — do this first with
   `app/collectors/log_discovery.py` (also not executed here, since it
   shells out to `ss`/`netstat` and reads `/proc`, which needs your real
   system).
9. **Response Center records real outcomes, never reports a block that
   didn't happen** — ✅ Executed: ran `enforcement.apply_block` directly
   against all four gate conditions — monitor mode (→
   `simulated_monitor_mode`, no system call made), allowlisted target (→
   `refused_allowlisted`), unapproved request (→ `refused_not_approved`),
   and enforcement mode with no `nft` binary available in this sandbox (→
   `failed_nft_unavailable`, not a fake "applied"). All four recorded
   distinct, accurate outcomes in the `responses` table.
10. **Monitor mode makes no enforcement changes** — ✅ Executed as part of
    #9 above: in monitor mode, `apply_block` never calls `_run()` /
    `subprocess` at all — confirmed by code path and by the outcome being
    `simulated_monitor_mode`.
11. **Enforcement checks authorization, allowlist, expiration, rollback**
    — ✅ Partial: authorization (`approved` flag) and allowlist checks
    executed and verified (#9). `sweep_expired_blocks` and
    `rollback_block` were code-reviewed and are straightforward DB+nft
    operations following the same pattern as `apply_block`, but were not
    separately executed with a real expiring block in this sandbox since
    doing so meaningfully needs the full app loop running. Exercise this
    in your demo: request a short-duration block, watch it auto-expire.
12. **Existing firewall rules/config not destroyed** — ✅ By design and
    code review: `enforcement.py` never calls `nft flush` or any command
    touching a table other than its own `inet aips_enforce`; this was
    confirmed by reading every `_run()` call site, not by executing
    against a real nftables ruleset (no root/nft in this sandbox). Verify
    on your machine with `sudo nft list ruleset` before and after a demo
    block to confirm only the `aips_enforce` table changed.
13. **Secrets not committed to Git** — ✅ `.gitignore` excludes `.env` and
    `data/`; `.env.example` contains only empty/placeholder values. Verify
    yourself with `git status` after `git init` that `.env` never appears
    as trackable.
14. **A fresh setup can be repeated using the documentation** — ⬜ Not run
    here (no Kali environment). The `README.md` steps match exactly what
    `setup.sh`/`start.sh`/`stop.sh` do, cross-checked by reading both, but
    you should do one full clean run-through before presenting.

## Additional checks performed beyond the 14 criteria

- ✅ Every `.py` file in the project compiles cleanly (`python3 -m
  py_compile`) — no syntax errors anywhere, including `main.py` and
  `openrouter_client.py` which I otherwise couldn't execute.
- ✅ `dashboard.js` passes `node --check` (syntax valid).
- ✅ The audit trail's hash chain was executed end-to-end: wrote two real
  entries, verified the chain, then hand-tampered one entry's content in
  the file and confirmed `verify()` correctly detects the break.
- ✅ The honeypot server was started as a real `asyncio` TCP server on a
  test port and connected to with a real socket client sending a raw
  HTTP-looking request; confirmed it returned the canned response,
  logged the correct method/path/source IP to the database, and that the
  event carries `source_label='REAL'`.
- ✅ The synthetic event generator (`simulator.py`) was executed directly;
  confirmed every generated event always carries `source_label=
  'SIMULATED'`.

## What you must still do before presenting

1. `./setup.sh` then `./start.sh` on your actual Kali box — confirm it
   starts clean.
2. Open `http://127.0.0.1:8080` in a browser; click through every sidebar
   item once.
3. Run `python3 -m app.collectors.log_discovery` against your real local
   server, fill in `.env`'s `TARGET_*` fields, confirm real events show up
   in Live Events when you hit your own server a few times.
4. Start the Event Generator from Quick Controls, confirm SIMULATED events
   and detections appear and are visually distinguished from REAL ones.
5. `source venv/bin/activate && pytest` — run the real automated suite
   (this requires internet once, to `pip install -r requirements.txt`,
   which the setup script does for you).
6. If you intend to demo enforcement mode: set `AIPS_MODE=enforcement` (or
   use the Configuration tab), confirm `nft` is installed, and test one
   block + rollback cycle against a throwaway/allowlisted-excluded test IP
   — never test against an IP you need to keep reaching the box from.
7. If you intend to demo the AI integration: put a real `OPENROUTER_API_KEY`
   in `.env` and click "Run health check" in the Configuration tab before
   you're in front of your evaluators.
