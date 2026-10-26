# AIPS — Limitations & Remaining Hardening Requirements

Read this before your demo. AIPS is a functional MVP built in one day for a
Grade 11 CTC submission. It is **not** production-ready, and claiming
otherwise in your presentation would be dishonest. Here is exactly what is
and isn't true about it.

## Security / hardening gaps (fix before using this on anything that matters)

1. **No dashboard authentication.** Anyone who can reach `http://127.0.0.1:8080`
   can view events, request blocks, and change mode. The only current
   protection is that AIPS refuses to start unless `AIPS_HOST=127.0.0.1`
   (see `app/config.py`), so only local processes/users on the same machine
   can reach it at all. If you ever change that, you MUST add real
   authentication first — this build does not include any.
2. **No CSRF protection on the API.** Mitigated somewhat by binding to
   loopback only and the browser's same-origin policy for fetch(), but a
   malicious local page could still script requests to `localhost:8080` if
   the user has the dashboard open. Add a CSRF token or an API key header
   before any wider exposure.
3. **Plain HTTP, no TLS.** Fine for `127.0.0.1`-only use on your own laptop;
   never put this behind a public IP without TLS in front of it.
4. **No per-user roles.** Every dashboard visitor has the same (full)
   privileges, including approving enforcement actions.
5. **No rate limiting on the AIPS API itself** — a flood of requests to the
   dashboard's own endpoints is not defended against.
6. **SQLite, not a hardened database.** Fine for a single-host demo; file
   permissions are the only access control. `.env` is created with `chmod
   600` by `setup.sh`, but `data/aips.db` currently is not explicitly
   locked down beyond default umask — tighten this (`chmod 600 data/aips.db`)
   if you keep using it past the demo.

## Detection limitations (be honest about these in your presentation)

- **Log-based only.** AIPS sees exactly what's in the access log: IP,
  timestamp, method, path, status, bytes, user-agent (if logged). It
  cannot see request bodies, most headers, or whether a login was
  *application-level* successful — only the HTTP status the server
  returned.
- **Reverse proxies change the source IP.** If the monitored service sits
  behind a reverse proxy, the access log's client IP may be the proxy's
  address, not the real client's, unless the log format and proxy are
  configured to forward/log the real IP. `log_discovery.py` does **not**
  auto-detect this — you classify `TARGET_BIND_SCOPE=behind_proxy`
  yourself if it applies, and double-check what IP actually ends up in the
  log before trusting it in a block decision.
- **Thresholds are static, not adaptive.** A slow, low-and-rate attacker
  who stays under `RATE_THRESHOLD`/`FAILED_LOGIN_THRESHOLD` will not
  trigger anything. This is a known, documented tradeoff of deterministic
  threshold rules versus a learned baseline — the latter was out of scope
  for a one-day build.
- **IP-based correlation only.** An attacker rotating source IPs defeats
  the per-IP windows and the repeat-offender bonus entirely.
- **No deep packet inspection, no TLS visibility, no WAF-grade payload
  analysis.** The `PATH_TRAVERSAL`/`SUSPICIOUS_PATH` rules are string
  matches on the request path only.

## Enforcement limitations

- Enforcement only works on Linux with `nftables` installed and the AIPS
  process able to run `nft` (normally requires root or `CAP_NET_ADMIN`).
  If `nft` isn't available, every block attempt fails closed and says so —
  it never pretends to have blocked anything (`app/response/enforcement.py`
  always checks `nft` availability before claiming success).
- A block only affects *new* connections matched by the firewall rule. It
  does not drop already-established connections, and it does nothing for a
  service bound only to `127.0.0.1` being accessed by another local process
  (a firewall rule cannot restrict loopback-to-loopback traffic from an
  already-trusted local process in the way it can restrict network traffic
  — document this honestly if your target is loopback-only).
- AIPS never modifies, restarts, or reloads the protected web server, and
  never touches any `nftables` table other than its own dedicated
  `inet aips_enforce` table — by design, so a bug here can't wipe your
  existing firewall configuration.

## Honeypot limitations

- Low-interaction by design: it logs the request line and headers, returns
  a generic canned response, and does nothing else. It does not emulate
  any specific service's full protocol, does not accept or process a
  request body meaningfully, and will not fool a sophisticated attacker
  performing active fingerprinting.

## Testing limitations

- The pytest suite (`tests/`) covers risk scoring, the rules engine,
  database operations, and the AI client (with mocked HTTP responses — no
  real API calls, no charges). It was **written and its underlying logic
  was manually executed and verified** during development (equivalent
  assertions run directly against the code), but the actual `pytest`
  command itself must be run on your machine after `pip install -r
  requirements.txt` — see `docs/ACCEPTANCE_TEST_REPORT.md` for the exact
  breakdown of what's been executed versus what you still need to run.
- There is no automated end-to-end test that starts the real FastAPI
  server and drives the dashboard through a browser. Your manual
  acceptance pass (also in `ACCEPTANCE_TEST_REPORT.md`) covers this.

## Hardware / environment limitations

- Built and reasoned through for a 4GB RAM laptop; no formal memory
  profiling was performed (no access to your actual hardware during
  development). If `uvicorn`/SQLite WAL mode causes memory pressure on
  your specific machine, consider reducing `RATE_WINDOW_SECONDS` query
  volume or lowering the dashboard's polling interval in `dashboard.js`.
- Tested logic only ran on a Linux container matching your target OS
  family; it was not run on your specific Kali Satellite C55 install.

## What would make this genuinely production-ready

1. Real authentication + HTTPS in front of the dashboard.
2. A hardened reverse proxy (e.g. properly configured nginx) in front of
   AIPS itself if ever exposed beyond localhost.
3. Adaptive/statistical baselining in addition to static thresholds.
4. Real integration tests against a running instance.
5. A security review of the `nft` subprocess calls (input is validated as
   a real IP address before use, but a formal review is still warranted
   before trusting this on anything beyond a demo).
6. Centralized logging/alerting instead of a single-host SQLite file.

None of the above was skipped by oversight — they were explicitly
deprioritized today in favor of a working, honest MVP per your stated
priority order (native startup → real observation → detection → safe
enforcement → AI → honeypot/polish).
