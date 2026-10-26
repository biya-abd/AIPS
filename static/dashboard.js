// AIPS dashboard client. Vanilla JS, no external dependencies (keeps the
// dashboard usable even with no internet access on the demo machine).

const api = (path, opts) => fetch(path, opts).then(r => {
  if (!r.ok) return r.json().then(e => { throw new Error(e.detail || r.statusText); });
  return r.json();
});

function toast(msg, isError) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.style.borderColor = isError ? 'var(--red)' : 'var(--cyan)';
  el.style.display = 'block';
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => el.style.display = 'none', 3500);
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}
function fmtDateTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString();
}
function fmtUptime(seconds) {
  if (seconds == null) return '—';
  const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}
function severityBadge(sev) { return `<span class="badge ${sev}">${sev.toUpperCase()}</span>`; }
function labelBadge(label) { return `<span class="badge ${(label||'').toLowerCase()}">${label||''}</span>`; }
function statusBadge(status) { return `<span class="badge status-${status}">${status}</span>`; }

// ---------------------------------------------------------------- nav ----
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => switchView(item.dataset.view));
});
document.querySelectorAll('[data-goto]').forEach(item => {
  item.addEventListener('click', () => switchView(item.dataset.goto));
});
function switchView(view) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === `view-${view}`));
  loadView(view);
}
function loadView(view) {
  if (view === 'live-events') loadLiveEvents();
  else if (view === 'threats') loadThreats();
  else if (view === 'agent-activity') loadAgentActivity();
  else if (view === 'response-center') loadResponseCenter();
  else if (view === 'honeypot') loadHoneypot();
  else if (view === 'audit-logs') loadAuditLogs();
  else if (view === 'configuration') loadConfiguration();
}

// ------------------------------------------------------------- charts ----
function drawDonut(canvas, segments) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 6, rin = r * 0.6;
  let start = -Math.PI / 2;
  segments.forEach(seg => {
    const angle = (seg.value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, start, start + angle);
    ctx.closePath();
    ctx.fillStyle = seg.color;
    ctx.fill();
    start += angle;
  });
  ctx.globalCompositeOperation = 'destination-out';
  ctx.beginPath();
  ctx.arc(cx, cy, rin, 0, Math.PI * 2);
  ctx.fill();
  ctx.globalCompositeOperation = 'source-over';
  ctx.fillStyle = '#e6ecfa';
  ctx.font = 'bold 18px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total, cx, cy - 6);
  ctx.font = '9px sans-serif';
  ctx.fillStyle = '#8b97b8';
  ctx.fillText('EVENTS', cx, cy + 10);
}

function drawLine(canvas, points, color) {
  const ctx = canvas.getContext('2d');
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * devicePixelRatio;
  canvas.height = (canvas.height || 60) * devicePixelRatio;
  ctx.scale(devicePixelRatio, devicePixelRatio);
  const w = rect.width, h = canvas.height / devicePixelRatio;
  ctx.clearRect(0, 0, w, h);
  if (!points.length) {
    ctx.fillStyle = '#5b6687'; ctx.font = '11px sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('no data yet', w / 2, h / 2);
    return;
  }
  const max = Math.max(1, ...points);
  const stepX = w / Math.max(1, points.length - 1);
  ctx.beginPath();
  points.forEach((p, i) => {
    const x = i * stepX, y = h - (p / max) * (h - 8) - 4;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, color + '55');
  grad.addColorStop(1, color + '05');
  ctx.fillStyle = grad;
  ctx.fill();
}

// ---------------------------------------------------------- dashboard ----
async function loadOverview() {
  const ov = await api('/api/overview');
  document.getElementById('hdr-status-text').textContent = 'System Online';
  document.getElementById('hdr-mode-pill').textContent = `Mode: ${ov.mode}`;
  document.getElementById('hdr-mode-pill').className = 'pill mode-' + ov.mode;
  document.getElementById('hdr-ai-model').textContent = ov.ai_model;
  document.getElementById('hdr-uptime').textContent = fmtUptime(ov.uptime_seconds);
  const aiOk = ov.ai_last_status && ov.ai_last_status.status === 'ok';
  document.getElementById('hdr-ai-dot').style.background = aiOk ? 'var(--green)' : 'var(--text-faint)';
  document.getElementById('hdr-ai-status').textContent = ov.ai_last_status ? ov.ai_last_status.status : 'unknown';

  document.getElementById('ov-sensor').textContent = ov.collector_configured ? 'Online' : 'Not configured';
  document.getElementById('ov-sensor').className = 'card-value ' + (ov.collector_configured ? 'green' : 'amber');
  document.getElementById('ov-sensor-sub').textContent = ov.collector_configured ? `bind: ${ov.target_bind_scope}` : 'run log_discovery + set .env';
  document.getElementById('ov-backend').textContent = 'Healthy';
  document.getElementById('ov-epm').textContent = ov.events_per_minute;
  document.getElementById('ov-last-event').textContent = ov.last_event_ts ? fmtTime(ov.last_event_ts) : 'none yet';
  document.getElementById('ov-last-event-sub').textContent = ov.last_event_ts ? fmtDateTime(ov.last_event_ts) : '';
  document.getElementById('ov-ai-model-sub').textContent = ov.ai_model;
  document.getElementById('ov-uptime').textContent = fmtUptime(ov.uptime_seconds);
  document.getElementById('threat-score').textContent = ov.current_threat_score;
  document.getElementById('threat-score').style.color = ov.current_threat_score >= 60 ? 'var(--red)' : (ov.current_threat_score >= 30 ? 'var(--amber)' : 'var(--green)');
  document.getElementById('si-total-events').textContent = ov.total_events_real;
  document.getElementById('eg-status').textContent = ov.event_generator_running ? 'running' : 'stopped';
  document.getElementById('cfg-current-mode').textContent = ov.mode;
  document.getElementById('rc-mode').textContent = ov.mode;

  const dist = ov.severity_distribution;
  drawDonut(document.getElementById('chart-donut'), [
    { value: dist.critical, color: 'var(--critical)'.startsWith('var') ? '#ef4444' : dist.critical },
    { value: dist.high, color: '#f97316' },
    { value: dist.medium, color: '#f59e0b' },
    { value: dist.low, color: '#3b82f6' },
  ]);
  document.getElementById('donut-legend').innerHTML = `
    <div class="stat-row"><span><span class="badge critical">CRIT</span></span><span>${dist.critical}</span></div>
    <div class="stat-row"><span><span class="badge high">HIGH</span></span><span>${dist.high}</span></div>
    <div class="stat-row"><span><span class="badge medium">MED</span></span><span>${dist.medium}</span></div>
    <div class="stat-row"><span><span class="badge low">LOW</span></span><span>${dist.low}</span></div>`;

  loadHoneypotSummary(ov);
  loadResponseSummary();
}

async function loadSeries() {
  const epm = await api('/api/series/events-per-minute?minutes=60');
  drawLine(document.getElementById('chart-events-rate'), epm.map(p => p.count), '#3b82f6');
  const trend = await api('/api/series/risk-trend?hours=1');
  drawLine(document.getElementById('chart-risk-trend'), trend.map(p => p.avg_risk_score || 0), '#22d3ee');
}

function renderFeedRow(ev) {
  return `<tr>
    <td>${fmtTime(ev.ts)}</td>
    <td>${esc(ev.event_type || 'http_request')}</td>
    <td>${esc(ev.source_ip || '—')}</td>
    <td>${esc(ev.path || '—')}</td>
    <td>${ev.status_code != null ? ev.status_code : '—'}</td>
    <td>${labelBadge(ev.source_label)}</td>
  </tr>`;
}

async function loadDashFeed() {
  const label = document.getElementById('dash-feed-label').value;
  const events = await api(`/api/events?limit=25${label ? '&label=' + label : ''}`);
  document.getElementById('dash-feed-body').innerHTML = events.length
    ? events.map(ev => `<tr>
        <td>${fmtTime(ev.ts)}</td><td>${esc(ev.event_type)}</td><td>${esc(ev.source_ip || '—')}</td>
        <td>${esc(ev.path || '—')}</td><td>—</td><td>—</td></tr>`).join('')
    : `<tr><td colspan="6" class="empty-state">No events yet</td></tr>`;
}

async function loadDashRecentDetections() {
  const dets = await api('/api/detections?limit=6');
  const el = document.getElementById('dash-recent-detections');
  el.innerHTML = dets.length ? dets.map(d => `
    <div class="stat-row">
      <span>${severityBadge(d.severity)} <strong>${esc(d.rule_name)}</strong></span>
      <span class="faint">${esc(d.source_ip || '')}</span>
    </div>`).join('') : `<div class="empty-state">No detections yet</div>`;
}

async function loadDashAgentActivity() {
  const audit = await api('/api/audit?limit=6');
  const el = document.getElementById('dash-agent-activity');
  el.innerHTML = audit.length ? audit.map(a => `
    <div class="timeline-item"><div class="timeline-dot"></div>
      <div><div class="timeline-time">${fmtTime(a.ts)}</div>
      <div class="timeline-title">${esc(a.action)}</div>
      <div class="timeline-detail">${esc(a.details || '')}</div></div>
    </div>`).join('') : `<div class="empty-state">No activity yet</div>`;
}

async function loadResponseSummary() {
  const responses = await api('/api/responses?limit=200');
  const since = Date.now() / 1000 - 86400;
  const r24 = responses.filter(r => r.ts >= since);
  const count = (outcome) => r24.filter(r => r.outcome === outcome).length;
  const el = document.getElementById('dash-response-summary');
  el.innerHTML = `
    <div class="stat-row"><span class="muted">Applied (24h)</span><span>${count('applied')}</span></div>
    <div class="stat-row"><span class="muted">Simulated (monitor mode, 24h)</span><span>${count('simulated_monitor_mode')}</span></div>
    <div class="stat-row"><span class="muted">Refused (24h)</span><span>${count('refused_allowlisted') + count('refused_not_approved')}</span></div>
    <div class="stat-row"><span class="muted">Failed (24h)</span><span>${count('failed') + count('failed_nft_unavailable')}</span></div>`;
}

function loadHoneypotSummary(ov) {
  const el = document.getElementById('dash-honeypot-summary');
  if (!ov.honeypot_enabled) {
    el.innerHTML = `<div class="empty-state">Honeypot disabled (HONEYPOT_ENABLED=false)</div>`;
    return;
  }
  api('/api/honeypot/stats').then(s => {
    el.innerHTML = `
      <div class="stat-row"><span class="muted">Interactions</span><span>${s.interactions_24h}</span></div>
      <div class="stat-row"><span class="muted">Unique IPs (24h)</span><span>${s.unique_ips_24h}</span></div>`;
  });
}

// -------------------------------------------------------- live events ----
async function loadLiveEvents() {
  const label = document.getElementById('le-label').value;
  const search = document.getElementById('le-search').value.trim().toLowerCase();
  let events = await api(`/api/events?limit=300${label ? '&label=' + label : ''}`);
  if (search) events = events.filter(e => (e.source_ip || '').includes(search) || (e.path || '').toLowerCase().includes(search));
  document.getElementById('le-body').innerHTML = events.length ? events.map(e => `
    <tr><td>${fmtDateTime(e.ts)}</td><td>${esc(e.source_ip || '—')}</td><td>${esc(e.method || '—')}</td>
      <td>${esc(e.path || '—')}</td><td>${e.status_code != null ? e.status_code : '—'}</td>
      <td>${e.bytes_sent != null ? e.bytes_sent : '—'}</td><td>${labelBadge(e.source_label)}</td></tr>`).join('')
    : `<tr><td colspan="7" class="empty-state">No matching events</td></tr>`;
}
document.getElementById('le-refresh').addEventListener('click', loadLiveEvents);
document.getElementById('le-label').addEventListener('change', loadLiveEvents);
document.getElementById('le-search').addEventListener('input', () => { clearTimeout(window._leT); window._leT = setTimeout(loadLiveEvents, 300); });

// ------------------------------------------------------------ threats ----
async function loadThreats() {
  const severity = document.getElementById('th-severity').value;
  const label = document.getElementById('th-label').value;
  let dets = await api(`/api/detections?limit=300${label ? '&label=' + label : ''}`);
  if (severity) dets = dets.filter(d => d.severity === severity);
  document.getElementById('th-body').innerHTML = dets.length ? dets.map(d => `
    <tr>
      <td>${fmtDateTime(d.last_seen)}</td><td>${esc(d.rule_name)}</td><td>${esc(d.source_ip || '—')}</td>
      <td>${severityBadge(d.severity)}</td><td>${d.risk_score}</td><td>${d.occurrence_count}</td>
      <td>${statusBadge(d.investigation_status)}</td><td>${labelBadge(d.source_label)}</td>
      <td><button class="btn small" data-detail="${d.detection_id}">Details</button></td>
    </tr>`).join('') : `<tr><td colspan="9" class="empty-state">No detections</td></tr>`;
  document.querySelectorAll('[data-detail]').forEach(btn => btn.addEventListener('click', () => showDetectionDetail(btn.dataset.detail, dets)));
}
document.getElementById('th-refresh').addEventListener('click', loadThreats);
document.getElementById('th-severity').addEventListener('change', loadThreats);
document.getElementById('th-label').addEventListener('change', loadThreats);
document.getElementById('th-detail-close').addEventListener('click', () => document.getElementById('th-detail-card').style.display = 'none');

function showDetectionDetail(id, dets) {
  const d = dets.find(x => x.detection_id === id);
  if (!d) return;
  const card = document.getElementById('th-detail-card');
  card.style.display = 'block';
  document.getElementById('th-detail-body').innerHTML = `
    <div class="stat-row"><span class="muted">Rule / version</span><span>${esc(d.rule_name)} v${esc(d.rule_version)}</span></div>
    <div class="stat-row"><span class="muted">Severity / Risk</span><span>${severityBadge(d.severity)} ${d.risk_score}</span></div>
    <div class="stat-row"><span class="muted">Source IP</span><span>${esc(d.source_ip || '—')}</span></div>
    <div class="stat-row"><span class="muted">Occurrences</span><span>${d.occurrence_count}</span></div>
    <div class="stat-row"><span class="muted">First / Last seen</span><span>${fmtDateTime(d.first_seen)} → ${fmtDateTime(d.last_seen)}</span></div>
    <div class="stat-row"><span class="muted">Recommended action</span><span>${esc(d.recommended_action || '—')}</span></div>
    <div class="faint mt">Evidence</div>
    <pre class="mono" style="background:#0d1426; padding:10px; border-radius:8px; overflow-x:auto; font-size:11.5px;">${esc(JSON.stringify(d.evidence, null, 2))}</pre>
    <div class="flex mt">
      <button class="btn small" id="th-analyze">Ask AI to analyze</button>
      <button class="btn small" id="th-investigating">Mark Investigating</button>
      <button class="btn small" id="th-closed">Mark Closed</button>
      <button class="btn small" id="th-block">Request Block</button>
    </div>
    <div id="th-ai-result" class="mt"></div>`;
  document.getElementById('th-analyze').addEventListener('click', async () => {
    document.getElementById('th-ai-result').innerHTML = `<div class="faint">Analyzing…</div>`;
    try {
      const res = await api(`/api/detections/${id}/analyze`, { method: 'POST' });
      if (!res.ok) {
        document.getElementById('th-ai-result').innerHTML = `<div class="faint">AI unavailable: ${esc(res.error)}</div>`;
      } else {
        document.getElementById('th-ai-result').innerHTML = `
          <div class="card" style="background:#0d1426;">
            <strong>Summary:</strong> ${esc(res.summary)}<br>
            <strong>Steps:</strong><ul>${res.investigative_steps.map(s => `<li>${esc(s)}</li>`).join('')}</ul>
            <strong>Recommendation (advisory only):</strong> ${esc(res.recommendation)}
          </div>`;
      }
    } catch (e) { document.getElementById('th-ai-result').innerHTML = `<div class="faint">Error: ${esc(e.message)}</div>`; }
  });
  document.getElementById('th-investigating').addEventListener('click', () => setStatus(id, 'investigating'));
  document.getElementById('th-closed').addEventListener('click', () => setStatus(id, 'closed'));
  document.getElementById('th-block').addEventListener('click', () => {
    switchView('response-center');
    document.getElementById('rc-target-ip').value = d.source_ip || '';
    document.getElementById('rc-reason').value = `${d.rule_name} detection ${d.detection_id}`;
  });
}
async function setStatus(id, status) {
  await api(`/api/detections/${id}/status`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({status}) });
  toast(`Detection marked ${status}`);
  loadThreats();
}

// ------------------------------------------------------ agent activity ----
async function loadAgentActivity() {
  const audit = await api('/api/audit?limit=200');
  document.getElementById('aa-body').innerHTML = audit.length ? audit.map(a => `
    <div class="timeline-item"><div class="timeline-dot"></div>
      <div><div class="timeline-time">${fmtDateTime(a.ts)}</div>
      <div class="timeline-title">${esc(a.actor)} — ${esc(a.action)} <span class="faint">(${esc(a.outcome)})</span></div>
      <div class="timeline-detail">${esc(a.details || '')}</div></div>
    </div>`).join('') : `<div class="empty-state">No activity yet</div>`;
}
document.getElementById('aa-refresh').addEventListener('click', loadAgentActivity);

// ----------------------------------------------------- response center ----
async function loadResponseCenter() {
  const ov = await api('/api/overview');
  document.getElementById('rc-mode').textContent = ov.mode;
  const responses = await api('/api/responses?limit=300');
  document.getElementById('rc-applied').textContent = responses.filter(r => r.outcome === 'applied').length;
  document.getElementById('rc-refused').textContent = responses.filter(r => r.outcome.startsWith('refused') || r.outcome.startsWith('failed')).length;
  document.getElementById('rc-body').innerHTML = responses.length ? responses.map(r => `
    <tr>
      <td>${fmtDateTime(r.ts)}</td><td>${esc(r.target)}</td><td>${esc(r.action_type)}</td>
      <td>${esc(r.reason || '—')}</td><td>${r.approved ? 'yes' : 'no'}</td>
      <td>${esc(r.outcome)}</td>
      <td>${r.expires_at ? fmtDateTime(r.expires_at) : '—'}</td>
      <td>${(r.outcome === 'applied' && !r.rolled_back) ? `<button class="btn small" data-rollback="${r.response_id}">Rollback</button>` : (r.rolled_back ? 'rolled back' : '')}</td>
    </tr>`).join('') : `<tr><td colspan="8" class="empty-state">No response actions yet</td></tr>`;
  document.querySelectorAll('[data-rollback]').forEach(btn => btn.addEventListener('click', async () => {
    await api(`/api/responses/${btn.dataset.rollback}/rollback`, { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({}) });
    toast('Rolled back');
    loadResponseCenter();
  }));
}
document.getElementById('rc-refresh').addEventListener('click', loadResponseCenter);
document.getElementById('rc-submit').addEventListener('click', async () => {
  const target_ip = document.getElementById('rc-target-ip').value.trim();
  if (!target_ip) { toast('Target IP required', true); return; }
  try {
    const res = await api('/api/responses/block', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        target_ip,
        reason: document.getElementById('rc-reason').value || 'manual request',
        duration_minutes: parseInt(document.getElementById('rc-duration').value || '30', 10),
        approved: document.getElementById('rc-approve').checked,
        requested_by: 'dashboard_operator',
      }),
    });
    toast(`Outcome: ${res.outcome}`);
    loadResponseCenter();
  } catch (e) { toast(e.message, true); }
});

// -------------------------------------------------------------- honeypot ----
async function loadHoneypot() {
  const stats = await api('/api/honeypot/stats');
  document.getElementById('hp-status').textContent = stats.enabled ? 'Active' : 'Disabled';
  document.getElementById('hp-interactions').textContent = stats.interactions_24h;
  document.getElementById('hp-unique').textContent = stats.unique_ips_24h;
  const events = await api('/api/honeypot/events?limit=100');
  document.getElementById('hp-body').innerHTML = events.length ? events.map(e => `
    <tr><td>${fmtDateTime(e.ts)}</td><td>${esc(e.source_ip)}:${e.source_port || ''}</td>
      <td>${esc(e.method || '—')}</td><td>${esc(e.path || '—')}</td><td>${labelBadge(e.source_label)}</td></tr>`).join('')
    : `<tr><td colspan="5" class="empty-state">No honeypot interactions yet</td></tr>`;
}
document.getElementById('hp-refresh').addEventListener('click', loadHoneypot);

// ---------------------------------------------------------- audit logs ----
async function loadAuditLogs() {
  const audit = await api('/api/audit?limit=300');
  document.getElementById('al-body').innerHTML = audit.length ? audit.map(a => `
    <tr><td>${fmtDateTime(a.ts)}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td>
      <td>${esc(a.details || '')}</td><td>${esc(a.outcome)}</td></tr>`).join('')
    : `<tr><td colspan="5" class="empty-state">No audit entries yet</td></tr>`;
}
document.getElementById('al-refresh').addEventListener('click', loadAuditLogs);
document.getElementById('al-verify').addEventListener('click', async () => {
  const res = await api('/api/audit/verify');
  const el = document.getElementById('al-verify-result');
  el.style.display = 'block';
  el.textContent = `Audit file integrity: ${res.ok ? 'OK' : 'BROKEN'} — ${res.message}`;
  el.style.color = res.ok ? 'var(--green)' : 'var(--red)';
});

// --------------------------------------------------------- configuration ----
async function loadConfiguration() {
  const s = await api('/api/settings');
  document.getElementById('cfg-current-mode').textContent = s.mode;
  document.getElementById('cfg-ai-model').textContent = document.getElementById('hdr-ai-model').textContent;
  document.getElementById('cfg-bind-scope').textContent = s.target_bind_scope;
  document.getElementById('cfg-access-log').textContent = s.target_access_log_path || '(not set)';
}
document.getElementById('cfg-mode-monitor').addEventListener('click', () => setMode('monitor'));
document.getElementById('cfg-mode-enforcement').addEventListener('click', () => setMode('enforcement'));
async function setMode(mode) {
  await api('/api/settings/mode', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({mode}) });
  toast(`Mode set to ${mode}`);
  loadConfiguration(); loadOverview();
}
document.getElementById('cfg-ai-check').addEventListener('click', async () => {
  document.getElementById('cfg-ai-status').textContent = 'checking…';
  const res = await api('/api/ai/status');
  document.getElementById('cfg-ai-status').textContent = `${res.status}${res.latency_ms ? ' (' + res.latency_ms + 'ms)' : ''}${res.error ? ' — ' + res.error : ''}`;
});

// ----------------------------------------------------- quick controls ----
document.getElementById('btn-eg-start').addEventListener('click', () => toggleGenerator(true));
document.getElementById('btn-eg-stop').addEventListener('click', () => toggleGenerator(false));
async function toggleGenerator(running) {
  await api('/api/settings/event-generator', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({running}) });
  document.getElementById('eg-status').textContent = running ? 'running' : 'stopped';
}
document.getElementById('dash-feed-label').addEventListener('change', loadDashFeed);

// -------------------------------------------------------------- SSE ------
function connectStream() {
  const es = new EventSource('/api/stream');
  es.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === 'event' || msg.type === 'detection') {
        loadDashFeed(); loadDashRecentDetections(); loadOverview();
        if (document.getElementById('view-threats').classList.contains('active')) loadThreats();
        if (document.getElementById('view-live-events').classList.contains('active')) loadLiveEvents();
      } else if (msg.type === 'honeypot') {
        if (document.getElementById('view-honeypot').classList.contains('active')) loadHoneypot();
      } else if (msg.type === 'response') {
        loadResponseSummary();
        if (document.getElementById('view-response-center').classList.contains('active')) loadResponseCenter();
      }
    } catch (e) { /* ignore malformed */ }
  };
  es.onerror = () => { /* browser auto-reconnects; nothing to do */ };
}

// --------------------------------------------------------------- boot ----
async function init() {
  await loadOverview();
  await loadSeries();
  await loadDashFeed();
  await loadDashRecentDetections();
  await loadDashAgentActivity();
  connectStream();
  setInterval(loadOverview, 5000);
  setInterval(loadSeries, 15000);
  setInterval(loadDashAgentActivity, 10000);
}
init();
