// Uptime monitor: is each studio site (spawn) answering, since when, and how
// reliably. Runs inside the dashboard server; results live in Postgres
// (uptime_sites / uptime_checks / uptime_incidents, created in initDB).
//
// The decisions are pure functions so they can be tested without a database:
//   applyResult  -- the 2-consecutive-failures rule and the up/down transitions
//   uptimePct    -- uptime percentage from check counts
//   formatClock  -- "3d 04:12:37" (mirrored in public/index.html, see there)
// createMonitor() is the impure part: the 60s loop, the DB writes, the emails.
//
// The honest limit: this runs on the dashboard, so if the dashboard (or
// Railway as a whole) is down, nothing here notices. An external free monitor
// pinging the dashboard's /health is the backstop for that.
'use strict';

const DOWN_AFTER = 2;            // consecutive failures before a site counts as DOWN
const TIMEOUT_MS = 10000;
const INTERVAL_MS = 60000;
const RETAIN_DAYS = 30;          // raw checks kept this long (~1440 rows/site/day)
const LOCK_KEY = 74_210_601;     // pg advisory lock: one checker at a time, even during a deploy overlap

const toMs = (v) => (v == null ? null : (v instanceof Date ? v.getTime() : (typeof v === 'number' ? v : new Date(v).getTime())));
const pad2 = (n) => String(n).padStart(2, '0');

// "3d 04:12:37", or "04:12:37" under a day. Live clock on the page.
// Mirror: formatUptimeClock in public/index.html — keep the two identical
// (test/uptime.test.js runs both against the same inputs).
function formatClock(ms) {
  if (!Number.isFinite(ms) || ms < 0) ms = 0;
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return (d > 0 ? d + 'd ' : '') + pad2(h) + ':' + pad2(m) + ':' + pad2(sec);
}

// "2h 5m", "45s", "3d 4h" -- for emails and incident lines, where a ticking
// hh:mm:ss would be noise.
function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) ms = 0;
  const s = Math.round(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm' + (s % 60 ? ' ' + (s % 60) + 's' : '');
  const h = Math.floor(m / 60);
  if (h < 24) return h + 'h' + (m % 60 ? ' ' + (m % 60) + 'm' : '');
  const d = Math.floor(h / 24);
  return d + 'd' + (h % 24 ? ' ' + (h % 24) + 'h' : '');
}

// null when there is no data, rather than a misleading 100% or 0%.
function uptimePct(ok, total) {
  ok = Number(ok) || 0; total = Number(total) || 0;
  if (total <= 0) return null;
  return Math.round((ok / total) * 10000) / 100;
}

// One check result in, the site's next state out, plus whether that is a
// transition worth an email. A site is DOWN only after DOWN_AFTER failures in
// a row, and its downtime is counted from the FIRST of them. 'unknown' -> 'up'
// is not a transition (a newly added site coming up is not news).
//   prev:   { status: 'unknown'|'up'|'down', statusSince, consecutiveFailures, firstFailAt }
//   result: { ok: boolean, at }
function applyResult(prev, result, downAfter = DOWN_AFTER) {
  const at = toMs(result.at);
  const p = {
    status: prev && prev.status ? prev.status : 'unknown',
    statusSince: toMs(prev && prev.statusSince),
    consecutiveFailures: (prev && prev.consecutiveFailures) | 0,
    firstFailAt: toMs(prev && prev.firstFailAt),
  };
  if (result.ok) {
    const next = { status: 'up', statusSince: p.status === 'up' && p.statusSince != null ? p.statusSince : at, consecutiveFailures: 0, firstFailAt: null };
    if (p.status === 'down') return { next, transition: 'up', downForMs: at - (p.statusSince != null ? p.statusSince : at) };
    return { next, transition: null };
  }
  const fails = p.consecutiveFailures + 1;
  const firstFailAt = p.consecutiveFailures > 0 && p.firstFailAt != null ? p.firstFailAt : at;
  if (p.status === 'down') return { next: { ...p, consecutiveFailures: fails, firstFailAt }, transition: null };
  if (fails >= downAfter) {
    return { next: { status: 'down', statusSince: firstFailAt, consecutiveFailures: fails, firstFailAt }, transition: 'down' };
  }
  return { next: { ...p, consecutiveFailures: fails, firstFailAt }, transition: null };
}

// 2xx/3xx is up. Redirects are not followed: a 301 to the right place means the
// site answered, and following it would test somebody else's server.
async function checkSite(url, { fetchImpl = fetch, timeoutMs = TIMEOUT_MS, now = Date.now } = {}) {
  const at = now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const t0 = Date.now();
  try {
    const res = await fetchImpl(url, {
      method: 'GET', redirect: 'manual', signal: ctrl.signal,
      headers: { 'User-Agent': 'KronaraUptime/1.0', 'Cache-Control': 'no-cache' },
    });
    const ms = Date.now() - t0;
    // Status is all we need; drop the body so the socket is freed.
    try { if (res.body && res.body.cancel) await res.body.cancel(); } catch (e) {}
    const ok = res.status >= 200 && res.status < 400;
    return { at, ok, statusCode: res.status, ms, error: ok ? null : 'HTTP ' + res.status };
  } catch (e) {
    const ms = Date.now() - t0;
    const timedOut = ctrl.signal.aborted || (e && e.name === 'AbortError');
    const cause = e && e.cause && (e.cause.code || e.cause.message);
    const error = timedOut ? 'Timed out after ' + Math.round(timeoutMs / 1000) + 's'
      : String((cause ? cause + ': ' : '') + (e && e.message || e)).slice(0, 300);
    return { at, ok: false, statusCode: null, ms, error };
  } finally {
    clearTimeout(timer);
  }
}

// 24 hourly buckets, oldest first, the last one being the current (partial)
// hour. rows: [{ hour, ok, total }] from date_trunc('hour', checked_at).
function fillHourBuckets(rows, nowMs, hours = 24) {
  const HOUR = 3600000;
  const cur = Math.floor(nowMs / HOUR) * HOUR;
  const byHour = new Map((rows || []).map(r => [Math.floor(toMs(r.hour) / HOUR) * HOUR, r]));
  const out = [];
  for (let i = hours - 1; i >= 0; i--) {
    const start = cur - i * HOUR;
    const r = byHour.get(start);
    out.push({ start: new Date(start).toISOString(), ok: r ? Number(r.ok) : 0, total: r ? Number(r.total) : 0 });
  }
  return out;
}

const escHtml = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hostOf = (u) => { try { return new URL(String(u)).host; } catch (e) { return String(u || ''); } };
const when = (ms) => new Date(ms).toUTCString();

function downEmail(site, { since, error, statusCode, dashboardUrl }) {
  const host = hostOf(site.url);
  return {
    subject: `DOWN: ${site.name} (${host})`,
    html: `<p><b>${escHtml(site.name)}</b> is not responding.</p>
      <p>Checked: <code>${escHtml(site.url)}</code><br>
      Failing since: ${escHtml(when(since))}<br>
      Last result: ${escHtml(error || (statusCode ? 'HTTP ' + statusCode : 'no response'))}</p>
      <p>You'll get one more email when it recovers.</p>
      ${dashboardUrl ? `<p><a href="${escHtml(dashboardUrl)}/#uptime">Open the uptime page</a></p>` : ''}`,
  };
}

function upEmail(site, { downForMs, since, upAt, dashboardUrl }) {
  const host = hostOf(site.url);
  return {
    subject: `RECOVERED: ${site.name} (${host}) — down for ${formatDuration(downForMs)}`,
    html: `<p><b>${escHtml(site.name)}</b> is responding again.</p>
      <p>Down for <b>${escHtml(formatDuration(downForMs))}</b><br>
      From: ${escHtml(when(since))}<br>
      To: ${escHtml(when(upAt))}</p>
      ${dashboardUrl ? `<p><a href="${escHtml(dashboardUrl)}/#uptime">Open the uptime page</a></p>` : ''}`,
  };
}

// The loop. One pass: check every unpaused site in parallel, record each
// result, apply the down rule, and send at most one email per transition.
// State lives on the uptime_sites row, so a dashboard restart neither loses a
// running clock nor re-sends an alert.
function createMonitor({ pool, sendMail, getAlertTo, dashboardUrl, fetchImpl, intervalMs = INTERVAL_MS, timeoutMs = TIMEOUT_MS, log = console }) {
  let timer = null, running = false, lastPrune = 0;

  async function recordAndTransition(site, r) {
    await pool.query(
      `INSERT INTO uptime_checks (site_id, checked_at, ok, status_code, response_ms, error) VALUES ($1,$2,$3,$4,$5,$6)`,
      [site.id, new Date(r.at), r.ok, r.statusCode, r.ms, r.error]);
    const { next, transition, downForMs } = applyResult({
      status: site.status, statusSince: site.status_since,
      consecutiveFailures: site.consecutive_failures, firstFailAt: site.first_fail_at,
    }, r);
    await pool.query(
      `UPDATE uptime_sites SET status=$2, status_since=$3, consecutive_failures=$4, first_fail_at=$5,
              last_checked_at=$6, last_ok=$7, last_status_code=$8, last_response_ms=$9, last_error=$10
        WHERE id=$1`,
      [site.id, next.status, next.statusSince != null ? new Date(next.statusSince) : null, next.consecutiveFailures,
       next.firstFailAt != null ? new Date(next.firstFailAt) : null, new Date(r.at), r.ok, r.statusCode, r.ms, r.error]);

    if (transition === 'down') {
      const inc = (await pool.query(
        `INSERT INTO uptime_incidents (site_id, started_at, error, status_code) VALUES ($1,$2,$3,$4) RETURNING id`,
        [site.id, new Date(next.statusSince), r.error, r.statusCode])).rows[0];
      const to = await getAlertTo();
      const sent = to ? await sendMail({ to, ...downEmail(site, { since: next.statusSince, error: r.error, statusCode: r.statusCode, dashboardUrl }) }) : false;
      await pool.query(`UPDATE uptime_incidents SET down_email_ok=$2 WHERE id=$1`, [inc.id, sent === true]);
      log.log(`[uptime] DOWN ${site.name} (${site.url}): ${r.error}`);
    } else if (transition === 'up') {
      const since = toMs(site.status_since);
      const inc = (await pool.query(
        `UPDATE uptime_incidents SET ended_at=$2 WHERE site_id=$1 AND ended_at IS NULL RETURNING id`,
        [site.id, new Date(r.at)])).rows[0];
      const to = await getAlertTo();
      const sent = to ? await sendMail({ to, ...upEmail(site, { downForMs, since, upAt: r.at, dashboardUrl }) }) : false;
      if (inc) await pool.query(`UPDATE uptime_incidents SET up_email_ok=$2 WHERE id=$1`, [inc.id, sent === true]);
      log.log(`[uptime] UP ${site.name} after ${formatDuration(downForMs)}`);
    }
  }

  async function runOnce() {
    if (running) return { skipped: 'already running' };
    running = true;
    let client;
    try {
      client = await pool.connect();
      const got = (await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY])).rows[0];
      if (!got || !got.ok) return { skipped: 'another instance holds the lock' };
      try {
        const sites = (await pool.query(`SELECT * FROM uptime_sites WHERE NOT paused ORDER BY sort_order, id`)).rows;
        const results = await Promise.all(sites.map(s => checkSite(s.url, { fetchImpl, timeoutMs })));
        for (let i = 0; i < sites.length; i++) {
          try { await recordAndTransition(sites[i], results[i]); }
          catch (e) { log.error('[uptime] record', sites[i].name, e.message); }
        }
        if (Date.now() - lastPrune > 3600000) {
          lastPrune = Date.now();
          await pool.query(`DELETE FROM uptime_checks WHERE checked_at < NOW() - ($1 || ' days')::interval`, [String(RETAIN_DAYS)]);
        }
        return { checked: sites.length };
      } finally {
        await client.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {});
      }
    } catch (e) {
      log.error('[uptime] run failed:', e.message);
      return { error: e.message };
    } finally {
      if (client) client.release();
      running = false;
    }
  }

  return {
    runOnce,
    start() {
      if (timer) return;
      // Stagger the first pass a little after boot so it doesn't race initDB's tail.
      const first = setTimeout(runOnce, 5000);
      if (first.unref) first.unref();
      timer = setInterval(runOnce, intervalMs);
      if (timer.unref) timer.unref();
      log.log(`[uptime] monitor started (every ${Math.round(intervalMs / 1000)}s)`);
    },
    stop() { if (timer) clearInterval(timer); timer = null; },
  };
}

module.exports = {
  DOWN_AFTER, TIMEOUT_MS, INTERVAL_MS, RETAIN_DAYS,
  formatClock, formatDuration, uptimePct, applyResult, checkSite, fillHourBuckets,
  downEmail, upEmail, createMonitor,
};
