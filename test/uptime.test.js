#!/usr/bin/env node
/**
 * Uptime monitor: the 2-failure rule, one email per transition, uptime %,
 * the clock format (server and page copies identical), and the checker itself.
 *
 *   node test/uptime.test.js
 */
"use strict";

const fs = require("fs");
const path = require("path");
const U = require("../lib/uptime");

const ROOT = path.join(__dirname, "..");
const html = fs.readFileSync(path.join(ROOT, "public", "index.html"), "utf8");
const server = fs.readFileSync(path.join(ROOT, "server.js"), "utf8");

let fails = 0;
const ok = (c, label, detail) => {
  if (!c) { fails++; console.log("  FAIL  " + label + (detail !== undefined ? "\n        " + detail : "")); }
  else console.log("  ok    " + label);
};
const eq = (a, b, label) => ok(JSON.stringify(a) === JSON.stringify(b), label, "got " + JSON.stringify(a) + ", want " + JSON.stringify(b));

const S = 1000, MIN = 60 * S, H = 60 * MIN, D = 24 * H;

// ── Clock formatting ──────────────────────────────────────────────────
eq(U.formatClock(0), "00:00:00", "clock: zero");
eq(U.formatClock(59 * S + 999), "00:00:59", "clock: floors partial seconds");
eq(U.formatClock(3 * D + 4 * H + 12 * MIN + 37 * S), "3d 04:12:37", "clock: the example from the brief");
eq(U.formatClock(23 * H + 59 * MIN + 59 * S), "23:59:59", "clock: no day part under a day");
eq(U.formatClock(D), "1d 00:00:00", "clock: exactly one day");
eq(U.formatClock(400 * D + 5 * S), "400d 00:00:05", "clock: long uptimes keep counting days");
eq(U.formatClock(-5000), "00:00:00", "clock: negative (clock skew) clamps to zero");
eq(U.formatClock(NaN), "00:00:00", "clock: garbage clamps to zero");

eq(U.formatDuration(45 * S), "45s", "duration: seconds");
eq(U.formatDuration(4 * MIN + 10 * S), "4m 10s", "duration: minutes and seconds");
eq(U.formatDuration(2 * H + 5 * MIN), "2h 5m", "duration: hours and minutes");
eq(U.formatDuration(3 * D + 4 * H), "3d 4h", "duration: days and hours");
eq(U.formatDuration(2 * MIN), "2m", "duration: drops a zero remainder");

// The page has its own copy (no shared module between server and browser).
{
  const grab = (name) => {
    const m = html.match(new RegExp("function " + name + "\\(ms\\) \\{[\\s\\S]*?\\n\\}"));
    return m ? new Function(m[0] + "; return " + name + ";")() : null;
  };
  const clientClock = grab("formatUptimeClock"), clientDur = grab("formatUptimeDuration");
  ok(clientClock && clientDur, "found the page's clock and duration functions");
  const samples = [0, 999, 59 * S, 61 * S, H - 1, 2 * H + 5 * MIN, D - 1, D, 3 * D + 4 * H + 12 * MIN + 37 * S, 400 * D, -1, NaN];
  ok(clientClock && samples.every(x => clientClock(x) === U.formatClock(x)), "page clock matches lib/uptime.js formatClock on every sample");
  ok(clientDur && samples.every(x => clientDur(x) === U.formatDuration(x)), "page duration matches lib/uptime.js formatDuration on every sample");
}

// ── Uptime % ──────────────────────────────────────────────────────────
eq(U.uptimePct(0, 0), null, "pct: no data is null, not 0% or 100%");
eq(U.uptimePct(1440, 1440), 100, "pct: all ok");
eq(U.uptimePct(1438, 1440), 99.86, "pct: two failed checks in a day");
eq(U.uptimePct("719", "720"), 99.86, "pct: accepts pg COUNT strings");
eq(U.uptimePct(0, 10), 0, "pct: all failed");

// ── The 2-failure rule and transitions ────────────────────────────────
{
  const t0 = Date.UTC(2026, 10, 2, 12, 0, 0);
  const at = (i) => t0 + i * MIN;

  let r = U.applyResult({ status: "unknown" }, { ok: true, at: at(0) });
  eq([r.next.status, r.transition], ["up", null], "unknown -> up is not a transition (no email for a new site)");
  eq(r.next.statusSince, at(0), "clock starts at the first good check");

  let st = r.next;
  r = U.applyResult(st, { ok: true, at: at(1) });
  eq(r.next.statusSince, at(0), "up stays up: clock keeps its original start");

  r = U.applyResult(r.next, { ok: false, at: at(2) });
  eq([r.next.status, r.transition, r.next.consecutiveFailures], ["up", null, 1], "one failure is a blip: still up, no email");
  eq(r.next.statusSince, at(0), "a blip does not reset the up clock");

  r = U.applyResult(r.next, { ok: true, at: at(3) });
  eq([r.next.status, r.transition, r.next.consecutiveFailures], ["up", null, 0], "blip then success: streak resets, no transition");
  eq(r.next.statusSince, at(0), "...and the up clock is still unbroken");

  r = U.applyResult(r.next, { ok: false, at: at(4) });
  r = U.applyResult(r.next, { ok: false, at: at(5) });
  eq([r.next.status, r.transition], ["down", "down"], "two failures in a row: DOWN, one transition");
  eq(r.next.statusSince, at(4), "downtime is counted from the FIRST failure");

  r = U.applyResult(r.next, { ok: false, at: at(6) });
  eq([r.next.status, r.transition, r.next.consecutiveFailures], ["down", null, 3], "still failing: no second down email");
  eq(r.next.statusSince, at(4), "down clock keeps its start");

  r = U.applyResult(r.next, { ok: true, at: at(10) });
  eq([r.next.status, r.transition], ["up", "up"], "first success after down: UP transition");
  eq(r.downForMs, 6 * MIN, "recovery reports how long it was down (first failure -> recovery)");
  eq(r.next.statusSince, at(10), "up clock restarts at recovery");

  // Fail, ok, fail, ok... never two in a row: never down.
  let s2 = { status: "up", statusSince: at(0), consecutiveFailures: 0 }, transitions = 0;
  for (let i = 1; i <= 20; i++) { const x = U.applyResult(s2, { ok: i % 2 === 0, at: at(i) }); if (x.transition) transitions++; s2 = x.next; }
  eq([s2.status, transitions], ["up", 0], "alternating blips never trip the rule");

  // A site that never comes up still alerts once.
  r = U.applyResult({ status: "unknown" }, { ok: false, at: at(0) });
  r = U.applyResult(r.next, { ok: false, at: at(1) });
  eq(r.transition, "down", "a new site that fails twice from the start alerts");

  // Dates from Postgres (Date objects / ISO strings) work as state.
  r = U.applyResult({ status: "down", statusSince: new Date(at(0)).toISOString(), consecutiveFailures: 5, firstFailAt: new Date(at(0)) }, { ok: true, at: new Date(at(30)) });
  eq([r.transition, r.downForMs], ["up", 30 * MIN], "state read back from the DB (ISO / Date) works");

  ok(U.DOWN_AFTER === 2, "DOWN_AFTER is 2");
}

// ── Hour buckets for the history strip ────────────────────────────────
{
  const now = Date.UTC(2026, 10, 2, 12, 34, 0);
  const b = U.fillHourBuckets([
    { hour: new Date(Date.UTC(2026, 10, 2, 12)), ok: "30", total: "34" },
    { hour: new Date(Date.UTC(2026, 10, 2, 0)), ok: 60, total: 60 },
    { hour: new Date(Date.UTC(2026, 10, 1, 12)), ok: 1, total: 1 },   // outside the window
  ], now);
  eq(b.length, 24, "buckets: 24 of them");
  eq(b[23], { start: "2026-11-02T12:00:00.000Z", ok: 30, total: 34 }, "buckets: last is the current partial hour");
  eq(b[11], { start: "2026-11-02T00:00:00.000Z", ok: 60, total: 60 }, "buckets: placed by hour");
  eq(b[0], { start: "2026-11-01T13:00:00.000Z", ok: 0, total: 0 }, "buckets: empty hours are zeros; older rows ignored");
}

// ── Emails ────────────────────────────────────────────────────────────
{
  const site = { name: "Aradia <prod>", url: "https://aradiafitness.app/api/known-features" };
  const d = U.downEmail(site, { since: Date.UTC(2026, 10, 2, 12), error: "Timed out after 10s", dashboardUrl: "https://dash.example" });
  ok(/^DOWN: Aradia <prod> \(aradiafitness\.app\)$/.test(d.subject), "down email subject names site and host", d.subject);
  ok(d.html.includes("Aradia &lt;prod&gt;") && !d.html.includes("<prod>"), "down email escapes the site name");
  ok(d.html.includes("Timed out after 10s") && d.html.includes("https://dash.example/#uptime"), "down email has the error and the page link");
  const u = U.upEmail(site, { downForMs: 4 * MIN + 10 * S, since: Date.UTC(2026, 10, 2, 12), upAt: Date.UTC(2026, 10, 2, 12, 4, 10) });
  ok(/RECOVERED: .* down for 4m 10s$/.test(u.subject), "recovery email subject says how long it was down", u.subject);
}

(async () => {
  // ── checkSite against a fake fetch ──────────────────────────────────
  const resp = (status) => ({ status, body: { cancel: async () => {} } });
  let seenOpts;
  let r = await U.checkSite("https://x.test/a", { fetchImpl: async (u, o) => { seenOpts = o; return resp(200); } });
  eq([r.ok, r.statusCode, r.error], [true, 200, null], "check: 200 is up");
  ok(seenOpts.redirect === "manual", "check: redirects are not followed");
  ok(typeof r.ms === "number" && r.ms >= 0, "check: response time recorded");
  r = await U.checkSite("https://x.test/a", { fetchImpl: async () => resp(302) });
  eq([r.ok, r.statusCode], [true, 302], "check: 3xx is up");
  r = await U.checkSite("https://x.test/a", { fetchImpl: async () => resp(503) });
  eq([r.ok, r.statusCode, r.error], [false, 503, "HTTP 503"], "check: 5xx is a failure");
  r = await U.checkSite("https://x.test/a", { fetchImpl: async () => { const e = new TypeError("fetch failed"); e.cause = { code: "ENOTFOUND" }; throw e; } });
  eq([r.ok, r.statusCode, r.error], [false, null, "ENOTFOUND: fetch failed"], "check: DNS / network error is a failure with the cause");
  const hang = (u, o) => new Promise((_, rej) => o.signal.addEventListener("abort", () => { const e = new Error("aborted"); e.name = "AbortError"; rej(e); }));
  r = await U.checkSite("https://x.test/a", { fetchImpl: hang, timeoutMs: 30 });
  eq([r.ok, r.error], [false, "Timed out after 0s"], "check: a hang is cut off by the timeout");
  ok(U.TIMEOUT_MS === 10000 && U.INTERVAL_MS === 60000, "defaults: 10s timeout, 60s interval");

  // ── The monitor end to end against a fake database ──────────────────
  // One site; fetch answers from a script. Counts emails and incident rows.
  const site = { id: 1, name: "Aradia", url: "https://aradiafitness.app/api/known-features", paused: false,
                 status: "unknown", status_since: null, consecutive_failures: 0, first_fail_at: null };
  const incidents = [], checks = [], mails = [];
  let lockFree = true;
  const q = async (sql, p) => {
    const s = String(sql).replace(/\s+/g, " ");
    if (/pg_try_advisory_lock/.test(s)) { const got = lockFree; return { rows: [{ ok: got }] }; }
    if (/pg_advisory_unlock/.test(s)) return { rows: [] };
    if (/FROM uptime_sites WHERE NOT paused/.test(s)) return { rows: site.paused ? [] : [{ ...site }] };
    if (/INSERT INTO uptime_checks/.test(s)) { checks.push(p); return { rows: [] }; }
    if (/UPDATE uptime_sites SET status=/.test(s)) {
      Object.assign(site, { status: p[1], status_since: p[2], consecutive_failures: p[3], first_fail_at: p[4] });
      return { rows: [] };
    }
    if (/INSERT INTO uptime_incidents/.test(s)) { const id = incidents.length + 1; incidents.push({ id, started_at: p[1], ended_at: null }); return { rows: [{ id }] }; }
    if (/UPDATE uptime_incidents SET ended_at/.test(s)) {
      const open = incidents.find(i => !i.ended_at); if (open) open.ended_at = p[1];
      return { rows: open ? [{ id: open.id }] : [] };
    }
    if (/UPDATE uptime_incidents SET (down|up)_email_ok/.test(s)) { const i = incidents.find(x => x.id === p[0]); if (i) i[/down/.test(s) ? "down_ok" : "up_ok"] = p[1]; return { rows: [] }; }
    if (/DELETE FROM uptime_checks/.test(s)) return { rows: [] };
    throw new Error("unexpected SQL: " + s);
  };
  const pool = { query: q, connect: async () => ({ query: q, release() {} }) };
  const script = [];
  const mon = U.createMonitor({
    pool, dashboardUrl: "https://dash.example",
    sendMail: async (m) => { mails.push(m); return true; },
    getAlertTo: async () => ["admin@kronara.app"],
    fetchImpl: async () => resp(script.shift()),
    log: { log() {}, error() {} },
  });
  const run = async (...codes) => { for (const c of codes) { script.push(c); await mon.runOnce(); } };

  await run(200, 200);
  eq([site.status, mails.length], ["up", 0], "monitor: healthy site, no email");
  await run(500);
  eq([site.status, mails.length, incidents.length], ["up", 0, 0], "monitor: one blip, no email, no incident");
  await run(200, 500, 500);
  eq([site.status, mails.length, incidents.length], ["down", 1, 1], "monitor: two in a row -> down, exactly one email, one incident");
  ok(mails[0].subject.startsWith("DOWN: Aradia") && mails[0].to[0] === "admin@kronara.app", "monitor: down email to the alert address", JSON.stringify(mails[0].to));
  await run(500, 503, 500, 500);
  eq(mails.length, 1, "monitor: staying down sends nothing more");
  await run(200);
  eq([site.status, mails.length], ["up", 2], "monitor: recovery sends exactly one more email");
  ok(/RECOVERED: Aradia .* down for/.test(mails[1].subject), "monitor: recovery email says how long", mails[1].subject);
  ok(incidents[0].ended_at && incidents[0].down_ok === true && incidents[0].up_ok === true, "monitor: incident closed, both emails recorded as sent");
  await run(200, 200);
  eq(mails.length, 2, "monitor: back to normal, quiet");
  eq(checks.length, 13, "monitor: every check recorded");

  lockFree = false;
  const before = checks.length;
  script.push(200); const skipped = await mon.runOnce(); script.length = 0;
  ok(skipped.skipped && checks.length === before, "monitor: another instance holding the lock means this one skips (no double emails during a deploy)");
  lockFree = true;

  site.paused = true;
  await run(500, 500, 500);
  eq(mails.length, 2, "monitor: paused sites are not checked or alerted");
  site.paused = false; script.length = 0;

  // A failed send is recorded, and does not turn into a retry storm.
  const mails2 = [];
  const mon2 = U.createMonitor({ pool, sendMail: async (m) => { mails2.push(m); return false; }, getAlertTo: async () => ["a@b.c"],
    fetchImpl: async () => resp(script.shift()), log: { log() {}, error() {} } });
  for (const c of [500, 500, 500, 500]) { script.push(c); await mon2.runOnce(); }
  eq(mails2.length, 1, "monitor: a failed send is attempted once per transition, not every minute");
  ok(incidents[1] && incidents[1].down_ok === false, "monitor: ...and recorded as not sent");

  // No recipient (emails turned off) still records the incident.
  for (const c of [200]) { script.push(c); await mon2.runOnce(); }
  const mon3 = U.createMonitor({ pool, sendMail: async (m) => { mails2.push(m); return true; }, getAlertTo: async () => null,
    fetchImpl: async () => resp(script.shift()), log: { log() {}, error() {} } });
  const n = mails2.length, inc = incidents.length;
  for (const c of [500, 500]) { script.push(c); await mon3.runOnce(); }
  ok(mails2.length === n && incidents.length === inc + 1, "monitor: alerts off -> incident recorded, nothing sent");

  // ── Wiring in server.js and the page ────────────────────────────────
  for (const route of ["app.get('/api/uptime',", "app.post('/api/uptime/sites',", "app.patch('/api/uptime/sites/:id',", "app.delete('/api/uptime/sites/:id',", "app.post('/api/uptime/settings',"]) {
    const i = server.indexOf(route);
    ok(i >= 0 && /requireUptime/.test(server.slice(i, i + 80)), route + " exists and is behind requireUptime");
  }
  ok(/requireUptime[\s\S]{0,400}bridgeScope\(req\)/.test(server), "studio-limited dashboard staff cannot read every studio's uptime");
  ok(/key='seeded'/.test(server), "seed runs once, guarded by a marker rather than an empty table");
  ok(server.includes("'/api/known-features'"), "spawns are checked at /api/known-features, not the 6 MB root page");
  ok(/uptimeMonitor\.start\(\)/.test(server) && /UPTIME_MONITOR/.test(server), "monitor starts after initDB and can be switched off");
  ok(!/admin@kronara\.app/.test(fs.readFileSync(path.join(ROOT, "lib", "uptime.js"), "utf8")), "the alert address is data/config, not baked into the checker");
  {
    const blocks = html.match(/<script[^>]*>([\s\S]*?)<\/script>/g) || [];
    const bad = [];
    for (const b of blocks) { try { new Function(b.replace(/^<script[^>]*>/, "").replace(/<\/script>$/, "")); } catch (e) { bad.push(e.message); } }
    ok(bad.length === 0, "every inline script still parses", bad.join(" | "));
  }
  ok(/'Tenants', 'Uptime', 'Alerts'/.test(html) && /id="pageUptime"/.test(html) && /data-page="uptime"/.test(html), "page is in the nav and in showPage's page list");

  console.log(fails ? `\n${fails} failing` : "\nall uptime checks pass");
  process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
