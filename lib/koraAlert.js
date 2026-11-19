// Kora health alerts (Jud, 2026-11-19): once a day at 5pm the dashboard asks each
// studio for its Kora health (thumbs-down answers this week, help topics whose
// code has changed since they were written) and pushes to admins' phones when
// it gets worse. Before this the only sign was a small "📚 N topics stale"
// line on the Kora Health page, which is easy to miss.
//
// decide() is pure so it can be tested without a database or network:
//   prev: { staleCount, badCount, lastStaleAlertAt } | null (never checked)
//   cur:  { staleCount, badCount }
// Push when out-of-date topics go up, when there are new thumbs-down answers,
// and, while topics stay out of date, a reminder once a week.
'use strict';

const REMIND_MS = 7 * 24 * 3600 * 1000;
const RUN_HOUR = 17, RUN_TZ = "America/Edmonton";   // daily, 5pm Jud's time
// How long until the next RUN_HOUR:00 in RUN_TZ (DST-safe: read the wall clock).
function msUntilNextRun(now, hour, tz) {
  now = now || Date.now(); hour = hour == null ? RUN_HOUR : hour; tz = tz || RUN_TZ;
  const p = new Intl.DateTimeFormat("en-CA", { timeZone: tz, hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })
    .formatToParts(new Date(now)).reduce((a, x) => { a[x.type] = parseInt(x.value, 10); return a; }, {});
  const h = p.hour === 24 ? 0 : p.hour, sinceMidnight = (h * 3600 + p.minute * 60 + p.second) * 1000;
  let wait = hour * 3600000 - sinceMidnight;
  if (wait <= 60000) wait += 24 * 3600000;
  return wait;
}
const LOCK_KEY = 74_210_602;   // one checker at a time (uptime uses ...601)

function decide(prev, cur, now, name) {
  now = now || Date.now();
  const stale = Math.max(0, cur.staleCount | 0), bad = Math.max(0, cur.badCount | 0);
  const pStale = prev ? Math.max(0, prev.staleCount | 0) : 0, pBad = prev ? Math.max(0, prev.badCount | 0) : 0;
  const lastStale = prev && prev.lastStaleAlertAt ? new Date(prev.lastStaleAlertAt).getTime() : 0;
  const out = [];
  let staleAlerted = false;
  if (stale > pStale || (stale > 0 && lastStale && now - lastStale >= REMIND_MS)) {
    out.push({ kind: 'stale', title: 'Kora: ' + stale + ' help topic' + (stale === 1 ? '' : 's') + ' out of date',
      body: (name || 'A studio') + ': the code behind ' + (stale === 1 ? 'this topic' : 'these topics') + ' changed since ' + (stale === 1 ? 'it was' : 'they were') + ' written, so Kora may answer wrongly. Rewrite them (kb:regen).' });
    staleAlerted = true;
  }
  if (bad > pBad) {
    const n = bad - pBad;
    out.push({ kind: 'bad', title: 'Kora: ' + n + ' new thumbs-down answer' + (n === 1 ? '' : 's'),
      body: (name || 'A studio') + ': ' + bad + ' this week. Open Kora Health to read the chat' + (n === 1 ? '' : 's') + '.' });
  }
  return { alerts: out, staleAlerted };
}

module.exports = { decide, msUntilNextRun, REMIND_MS, RUN_HOUR, RUN_TZ, LOCK_KEY };
