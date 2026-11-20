// Kora health alerts (2026-11-19): when they fire, and that the page,
// badge and push setting are wired up.
'use strict';
const fs = require('fs');
const path = require('path');
const { decide, REMIND_MS } = require('../lib/koraAlert');
let fails = 0, n = 0;
const ok = (c, m) => { n++; if (!c) { fails++; console.log('  FAIL  ' + m); } };
const now = Date.parse('2026-11-19T20:00:00Z');

let d = decide(null, { staleCount: 20, badCount: 0 }, now, 'Aradia');
ok(d.alerts.length === 1 && d.alerts[0].kind === 'stale' && /20 help topics/.test(d.alerts[0].title) && d.staleAlerted, 'first reading with stale topics alerts');
d = decide({ staleCount: 20, badCount: 0, lastStaleAlertAt: new Date(now - 3600e3) }, { staleCount: 20, badCount: 0 }, now);
ok(d.alerts.length === 0 && !d.staleAlerted, 'same count an hour later: quiet');
d = decide({ staleCount: 20, badCount: 0, lastStaleAlertAt: new Date(now - REMIND_MS) }, { staleCount: 20, badCount: 0 }, now);
ok(d.alerts.length === 1 && d.staleAlerted, 'still stale after a week: one reminder');
d = decide({ staleCount: 20, badCount: 0, lastStaleAlertAt: new Date(now - 3600e3) }, { staleCount: 22, badCount: 0 }, now);
ok(d.alerts.length === 1 && /22/.test(d.alerts[0].title), 'more topics go stale: alert');
d = decide({ staleCount: 20, badCount: 0, lastStaleAlertAt: new Date(now - 3600e3) }, { staleCount: 5, badCount: 0 }, now);
ok(d.alerts.length === 0, 'fewer stale topics (someone fixed some): quiet');
d = decide({ staleCount: 0, badCount: 1 }, { staleCount: 0, badCount: 3 }, now, 'Aradia');
ok(d.alerts.length === 1 && d.alerts[0].kind === 'bad' && /2 new thumbs-down answers/.test(d.alerts[0].title), 'new thumbs-down answers: alert with how many');
d = decide({ staleCount: 0, badCount: 3 }, { staleCount: 0, badCount: 2 }, now);
ok(d.alerts.length === 0, 'a thumbs-down ageing out of the week: quiet');
d = decide(null, { staleCount: 0, badCount: 0 }, now);
ok(d.alerts.length === 0, 'all good: quiet');

// Daily at 5pm Edmonton.
const { msUntilNextRun } = require('../lib/koraAlert');
const at = (iso) => Date.parse(iso);
ok(msUntilNextRun(at('2026-11-19T22:00:00Z')) === 60 * 60000, '4pm local (UTC-6): an hour to go');
ok(msUntilNextRun(at('2026-11-19T23:30:00Z')) === 23.5 * 3600000, '5:30pm: tomorrow at 5');
ok(msUntilNextRun(at('2026-11-19T06:00:00Z')) === 17 * 3600000, 'midnight: 17 hours');

const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8').replace(/\r\n/g, '\n');
const page = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8').replace(/\r\n/g, '\n');
ok(/kora: 'push_kora'/.test(server) && /kora: \['korahealth'\]/.test(server), 'pushes go only to people who can open Kora Health, and each can mute them');
ok(/'push_uptime', 'push_kora', 'email_new_ticket'/.test(server) && /COALESCE\(push_kora,TRUE\) AS push_kora/.test(server), 'the mute switch reads and saves');
ok(/koraAlert\.msUntilNextRun\(\)/.test(server) &&/pg_try_advisory_lock\(\$1\) AS ok', \[koraAlert\.LOCK_KEY\]/.test(server), 'daily at 5pm, one checker at a time');
ok(/if \(req\.query\.summary\)/.test(server), 'the badge reads the stored reading (same route the control plane already allows)');
ok(/id="koraBadge"/.test(page) && /function refreshKoraBadge_\(\)/.test(page) && /row\('push_kora'/.test(page), 'menu badge and push setting on the page');
ok(/help topic' \+ \(stale\.length === 1 \? '' : 's'\) \+ ' out of date'/.test(page) && /<b>Out of date:<\/b>/.test(page), 'the page lists the out-of-date topics and what to do');

console.log('kora-alert: ' + (fails ? fails + ' FAILED of ' + n : 'ok (' + n + ' checks)'));
if (fails) process.exit(1);
