// Feature requests: intake from any spawn, review here, move onto the
// working backlog (dev_tracker), tell the spawn back. Two hooks straddle the
// aradia-time repo with no compiler between them -- see that repo's
// tests/feature-requests.test.js for the matching pins on its side. Treat a
// mismatch here as the thing to fix on whichever side is wrong, not proof
// this file is wrong.
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const server = fs.readFileSync(path.join(ROOT, "server.js"), "utf8");
const html = fs.readFileSync(path.join(ROOT, "public", "index.html"), "utf8");

let fails = 0;
const ok = (c, label, detail) => {
  if (!c) { fails++; console.log("  FAIL  " + label + (detail ? "\n        " + detail : "")); }
  else console.log("  ok    " + label);
};

// ── The page still parses ─────────────────────────────────────────────
{
  const blocks = html.match(/<script[^>]*>([\s\S]*?)<\/script>/g) || [];
  let bad = [];
  for (const b of blocks) {
    const src = b.replace(/^<script[^>]*>/, "").replace(/<\/script>$/, "");
    try { new Function(src); } catch (e) { bad.push(e.message); }
  }
  ok(bad.length === 0, "every inline script still parses", bad.join(" | "));
}

// ── Inbound intake: matches what a spawn's /submitFeatureRequest sends ───
{
  const i = server.indexOf("app.post('/api/hooks/featureRequest'");
  ok(i >= 0, "found the featureRequest intake hook");
  const hook = i >= 0 ? server.slice(i, server.indexOf("app.post('/api/hooks/ticket/:id/reply'")) : "";
  ok(/requireApiKey/.test(server.slice(i, i + 60)), "intake hook is behind requireApiKey");
  ["externalId", "fromEmail", "fromName", "title", "description", "spawn", "spawnName", "callbackUrl"].forEach(f =>
    ok(new RegExp("\\b" + f + "\\b").test(hook), "reads " + f + " from the spawn's payload"));
  ok(/INSERT INTO feature_requests/.test(hook), "stores it in feature_requests");
}

// ── Move action: creates the dev_tracker card and calls the spawn back ───
{
  const i = server.indexOf("app.post('/api/requests/:id/move'");
  ok(i >= 0, "found the move-to-dev-tracker endpoint");
  const j = server.indexOf("app.get('/api/dev-tracker'", i);
  const hook = i >= 0 ? server.slice(i, j > i ? j : i + 3000) : "";
  ok(/requireAdmin/.test(server.slice(i, i + 60)), "move endpoint requires an authenticated admin");
  ok(/INSERT INTO dev_tracker/.test(hook), "creates a dev_tracker card");
  ok(/status='moved'/.test(hook), "marks the intake row moved");
  ok(/featureRequestUpdate/.test(hook), "calls the spawn back at /api/hooks/featureRequestUpdate");
  ["externalId", "status", "movedAt", "timelineNote"].forEach(f =>
    ok(new RegExp("\\b" + f + "\\b").test(hook), "callback payload includes " + f));
  ok(/fr\.callback_url/.test(hook) && /fr\.app_api_key/.test(hook),
     "the callback uses the REQUEST's own callback_url + key (per-row, like the ticket reply callback) -- not a hardcoded spawn");
  ok(/timeline_note=\$5/.test(hook) || /SET status='moved'[^`]*timeline_note=/.test(hook),
     "the timeline typed into the move form is persisted on the intake row, not left living only in the request body -- " +
     "a retry (or an audit later) would otherwise have nothing real to resend and would send an empty one");
}

// ── The callback's outcome is real, not assumed ───────────────────────
// A production move reported "the studio has been told" while the callback
// was still fire-and-forget and unchecked -- the fetch never actually
// reached the spawn (or the response was never inspected), the intake row
// showed 'moved' regardless, and there was no way to tell or retry. These
// pin the fix: the callback is awaited, its HTTP status and body are
// checked, and the real outcome -- not merely "we had enough to try with"
// -- is what gets persisted and returned.
{
  const fn = server.slice(server.indexOf("async function notifySpawn"), server.indexOf("async function notifySpawn") + 2000);
  ok(/await fetch\(/.test(fn), "the callback to the spawn is awaited, not fire-and-forget");
  ok(/AbortSignal\.timeout\(/.test(fn), "the awaited callback has a timeout, so a hung spawn can't hang the admin action");
  ok(/if \(!resp\.ok\)/.test(fn), "checks the HTTP status, not just whether fetch() threw");
  ok(/body\.ok !== true/.test(fn), "checks the response BODY says ok, not only the HTTP status");
  ok(/return \{ notified: true, notifyError: null \}/.test(fn), "returns the real outcome for the caller to persist");

  const move = server.slice(server.indexOf("app.post('/api/requests/:id/move'"), server.indexOf("app.get('/api/dev-tracker'"));
  ok(/await notifySpawn\(/.test(move), "the move handler awaits the real outcome before responding");
  ok(/UPDATE feature_requests SET notified=\$1, notify_error=\$2/.test(move),
     "persists the real outcome, so it survives past this one response and can be shown/retried later");
  ok(/notified: notified,|notified,/.test(move) && !/notified: willCallback/.test(server),
     "the client-facing 'notified' field is the awaited result, not the old precondition-only willCallback");
}

// ── Retrying a failed notification ────────────────────────────────────
{
  const i = server.indexOf("app.post('/api/requests/:id/retry-notify'");
  ok(i >= 0, "found the retry-notify endpoint");
  ok(/requireAdmin/.test(server.slice(i, i + 60)), "retry-notify requires an authenticated admin");
  const hook = server.slice(i, server.indexOf("async function notifySpawn"));
  ok(/status !== 'moved'/.test(hook), "refuses to retry a request that was never actually moved");
  ok(/await notifySpawn\(/.test(hook), "retry reuses the same real-outcome check as the original move");
}

// ── An already-moved request can't be moved twice ─────────────────────
{
  const i = server.indexOf("app.post('/api/requests/:id/move'");
  const j = server.indexOf("app.get('/api/dev-tracker'", i);
  const hook = server.slice(i, j);
  ok(/status === 'moved'/.test(hook), "refuses to re-move a request that already has a dev_tracker card");
}

console.log(fails ? "\n" + fails + " failure(s)" : "\nall passed");
process.exit(fails ? 1 : 0);
