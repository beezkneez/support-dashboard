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
