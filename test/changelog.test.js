// Changelog ("What's New"): one central list per app, broadcast to every
// spawn on Announce. Unlike feature requests (one spawn, one callback) this
// is one entry, many spawns -- see aradia-time's tests/changelog.test.js for
// the matching pins on the receiving side.
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

// ── Spawn-facing reads are scoped per app, additive for admins ──────────
{
  const i = server.indexOf("app.post('/api/hooks/getChangelogEntries'");
  ok(i >= 0, "found the spawn-facing getChangelogEntries hook");
  const hook = server.slice(i, server.indexOf("app.post('/api/hooks/markChangelogsRead'"));
  ok(/requireApiKey/.test(server.slice(i, i + 60)), "getChangelogEntries hook is behind requireApiKey");
  ok(/ce\.app_id=\$1/.test(hook), "scoped to the calling app, not every app's entries");
  ok(/ce\.published=TRUE/.test(hook), "only published entries reach a spawn -- drafts stay private to the author");
  ok(/seeAdmin/.test(hook) && /audience='admin'/.test(hook),
     "seeAdmin additively includes audience='admin' rows -- staff never get them, admins/mods get both");
}

// ── Broadcast on Announce: one entry, every spawn, best-effort ──────────
{
  const i = server.indexOf("app.post('/api/changelog/:id/announce'");
  ok(i >= 0, "found the announce endpoint");
  const j = server.indexOf("app.delete('/api/changelog/:id'", i);
  const hook = server.slice(i, j > i ? j : i + 3000);
  ok(/requireAdmin/.test(server.slice(i, i + 60)), "announce requires an authenticated admin (this dashboard's own login)");
  ok(/FROM tenants WHERE app_id=\$1/.test(hook), "looks up every spawn registered for the entry's app, not a single callback_url");
  ok(/changelogAnnounce/.test(hook), "posts to each spawn's /api/hooks/changelogAnnounce");
  ok(/Promise\.allSettled/.test(hook), "one spawn failing to receive it does not block the others");
  ok(/announced_at=NOW\(\)/.test(hook), "marks the entry announced regardless of individual spawn delivery outcomes");
  ["entryId", "title", "body", "audience", "category"].forEach(f =>
    ok(new RegExp("\\b" + f + "\\b").test(hook), "broadcast payload includes " + f));
}

// ── Reads are scoped to (app, email), not spawn -- same person, any studio ──
{
  const i = server.indexOf("CREATE TABLE IF NOT EXISTS changelog_reads");
  ok(i >= 0, "found the changelog_reads table");
  const ddl = server.slice(i, i + 500);
  ok(/PRIMARY KEY \(app_id, user_email, entry_id\)/.test(ddl),
     "primary key is (app, email, entry) -- read state follows the person, not which studio they asked from");
}

console.log(fails ? "\n" + fails + " failure(s)" : "\nall passed");
process.exit(fails ? 1 : 0);
