// Dev Tracker Progress Tree: a fixed, hierarchical taxonomy of every section
// of an app (aradia-time to start), with Dev Tracker cards tagged to a node
// via section_id so a % complete bar rolls up per branch automatically.
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

// ── Schema ──────────────────────────────────────────────────────────
ok(/CREATE TABLE IF NOT EXISTS tree_sections/.test(server), "tree_sections table exists");
ok(/parent_id\s+TEXT REFERENCES tree_sections\(id\)/.test(server), "tree_sections self-references via parent_id");
ok(/UNIQUE \(app_id, slug\)/.test(server), "tree_sections has an idempotent-seed unique key on (app_id, slug)");
ok(/ALTER TABLE dev_tracker ADD COLUMN IF NOT EXISTS section_id TEXT REFERENCES tree_sections\(id\)/.test(server), "dev_tracker gained a nullable section_id column");
ok(/ALTER TABLE dev_tracker ADD COLUMN IF NOT EXISTS seed_key/.test(server), "dev_tracker gained a seed_key column for idempotent seeding");
ok(/CREATE UNIQUE INDEX IF NOT EXISTS idx_dev_tracker_seed_key ON dev_tracker \(seed_key\) WHERE seed_key IS NOT NULL/.test(server), "seed_key uniqueness is a partial index, so normal (NULL) cards are never constrained");

// ── Seed data ───────────────────────────────────────────────────────
ok(/const DEV_TREE_SEED = \[/.test(server), "found the tree taxonomy seed array");
ok(/const DEV_TREE_CARD_SEED = \[/.test(server), "found the starter Dev Tracker card seed array");
ok(/slug: 'admin'/.test(server) && /slug: 'booking_staff'/.test(server) && /slug: 'public_booking'/.test(server), "seed covers Admin, Booking (staff-side), and the Public Booking Site as distinct branches");
ok(/slug: 'party_calendar'/.test(server) && /slug: 'tsps'/.test(server) && /slug: 'requests_subsystem'/.test(server), "seed gives Party Calendar, TSPS, and Requests their own top-level branches");
ok(/slug: 'launch_readiness'/.test(server), "seed includes a Public Launch Readiness branch");
ok(/tracked under the TSPS branch/.test(server), "the Admin > Scheduling cross-reference leaves say where their work is actually tracked");

// ── Endpoints ───────────────────────────────────────────────────────
{
  const i = server.indexOf("app.get('/api/tree-sections'");
  ok(i >= 0, "found GET /api/tree-sections");
  ok(i >= 0 && /requireAdmin/.test(server.slice(i, i + 60)), "tree-sections endpoint requires an authenticated admin");
}
{
  const i = server.indexOf("app.get('/api/dev-tracker-tree'");
  ok(i >= 0, "found GET /api/dev-tracker-tree");
  ok(i >= 0 && /requireAdmin/.test(server.slice(i, i + 60)), "dev-tracker-tree endpoint requires an authenticated admin");
  const body = i >= 0 ? server.slice(i, server.indexOf("app.get('/api/", i + 40)) : "";
  ok(/percent:\s*total === 0 \? null/.test(body), "a node with zero items rolls up to null percent, not 0 or 100");
}
{
  const i = server.indexOf("app.post('/api/dev-tracker'");
  const body = i >= 0 ? server.slice(i, server.indexOf("app.delete('/api/dev-tracker", i)) : "";
  ok(/item\.sectionId/.test(body), "POST /api/dev-tracker reads sectionId from the body");
}

// ── UI wiring ───────────────────────────────────────────────────────
ok(/data-page="devtree"/.test(html), "sidebar has the Progress Tree nav entry");
ok(/id="pageDevTree"/.test(html), "pageDevTree container exists");
ok(/'DevTree'/.test(html), "showPage()'s hide-list includes DevTree");
ok(/page === 'devtree'/.test(html) && /loadDevTree\(\)/.test(html), "showPage('devtree') calls loadDevTree()");
ok(/id="dtNewSection"/.test(html), "the 'Add a card' form has a section picker");
ok(/function renderTreeNode/.test(html), "found the tree node renderer");
ok(/function toggleTreeNode/.test(html), "found the expand/collapse toggle");
ok(/devTreeExpanded/.test(html), "expand/collapse state persists (localStorage key)");

console.log(fails ? "\n" + fails + " failure(s)" : "\nall passed");
process.exit(fails ? 1 : 0);
