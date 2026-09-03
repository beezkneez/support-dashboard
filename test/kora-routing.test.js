// The central-support routing, and the inline script this dashboard is built on.
//
// The inline-script check earns its place: public/index.html is one big
// <script>, and a template literal that gets split across lines while editing
// takes the whole dashboard down with a syntax error that nothing else catches
// until you open it in a browser. That happened twice while writing this file.
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const server = fs.readFileSync(path.join(ROOT, "server.js"), "utf8");
const html = fs.readFileSync(path.join(ROOT, "public", "index.html"), "utf8");
const sw   = fs.readFileSync(path.join(ROOT, "public", "sw.js"), "utf8");

let fails = 0;
const ok = (c, label, detail) => {
  if (!c) { fails++; console.log("  FAIL  " + label + (detail ? "\n        " + detail : "")); }
  else console.log("  ok    " + label);
};

// ── The page has to actually parse ──────────────────────────────────
{
  const blocks = html.match(/<script[^>]*>([\s\S]*?)<\/script>/g) || [];
  ok(blocks.length > 0, "found the inline script");
  let bad = [];
  for (const b of blocks) {
    const src = b.replace(/^<script[^>]*>/, "").replace(/<\/script>$/, "");
    try { new Function(src); } catch (e) { bad.push(e.message); }
  }
  ok(bad.length === 0, "every inline script parses", bad.join(" | "));
}

// ── Intake carries enough to triage without asking ──────────────────
{
  const hook = server.slice(server.indexOf("app.post('/api/hooks/ticket'"),
                            server.indexOf("app.post('/api/hooks/ticket/:id/reply'"));
  ok(/aiSessionId/.test(hook) && /imageUrl/.test(hook) && /pageContext/.test(hook),
     "the ticket hook accepts the chat, the screenshot and the page context");
  ok(/INSERT INTO tickets[\s\S]{0,400}ai_session_id, image_url, page_context/.test(hook),
     "and stores all three");

  ok(/ADD COLUMN IF NOT EXISTS forwarded_at/.test(server),
     "tickets can record that they were passed down to a studio");
}

// ── Forwarding ──────────────────────────────────────────────────────
{
  const fwd = server.slice(server.indexOf("app.post('/api/tickets/:id/forward'"),
                           server.indexOf("app.post('/api/tickets/:id/note'"));
  ok(fwd.length > 200, "found the forward endpoint");
  ok(/requireAdmin/.test(fwd), "only an admin here can forward");
  ok(/hooks\/ticketForward/.test(fwd), "it calls the spawn the ticket came from");
  ok(/callback_url \|\| t\.app_callback_url/.test(fwd),
     "using that spawn's own callback, not a single shared one");

  // Forwarding twice would notify the studio twice for one ticket.
  ok(/if \(t\.forwarded_at\)/.test(fwd), "forwarding twice is a no-op");

  // The dangerous failure is marking it forwarded when it never arrived: the
  // ticket then shows as somebody else's problem and is nobody's.
  const markIdx = fwd.indexOf("SET forwarded_at = NOW()");
  const guardIdx = fwd.indexOf("The spawn refused the forward");
  ok(guardIdx > 0 && guardIdx < markIdx,
     "it is only marked forwarded after the spawn confirms it took it");
  ok(/no callback URL registered/.test(fwd),
     "and a spawn with no callback is refused rather than silently marked");
}

// ── The UI ──────────────────────────────────────────────────────────
{
  ok(/function koraContextPanel\(/.test(html), "the ticket view renders the context panel");
  ok(/recentErrors/.test(html), "including the errors their browser logged");
  ok(/function forwardTicket\(/.test(html), "and offers the forward action");
  ok(/forwarded_at\s*\n?\s*\?/.test(html) || /t\.forwarded_at/.test(html),
     "which becomes a badge once it has been passed down");

  // A spawn without Bunny storage keeps the raw data URL; that is fine in an
  // <img> but must never be treated as a link.
  const panel = html.slice(html.indexOf("function koraContextPanel("), html.indexOf("async function forwardTicket("));
  ok(/\^https\?:/.test(panel) || /https\?:\\\/\\\//.test(panel),
     "the screenshot source is scheme-checked before it is rendered");
}

// -- The list reads like an inbox -----------------------------------
{
  // It used to group every 'open' ticket above every 'in_progress' one, so the
  // ticket you had just replied to sank below older untouched ones: you answer
  // something and it moves away from you.
  const list = server.slice(server.indexOf("app.get('/api/tickets'"), server.indexOf("app.get('/api/tickets/:id'"));
  ok(/ORDER BY t\.updated_at DESC/.test(list), "most recent activity first");
  ok(!/CASE t\.status WHEN 'open' THEN 0/.test(list), "no longer grouped by status ahead of recency");

  // "Open" and "In Progress" do not say whose turn it is, and a ticket goes
  // back to 'open' when the user replies — so open really means "waiting on
  // you".
  ok(/>Needs you</.test(html) && />Waiting on them</.test(html),
     "the tiles say whose turn it is rather than a status name");
  ok(/function showTicketsFiltered\(/.test(html), "and clicking one opens that slice of the list");
  ok(/stat-clickable/.test(html), "with a visible affordance that they are clickable");
}

// -- The default view has to include what you have replied to ---------
{
  // Replying flips a ticket open -> in_progress. With the filter defaulting to
  // "open", answering one made it disappear — survivable when this was a second
  // copy of the tickets, not now that it is the only place they live.
  const list = server.slice(server.indexOf("app.get('/api/tickets'"), server.indexOf("app.get('/api/tickets/:id'"));
  ok(/status === 'active'/.test(list), "there is an 'active' status filter");
  ok(/t\.status IN \('open','in_progress'\)/.test(list),
     "which means open OR replied-to-and-waiting, not just untouched");

  ok(/<option value="active" selected>/.test(html), "and it is what the page opens on");
  ok(!/<option value="open" selected>/.test(html), "the old open-only default is gone");
  ok(/tickets\?status=active/.test(html), "the home list uses it too");
}

// ── Push ────────────────────────────────────────────────────────────
{
  // Support is answered only here now, so a missed notification is a support
  // request nobody has seen. Email alone loses to a busy inbox.
  ok(/require\('web-push'\)/.test(server), "web-push is wired in");
  ok(/CREATE TABLE IF NOT EXISTS push_subscriptions/.test(server), "subscriptions are stored per device");
  ok(/endpoint   TEXT NOT NULL UNIQUE/.test(server),
     "endpoint is unique, so re-subscribing a browser updates rather than doubles it");
  ok(/ON CONFLICT \(endpoint\) DO UPDATE/.test(server), "and the insert relies on that");

  const push = server.slice(server.indexOf("async function pushToAdmins("), server.indexOf("app.get('/api/push/key'"));
  // A subscription outlives the browser profile that made it. Without pruning,
  // the table fills with endpoints that can never deliver again.
  ok(/404 \|\| code === 410 \|\| code === 403/.test(push), "dead subscriptions are pruned on 404/410/403");
  ok(/DELETE FROM push_subscriptions WHERE id/.test(push), "actually deleted, not just logged");

  // Every notified event needs a preference column, or it is unmutable.
  ok(/push_new_ticket/.test(server) && /push_user_reply/.test(server), "each push category has a preference");
  ok(/email_new_ticket/.test(server), "and email is a separate switch from push");
  ok(/pushToAdmins\(/.test(server.slice(server.indexOf("app.post('/api/hooks/ticket'"),
                                        server.indexOf("app.post('/api/hooks/ticket/:id/reply'"))),
     "a new ticket pushes");

  // Only an admin's own devices, or one admin could unenrol another's phone.
  const unsub = server.slice(server.indexOf("app.post('/api/push/unsubscribe'"), server.indexOf("app.get('/api/push/devices'"));
  ok(/admin_id=\$2/.test(unsub), "you can only remove your own devices");

  ok(/addEventListener\('push'/.test(sw), "the service worker receives pushes");
  ok(/notificationclick/.test(sw), "and clicking one opens the dashboard");
  ok(/clients\.matchAll/.test(sw), "focusing an open tab rather than opening a second");

  // A denied permission is sticky, so the UI has to say where to undo it.
  ok(/site settings/i.test(html), "a blocked permission explains how to unblock it");
}

console.log(fails ? "\n" + fails + " FAILED" : "\nall passed");
process.exit(fails ? 1 : 0);
