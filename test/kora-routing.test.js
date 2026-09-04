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
  // Anchored on the structure, not the wording — the message has been reworded
  // once already and the guarantee is about ordering, not prose.
  const markIdx = fwd.indexOf("SET forwarded_at = NOW()");
  const guardIdx = fwd.search(/if \(!r\.ok\) \{[\s\S]{0,200}return res\.json\(\{ ok: false/);
  ok(guardIdx > 0 && guardIdx < markIdx,
     "it is only marked forwarded after the spawn confirms it took it");
  ok(/no callback URL registered/.test(fwd),
     "and a spawn with no callback is refused rather than silently marked");

  // A spawn mid-restart serves its host's HTML error page. Calling .json() on
  // that surfaced as "Unexpected token '<'", which tells the reader nothing and
  // looks identical to a genuine refusal.
  ok(/content-type/.test(fwd) && /application\/json/.test(fwd),
     "the reply is checked for JSON before it is parsed");
  ok(/probably restarting/.test(fwd),
     "a gateway page is reported as a restart, with the HTTP status");
  // A 404 and a 502 both arrive as HTML but mean opposite things: one spawn is
  // on an older build and will never accept this until it is updated, the other
  // is coming back in a minute. Telling someone to retry the first is telling
  // them to wait for something that will not happen.
  ok(/httpStatus === 404/.test(fwd), "a 404 is distinguished from a restart");
  ok(/older build/.test(fwd), "and reported as the spawn needing an update");
  ok(!/\.then\(x => x\.json\(\)\)/.test(fwd), "no blind .json() parse");
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

// ── Requests a studio was sent directly ─────────────────────────────
{
  // Forwarding every studio question through one person does not survive a
  // dozen studios, so people can now address one to their studio themselves.
  // It still arrives here — that is what keeps "nothing goes unseen" true —
  // but it is not this dashboard's work.
  ok(/ADD COLUMN IF NOT EXISTS destination TEXT DEFAULT 'kronara'/.test(server),
     "a ticket records which way it came in");
  // An older spawn sends no destination. Reading that as ours is the safe
  // default; the other way files a studio's traffic as already handled.
  const hook = server.slice(server.indexOf("app.post('/api/hooks/ticket'"),
                            server.indexOf("app.post('/api/hooks/ticket/:id/reply'"));
  ok(/destination === 'studio' \? 'studio' : 'kronara'/.test(hook),
     "…defaulting to ours when a spawn does not say");
  ok(/INSERT INTO tickets[\s\S]{0,400}destination/.test(hook), "and stores it");

  // Pushing every studio's own business to one phone is the same bottleneck
  // rebuilt as a notification stream.
  const silentIdx = hook.indexOf("if (dest === 'studio')");
  const pushIdx   = hook.indexOf("pushToAdmins(");
  ok(silentIdx > 0 && silentIdx < pushIdx,
     "a studio-bound ticket is recorded silently — no push, no email");
}

// ── Whose turn it is, as a filter ───────────────────────────────────
{
  const list = server.slice(server.indexOf("app.get('/api/tickets'"), server.indexOf("app.get('/api/tickets/:id'"));
  ok(/queue === 'mine'/.test(list) && /queue === 'studio'/.test(list),
     "the list can be sliced by whose problem it is");
  ok(/t\.forwarded_at IS NOT NULL OR t\.destination='studio'/.test(list),
     "'with a studio' merges passed-down and sent-direct — one section, since whose turn it is matters more than how it got there");
  // Chasing a stalled ticket is yours even though answering it is not.
  ok(/t\.destination IS DISTINCT FROM 'studio' OR t\.stale_at IS NOT NULL/.test(list),
     "…and one that has gone quiet joins your own queue");

  ok(/queue=mine/.test(html) && /queue=studio/.test(html),
     "the home page asks for both and shows them separately");
  ok(/>With a studio</.test(html), "with a section that says what it is");
  ok(/id="filterQueue"/.test(html), "and the ticket list has the same filter");
}

// ── Silence is the thing that interrupts you ────────────────────────
{
  const stale = server.slice(server.indexOf("app.post('/api/hooks/ticketStale'"),
                             server.indexOf("app.post('/api/hooks/registerTenant'"));
  ok(stale.length > 400, "found the stale hook");
  ok(/requireApiKey/.test(stale), "only a spawn can report one");
  ok(/if \(t\.stale_at \|\| t\.destination !== 'studio'\)/.test(stale),
     "flagging twice, or flagging one already pulled back, is a no-op");
  ok(/pushToAdmins\(/.test(stale) && /sendMail\(/.test(stale),
     "this one does interrupt — somebody has been waiting with nobody on it");
  // The ticket is not seized. Surfacing it is the whole intervention.
  ok(!/destination='kronara'/.test(stale), "…without taking the ticket off the studio");

  // Pass-back has to undo BOTH routes in, or a directly-addressed ticket comes
  // back and stays filed as the studio's at the same time.
  const pbk = server.slice(server.indexOf("app.post('/api/hooks/ticketPassBack'"),
                           server.indexOf("app.post('/api/hooks/ticketStale'"));
  ok(pbk.length > 400, "found the pass-back hook");
  ok(/destination='kronara'/.test(pbk), "handing one back files it as ours again");
  ok(/stale_at=NULL/.test(pbk), "and clears the quiet flag, since it is nobody's to ignore now");
}

console.log(fails ? "\n" + fails + " FAILED" : "\nall passed");
process.exit(fails ? 1 : 0);
