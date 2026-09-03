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

console.log(fails ? "\n" + fails + " FAILED" : "\nall passed");
process.exit(fails ? 1 : 0);
