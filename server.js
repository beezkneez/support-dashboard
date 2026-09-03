require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();

// Health check — must be first, before any middleware
app.get('/health', (req, res) => res.send('ok'));

app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Request logging
app.use((req, res, next) => {
  console.log(`[req] ${req.method} ${req.url}`);
  next();
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ── Resend ──────────────────────────────────────────────────────────
let Resend;
try { Resend = require('resend').Resend; } catch(e) {}

function getResend() {
  if (!Resend || !process.env.RESEND_API_KEY) return null;
  return new Resend(process.env.RESEND_API_KEY);
}

async function sendMail({ to, subject, html, replyTo }) {
  const resend = getResend();
  if (!resend) { console.log('[email] Resend not configured, skipping'); return; }
  try {
    await resend.emails.send({
      from: process.env.RESEND_FROM || 'Support <support@example.com>',
      to: Array.isArray(to) ? to : [to],
      subject,
      html,
      replyTo
    });
    console.log(`[email] Sent to ${to}: ${subject}`);
  } catch(e) {
    console.error('[email] Failed:', e.message);
  }
}

// ── Database Init ───────────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id         SERIAL PRIMARY KEY,
        email      TEXT NOT NULL UNIQUE,
        password   TEXT NOT NULL,
        name       TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id         TEXT PRIMARY KEY,
        admin_id   INTEGER REFERENCES admin_users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '7 days')
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS apps (
        id         SERIAL PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,
        slug       TEXT NOT NULL UNIQUE,
        api_key    TEXT NOT NULL UNIQUE,
        color      TEXT DEFAULT '#6366f1',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tickets (
        id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        app_id      INTEGER REFERENCES apps(id) ON DELETE SET NULL,
        external_id TEXT,
        tenant_id   INTEGER,
        from_email  TEXT NOT NULL,
        from_name   TEXT,
        type        TEXT DEFAULT 'message',
        subject     TEXT,
        status      TEXT DEFAULT 'open',
        priority    TEXT DEFAULT 'normal',
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        updated_at  TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ticket_messages (
        id           SERIAL PRIMARY KEY,
        ticket_id    TEXT REFERENCES tickets(id) ON DELETE CASCADE,
        sender_type  TEXT NOT NULL,
        sender_name  TEXT,
        sender_email TEXT,
        body         TEXT NOT NULL,
        source       TEXT DEFAULT 'app',
        created_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ticket_notes (
        id         SERIAL PRIMARY KEY,
        ticket_id  TEXT REFERENCES tickets(id) ON DELETE CASCADE,
        admin_id   INTEGER REFERENCES admin_users(id),
        body       TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tenants (
        id                    SERIAL PRIMARY KEY,
        app_id                INTEGER REFERENCES apps(id) ON DELETE SET NULL,
        name                  TEXT NOT NULL,
        slug                  TEXT,
        owner_email           TEXT,
        plan_name             TEXT DEFAULT 'starter',
        stripe_customer_id    TEXT,
        stripe_subscription_id TEXT,
        plan_price            INTEGER DEFAULT 0,
        plan_interval         TEXT DEFAULT 'month',
        subscription_status   TEXT DEFAULT 'active',
        current_period_end    TIMESTAMPTZ,
        card_brand            TEXT,
        card_last4            TEXT,
        notes                 TEXT,
        created_at            TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // ── Kronara app directory ────────────────────────────────────────────
    // The Kronara mobile app is ONE binary serving every spawn: you open it,
    // find your studio, and it points its WebView at that studio's deployment.
    // For a newly spawned studio to appear WITHOUT an App Store release, the
    // studio list has to be served from here.
    //
    // These columns extend `tenants` rather than living in their own table:
    // it is the same real-world entity, and a second table would mean two
    // answers to "which studios exist". A row is created by the billing/admin
    // flow OR by a spawn announcing itself — whichever happens first — and the
    // two are matched on slug.
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS base_url TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS member_url TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_url TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS brand_color TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS member_name TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS build TEXT`).catch(()=>{});
    // Operator kill switch — hide a studio from the app without touching the
    // spawn. Deliberately never written by the self-registration hook.
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS listed BOOLEAN DEFAULT TRUE`).catch(()=>{});
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ`).catch(()=>{});
    await client.query(`CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants (LOWER(slug))`).catch(()=>{});

    // Spawn tag (which studio a ticket came from) + per-app callback URL for reply-back.
    await client.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS spawn TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS spawn_name TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS callback_url TEXT`).catch(()=>{});
    // Kora. Every spawn now routes ALL support here rather than to its own
    // studio admin, so this has to carry enough for the whole triage: the chat
    // that produced the ticket, the screenshot, and where the person was.
    await client.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS ai_session_id TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS image_url TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS page_context JSONB DEFAULT '{}'::jsonb`).catch(()=>{});
    // Set when it has been handed down to the studio's own admin, which is the
    // only way a ticket becomes visible on a spawn at all now.
    await client.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS forwarded_at TIMESTAMPTZ`).catch(()=>{});
    await client.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS forwarded_by TEXT`).catch(()=>{});
    // Push, per device. Support is answered only here now, so “I did not see
    // it” is a real failure. endpoint is UNIQUE so re-subscribing the same
    // browser updates its row instead of doubling every notification.
    await client.query(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id         SERIAL PRIMARY KEY,
        admin_id   INTEGER REFERENCES admin_users(id) ON DELETE CASCADE,
        endpoint   TEXT NOT NULL UNIQUE,
        p256dh     TEXT NOT NULL,
        auth       TEXT NOT NULL,
        label      TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_ok    TIMESTAMPTZ
      )
    `).catch(()=>{});
    // Email and push are independent switches, defaulting on — an admin who
    // has never touched the settings should still be told about a ticket.
    await client.query(`ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS push_new_ticket BOOLEAN DEFAULT TRUE`).catch(()=>{});
    await client.query(`ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS push_user_reply BOOLEAN DEFAULT TRUE`).catch(()=>{});
    await client.query(`ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS email_new_ticket BOOLEAN DEFAULT TRUE`).catch(()=>{});
    await client.query(`ALTER TABLE apps ADD COLUMN IF NOT EXISTS callback_url TEXT`).catch(()=>{});
    // Auto-configure the Aradia Time reply-back URL (only if not already set).
    await client.query(
      `UPDATE apps SET callback_url=$1 WHERE slug='aradia-time' AND (callback_url IS NULL OR callback_url='')`,
      [process.env.ARADIA_CALLBACK_URL || 'https://aradiafitness.app']
    ).catch(()=>{});

    // Seed default admin if not exists
    if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
      const existing = await client.query('SELECT id FROM admin_users WHERE email=$1', [process.env.ADMIN_EMAIL]);
      if (existing.rows.length === 0) {
        const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
        await client.query('INSERT INTO admin_users (email, password, name) VALUES ($1,$2,$3)',
          [process.env.ADMIN_EMAIL, hash, 'Admin']);
        console.log('[init] Default admin created:', process.env.ADMIN_EMAIL);
      }
    }

    // Seed default apps if none exist
    const appsExist = await client.query('SELECT COUNT(*) as c FROM apps');
    if (parseInt(appsExist.rows[0].c) === 0) {
      const key1 = 'sk_' + uuidv4().replace(/-/g, '');
      const key2 = 'sk_' + uuidv4().replace(/-/g, '');
      await client.query(
        `INSERT INTO apps (name, slug, api_key, color) VALUES
         ('Aradia Time', 'aradia-time', $1, '#f59e0b'),
         ('Kronara Build', 'kronara-build', $2, '#6366f1')`,
        [key1, key2]
      );
      console.log('[init] Default apps created');
      console.log('[init] Aradia Time API key:', key1);
      console.log('[init] Kronara Build API key:', key2);
    }

    console.log('[init] Database ready');
  } finally {
    client.release();
  }
}

// ── Auth Middleware ──────────────────────────────────────────────────
async function requireAdmin(req, res, next) {
  const token = req.cookies?.session || req.headers['x-session'];
  if (!token) return res.status(401).json({ ok: false, reason: 'Not authenticated' });

  const result = await pool.query(
    `SELECT a.id, a.email, a.name FROM sessions s
     JOIN admin_users a ON a.id = s.admin_id
     WHERE s.id=$1 AND s.expires_at > NOW()`,
    [token]
  );
  if (result.rows.length === 0) return res.status(401).json({ ok: false, reason: 'Session expired' });
  req.admin = result.rows[0];
  next();
}

async function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ ok: false, reason: 'Missing API key' });

  const result = await pool.query('SELECT * FROM apps WHERE api_key=$1', [key]);
  if (result.rows.length === 0) return res.status(401).json({ ok: false, reason: 'Invalid API key' });
  req.app = result.rows[0];
  next();
}

// ── Auth Routes ─────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ ok: false, reason: 'Email and password required' });

    const result = await pool.query('SELECT * FROM admin_users WHERE email=$1', [email.toLowerCase().trim()]);
    if (result.rows.length === 0) return res.json({ ok: false, reason: 'Invalid credentials' });

    const admin = result.rows[0];
    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.json({ ok: false, reason: 'Invalid credentials' });

    const sessionId = uuidv4();
    await pool.query('INSERT INTO sessions (id, admin_id) VALUES ($1,$2)', [sessionId, admin.id]);

    res.cookie('session', sessionId, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ ok: true, admin: { id: admin.id, email: admin.email, name: admin.name } });
  } catch(e) {
    console.error(e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.cookies?.session;
  if (token) await pool.query('DELETE FROM sessions WHERE id=$1', [token]);
  res.clearCookie('session');
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAdmin, (req, res) => {
  res.json({ ok: true, admin: req.admin });
});

// ── App Webhook Routes (called by aradia-time / kronara-build) ──────
app.post('/api/hooks/ticket', requireApiKey, async (req, res) => {
  try {
    const { externalId, tenantId, fromEmail, fromName, type, subject, body, spawn, spawnName, callbackUrl,
            aiSessionId, imageUrl, pageContext } = req.body;
    if (!fromEmail || !body) return res.json({ ok: false, reason: 'fromEmail and body required' });

    const ticketId = uuidv4();
    await pool.query(
      `INSERT INTO tickets (id, app_id, external_id, tenant_id, from_email, from_name, type, subject, spawn, spawn_name, callback_url,
                            ai_session_id, image_url, page_context)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [ticketId, req.app.id, externalId || null, tenantId || null,
       fromEmail, fromName || null, type || 'message', subject || '(no subject)', spawn || null, spawnName || null, callbackUrl || null,
       aiSessionId || null, imageUrl || null, JSON.stringify(pageContext || {})]
    );

    await pool.query(
      `INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, sender_email, body, source)
       VALUES ($1,'user',$2,$3,$4,'app')`,
      [ticketId, fromName || fromEmail, fromEmail, body]
    );

    // Push first: it is the one that arrives while you are away from an inbox,
    // and it is what makes answering support only here safe — nothing gets
    // missed because nobody happened to be looking at their email.
    pushToAdmins(
      (type === 'bug' ? '🐛 Bug' : '💬 Support') + ' · ' + (spawnName || spawn || req.app.name),
      (fromName || fromEmail) + ': ' + (subject || body),
      '/', 'ticket'
    );

    // Notify admin via email
    const dashUrl = process.env.DASHBOARD_URL || 'http://localhost:4500';
    sendMail({
      to: process.env.ADMIN_EMAIL,
      subject: `[${req.app.name}] ${type === 'bug' ? '🐛 Bug' : '💬 Message'}: ${subject || '(no subject)'}`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:${req.app.color};color:#fff;padding:16px 20px;border-radius:8px 8px 0 0;">
            <strong>${req.app.name}</strong> — New ${type === 'bug' ? 'Bug Report' : 'Support Message'}
          </div>
          <div style="border:1px solid #e5e7eb;border-top:0;padding:20px;border-radius:0 0 8px 8px;">
            <p><strong>From:</strong> ${fromName || ''} &lt;${fromEmail}&gt;</p>
            <p><strong>Subject:</strong> ${subject || '(none)'}</p>
            <hr style="border:0;border-top:1px solid #e5e7eb;margin:16px 0;">
            <div style="white-space:pre-wrap;">${body}</div>
            <hr style="border:0;border-top:1px solid #e5e7eb;margin:16px 0;">
            <a href="${dashUrl}" style="display:inline-block;background:${req.app.color};color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;">
              View in Dashboard
            </a>
          </div>
        </div>
      `,
      replyTo: fromEmail
    });

    res.json({ ok: true, ticketId });
  } catch(e) {
    console.error('[hooks/ticket]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// User replies to a ticket (called by the source app)
app.post('/api/hooks/ticket/:id/reply', requireApiKey, async (req, res) => {
  try {
    const { id } = req.params;
    const { fromEmail, fromName, body } = req.body;
    if (!body) return res.json({ ok: false, reason: 'body required' });

    const ticket = await pool.query('SELECT * FROM tickets WHERE id=$1 AND app_id=$2', [id, req.app.id]);
    if (ticket.rows.length === 0) return res.json({ ok: false, reason: 'Ticket not found' });

    await pool.query(
      `INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, sender_email, body, source)
       VALUES ($1,'user',$2,$3,$4,'app')`,
      [id, fromName || fromEmail, fromEmail, body]
    );

    await pool.query(`UPDATE tickets SET updated_at=NOW(), status='open' WHERE id=$1`, [id]);

    // Notify admin
    pushToAdmins(
      '↩ Reply · ' + req.app.name,
      (fromName || fromEmail) + ': ' + body,
      '/', 'reply'
    );
    sendMail({
      to: process.env.ADMIN_EMAIL,
      subject: `[${req.app.name}] Reply on: ${ticket.rows[0].subject || '(no subject)'}`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:${req.app.color};color:#fff;padding:16px 20px;border-radius:8px 8px 0 0;">
            <strong>${req.app.name}</strong> — User replied to ticket
          </div>
          <div style="border:1px solid #e5e7eb;border-top:0;padding:20px;border-radius:0 0 8px 8px;">
            <p><strong>From:</strong> ${fromName || ''} &lt;${fromEmail}&gt;</p>
            <p><strong>Subject:</strong> ${ticket.rows[0].subject || '(none)'}</p>
            <hr style="border:0;border-top:1px solid #e5e7eb;margin:16px 0;">
            <div style="white-space:pre-wrap;">${body}</div>
          </div>
        </div>
      `,
      replyTo: fromEmail
    });

    res.json({ ok: true });
  } catch(e) {
    console.error('[hooks/reply]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// User reply forwarded from the source app, keyed by external_id (the app's own ticket id).
app.post('/api/hooks/ticketExtReply', requireApiKey, async (req, res) => {
  try {
    const { externalId, fromEmail, fromName, body } = req.body;
    if (!externalId || !body) return res.json({ ok: false, reason: 'externalId and body required' });
    const ticket = await pool.query('SELECT * FROM tickets WHERE external_id=$1 AND app_id=$2', [externalId, req.app.id]);
    if (ticket.rows.length === 0) return res.json({ ok: false, reason: 'Ticket not found' });
    const id = ticket.rows[0].id;
    await pool.query(
      `INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, sender_email, body, source)
       VALUES ($1,'user',$2,$3,$4,'app')`,
      [id, fromName || fromEmail, fromEmail, body]
    );
    await pool.query(`UPDATE tickets SET updated_at=NOW(), status='open' WHERE id=$1`, [id]);
    sendMail({
      to: process.env.ADMIN_EMAIL,
      subject: `[${req.app.name}] Reply on: ${ticket.rows[0].subject || '(no subject)'}`,
      html: `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;"><p><strong>${fromName || ''}</strong> &lt;${fromEmail}&gt; replied:</p><div style="white-space:pre-wrap;background:#f9fafb;padding:12px;border-radius:6px;">${body}</div></div>`,
      replyTo: fromEmail
    });
    res.json({ ok: true });
  } catch(e) {
    console.error('[hooks/ticketExtReply]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// ── Kronara app directory: a spawn announcing itself ───────────────────────
// Called by every spawn on boot and every 6h after (announceTenantToDirectory
// in the tenant's server.js). The repeat is what makes the directory
// self-healing: a restore here, or a studio changing domain, recovers on its
// own instead of needing every spawn redeployed by hand.
app.post('/api/hooks/registerTenant', requireApiKey, async (req, res) => {
  try {
    const b = req.body || {};
    const slug = String(b.code || b.spawn || '').trim().toLowerCase();
    const name = String(b.name || '').trim();
    const baseUrl = String(b.baseUrl || '').trim().replace(/\/+$/, '');

    if (!slug || !name || !baseUrl) {
      return res.status(400).json({ ok: false, reason: 'code, name and baseUrl are required' });
    }
    // A directory entry is a URL the app will navigate to — never let a spawn
    // register a non-https target.
    if (!/^https:\/\/[^\s/]+\.[^\s/]+/i.test(baseUrl)) {
      return res.status(400).json({ ok: false, reason: 'baseUrl must be https' });
    }

    const vals = {
      name,
      member_name: String(b.memberName || '').trim() || null,
      base_url: baseUrl,
      member_url: String(b.memberUrl || '').trim().replace(/\/+$/, '') || null,
      logo_url: String(b.logoUrl || '').trim() || null,
      brand_color: String(b.brandColor || '').trim() || null,
      build: String(b.build || '').trim() || null,
    };

    // Match on slug. Not ON CONFLICT: `slug` has no unique constraint and this
    // table predates the directory, so existing rows can't be assumed clean.
    // This runs once per spawn per 6h — the extra round trip costs nothing.
    const existing = await pool.query(
      `SELECT id FROM tenants WHERE LOWER(slug)=$1 ORDER BY id LIMIT 1`, [slug]
    );

    if (existing.rows.length) {
      // NOTE: `listed` is intentionally absent — that's the operator's switch,
      // and a spawn re-announcing itself must not silently un-hide it.
      await pool.query(
        `UPDATE tenants SET name=$1, member_name=$2, base_url=$3, member_url=$4,
                            logo_url=$5, brand_color=$6, build=$7, last_seen_at=NOW()
          WHERE id=$8`,
        [vals.name, vals.member_name, vals.base_url, vals.member_url,
         vals.logo_url, vals.brand_color, vals.build, existing.rows[0].id]
      );
    } else {
      await pool.query(
        `INSERT INTO tenants (app_id, name, slug, member_name, base_url, member_url,
                              logo_url, brand_color, build, last_seen_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())`,
        [(req.app && req.app.id) || null, vals.name, slug, vals.member_name, vals.base_url,
         vals.member_url, vals.logo_url, vals.brand_color, vals.build]
      );
      console.log(`[directory] New spawn registered: ${slug} -> ${baseUrl}`);
    }

    res.json({ ok: true });
  } catch(e) {
    console.error('[hooks/registerTenant]', e);
    res.status(500).json({ ok: false, reason: 'Server error' });
  }
});

// Get tickets for a user (called by source app to show "My Tickets")
app.get('/api/hooks/tickets', requireApiKey, async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.json({ ok: false, reason: 'email required' });

    const result = await pool.query(
      `SELECT t.id, t.subject, t.type, t.status, t.priority, t.created_at, t.updated_at,
              (SELECT COUNT(*) FROM ticket_messages m WHERE m.ticket_id=t.id AND m.sender_type='admin') as reply_count
       FROM tickets t
       WHERE t.app_id=$1 AND t.from_email=$2
       ORDER BY t.updated_at DESC
       LIMIT 50`,
      [req.app.id, email]
    );

    res.json({ ok: true, tickets: result.rows });
  } catch(e) {
    console.error('[hooks/tickets]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// Get messages for a specific ticket (called by source app)
app.get('/api/hooks/ticket/:id/messages', requireApiKey, async (req, res) => {
  try {
    const { id } = req.params;
    const ticket = await pool.query('SELECT * FROM tickets WHERE id=$1 AND app_id=$2', [id, req.app.id]);
    if (ticket.rows.length === 0) return res.json({ ok: false, reason: 'Ticket not found' });

    const messages = await pool.query(
      `SELECT id, sender_type, sender_name, body, source, created_at
       FROM ticket_messages WHERE ticket_id=$1 ORDER BY created_at ASC`,
      [id]
    );

    res.json({ ok: true, ticket: ticket.rows[0], messages: messages.rows });
  } catch(e) {
    console.error('[hooks/messages]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// ── Admin Dashboard Routes ──────────────────────────────────────────

// List all tickets
app.get('/api/tickets', requireAdmin, async (req, res) => {
  try {
    const { status, app: appSlug, type, search } = req.query;

    let where = [];
    let params = [];
    let idx = 1;

    // 'active' means anything still needing you: open, or replied-to and
    // waiting on them. Replying flips a ticket open -> in_progress, so a plain
    // status=open view drops a ticket the instant you answer it — which was
    // survivable when this was a second copy of the tickets and is not now that
    // it is the only place they live.
    if (status === 'active') {
      where.push(`t.status IN ('open','in_progress')`);
    } else if (status && status !== 'all') {
      where.push(`t.status=$${idx++}`);
      params.push(status);
    }
    if (appSlug && appSlug !== 'all') {
      where.push(`a.slug=$${idx++}`);
      params.push(appSlug);
    }
    if (type && type !== 'all') {
      where.push(`t.type=$${idx++}`);
      params.push(type);
    }
    if (search) {
      where.push(`(t.subject ILIKE $${idx} OR t.from_email ILIKE $${idx} OR t.from_name ILIKE $${idx})`);
      params.push(`%${search}%`);
      idx++;
    }

    const whereClause = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';

    const result = await pool.query(
      `SELECT t.*, a.name as app_name, a.slug as app_slug, a.color as app_color,
              (SELECT COUNT(*) FROM ticket_messages m WHERE m.ticket_id=t.id) as message_count,
              (SELECT body FROM ticket_messages m WHERE m.ticket_id=t.id ORDER BY m.created_at ASC LIMIT 1) as first_message
       FROM tickets t
       LEFT JOIN apps a ON a.id = t.app_id
       ${whereClause}
       ORDER BY
         CASE t.status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
         t.updated_at DESC
       LIMIT 200`,
      params
    );

    res.json({ ok: true, tickets: result.rows });
  } catch(e) {
    console.error('[tickets]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// Get single ticket with messages and notes
app.get('/api/tickets/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const ticket = await pool.query(
      `SELECT t.*, a.name as app_name, a.slug as app_slug, a.color as app_color
       FROM tickets t LEFT JOIN apps a ON a.id=t.app_id WHERE t.id=$1`,
      [id]
    );
    if (ticket.rows.length === 0) return res.json({ ok: false, reason: 'Not found' });

    const messages = await pool.query(
      'SELECT * FROM ticket_messages WHERE ticket_id=$1 ORDER BY created_at ASC', [id]
    );

    const notes = await pool.query(
      `SELECT n.*, u.name as admin_name FROM ticket_notes n
       LEFT JOIN admin_users u ON u.id=n.admin_id
       WHERE n.ticket_id=$1 ORDER BY n.created_at ASC`,
      [id]
    );

    res.json({ ok: true, ticket: ticket.rows[0], messages: messages.rows, notes: notes.rows });
  } catch(e) {
    console.error('[ticket]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// Admin replies to a ticket
app.post('/api/tickets/:id/reply', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { body } = req.body;
    if (!body) return res.json({ ok: false, reason: 'body required' });

    const ticket = await pool.query(
      'SELECT t.*, a.name as app_name, a.color as app_color, a.api_key as app_api_key, a.callback_url as app_callback_url FROM tickets t LEFT JOIN apps a ON a.id=t.app_id WHERE t.id=$1',
      [id]
    );
    if (ticket.rows.length === 0) return res.json({ ok: false, reason: 'Not found' });

    const t = ticket.rows[0];

    await pool.query(
      `INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, sender_email, body, source)
       VALUES ($1,'admin',$2,$3,$4,'dashboard')`,
      [id, req.admin.name || req.admin.email, req.admin.email, body]
    );

    // Update status to in_progress if it was open
    if (t.status === 'open') {
      await pool.query(`UPDATE tickets SET status='in_progress', updated_at=NOW() WHERE id=$1`, [id]);
    } else {
      await pool.query(`UPDATE tickets SET updated_at=NOW() WHERE id=$1`, [id]);
    }

    // Prefer per-ticket callback URL (the exact spawn this ticket came from);
    // fall back to the app-level one. This is what makes new spawns work
    // automatically without per-spawn dashboard config.
    const callbackBase = t.callback_url || t.app_callback_url;
    const willCallback = !!(callbackBase && t.external_id && t.app_api_key);

    // Push the reply back into the source app so it lands in the user's in-app
    // thread and fires their notifications (push + email, respecting their prefs).
    if (willCallback) {
      fetch(callbackBase.replace(/\/$/, '') + '/api/hooks/ticketReply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': t.app_api_key },
        body: JSON.stringify({
          externalId: t.external_id,
          body,
          senderName: req.admin.name || 'Support',
          senderEmail: req.admin.email || ''
        })
      }).catch(err => console.error('[reply→app callback]', err.message));
    }

    // Only send the dashboard's own email when the source app WON'T (no callback) —
    // avoids the user getting two emails for one reply.
    if (!willCallback) {
      sendMail({
        to: t.from_email,
        subject: `Re: ${t.subject || 'Your support request'} — ${t.app_name || 'Support'}`,
        html: `
          <div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
            <div style="background:${t.app_color || '#6366f1'};color:#fff;padding:16px 20px;border-radius:8px 8px 0 0;">
              <strong>${t.app_name || 'Support'}</strong> — Reply to your ticket
            </div>
            <div style="border:1px solid #e5e7eb;border-top:0;padding:20px;border-radius:0 0 8px 8px;">
              <p>Hi ${t.from_name || 'there'},</p>
              <div style="white-space:pre-wrap;margin:16px 0;padding:16px;background:#f9fafb;border-radius:6px;">${body}</div>
              <hr style="border:0;border-top:1px solid #e5e7eb;margin:16px 0;">
              <p style="color:#6b7280;font-size:14px;">Simply reply to this email to respond.</p>
            </div>
          </div>
        `,
        replyTo: process.env.ADMIN_EMAIL
      });
    }

    res.json({ ok: true });
  } catch(e) {
    console.error('[reply]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// Add internal note
// Hand a ticket down to the studio's own admin.
//
// Every spawn now sends ALL support here rather than to its own admin panel,
// because most of it is about how the software works and only one person can
// answer that. But some of it isn't: "why was my timesheet flagged", "can you
// approve my late shift" are questions for that studio, and nobody here can
// answer them.
//
// So this is the release valve. Forwarding makes the ticket visible in that
// spawn's own support screen — which is otherwise empty by design — and the
// studio admin replies there. Their reply reaches the staff member through the
// same path a reply from here would.

// ── Push notifications for the dashboard ─────────────────────────────
//
// Support is answered here and nowhere else now, so "I didn't see it" is a
// real failure mode rather than an inconvenience. Email alone loses to a busy
// inbox; this is the same per-device Web Push setup the tenant apps use.
//
// Per device on purpose: one row per browser/phone, so enrolling a phone does
// not un-enrol a laptop, and losing a device does not take the others with it.
// Dead subscriptions are pruned when the push service rejects them — a
// subscription outlives the browser profile that made it, and without pruning
// the table fills with endpoints that will never deliver again.
const webpush = require('web-push');

const PUSH_READY = !!(process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY);
if (PUSH_READY) {
  webpush.setVapidDetails(
    'mailto:' + (process.env.ADMIN_EMAIL || 'support@example.com'),
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
} else {
  console.warn('[push] VAPID keys unset — push is off, email only.');
}

// Send to every device this admin has enrolled.
async function pushToAdmins(title, body, url, category) {
  if (!PUSH_READY) return;
  try {
    // Preference is per admin, per category. An admin with push off for a
    // category simply has no rows returned for it.
    const col = { ticket: 'push_new_ticket', reply: 'push_user_reply' }[category] || null;
    const q = col
      ? `SELECT s.* FROM push_subscriptions s
           JOIN admin_users a ON a.id = s.admin_id
          WHERE COALESCE(a.${col}, TRUE) = TRUE`
      : `SELECT s.* FROM push_subscriptions s`;
    const subs = (await pool.query(q)).rows;

    await Promise.all(subs.map(async (s) => {
      try {
        await webpush.sendNotification(
          { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
          JSON.stringify({ title, body: String(body || '').slice(0, 180), url: url || '/' })
        );
        await pool.query(`UPDATE push_subscriptions SET last_ok = NOW() WHERE id = $1`, [s.id]).catch(() => {});
      } catch (err) {
        const code = err && err.statusCode;
        // 404/410 mean the subscription is gone for good; 403 means the VAPID
        // key no longer matches it. Keeping any of them just guarantees a
        // failure on every future send.
        if (code === 404 || code === 410 || code === 403) {
          await pool.query(`DELETE FROM push_subscriptions WHERE id = $1`, [s.id]).catch(() => {});
          console.log('[push] pruned a dead subscription (' + code + ')');
        } else {
          console.error('[push] send failed:', code || (err && err.message));
        }
      }
    }));
  } catch (e) {
    console.error('[push]', e.message);
  }
}

// The key the browser needs to subscribe. Public by definition.
app.get('/api/push/key', requireAdmin, (req, res) => {
  res.json({ ok: true, enabled: PUSH_READY, key: process.env.VAPID_PUBLIC_KEY || '' });
});

app.post('/api/push/subscribe', requireAdmin, async (req, res) => {
  try {
    const { endpoint, keys, label } = req.body || {};
    if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
      return res.json({ ok: false, reason: 'Incomplete subscription.' });
    }
    // Endpoint is unique, so re-subscribing the same browser updates its row
    // rather than adding a duplicate that would double every notification.
    await pool.query(
      `INSERT INTO push_subscriptions (admin_id, endpoint, p256dh, auth, label)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (endpoint) DO UPDATE
         SET admin_id = EXCLUDED.admin_id, p256dh = EXCLUDED.p256dh,
             auth = EXCLUDED.auth, label = EXCLUDED.label, last_ok = NOW()`,
      [req.admin.id, endpoint, keys.p256dh, keys.auth, String(label || '').slice(0, 80)]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('[push subscribe]', e.message);
    res.json({ ok: false, reason: e.message });
  }
});

app.post('/api/push/unsubscribe', requireAdmin, async (req, res) => {
  try {
    const { endpoint, id } = req.body || {};
    if (id) await pool.query(`DELETE FROM push_subscriptions WHERE id=$1 AND admin_id=$2`, [id, req.admin.id]);
    else if (endpoint) await pool.query(`DELETE FROM push_subscriptions WHERE endpoint=$1`, [endpoint]);
    else return res.json({ ok: false, reason: 'Nothing named to remove.' });
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, reason: e.message });
  }
});

// The devices you are enrolled on, so a lost phone can be removed from the
// one you still have.
app.get('/api/push/devices', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, label, created_at, last_ok FROM push_subscriptions WHERE admin_id=$1 ORDER BY created_at DESC`,
      [req.admin.id]);
    const a = await pool.query(
      `SELECT COALESCE(push_new_ticket,TRUE) AS push_new_ticket,
              COALESCE(push_user_reply,TRUE) AS push_user_reply,
              COALESCE(email_new_ticket,TRUE) AS email_new_ticket
         FROM admin_users WHERE id=$1`, [req.admin.id]);
    res.json({ ok: true, enabled: PUSH_READY, devices: r.rows, prefs: a.rows[0] || {} });
  } catch (e) {
    res.json({ ok: false, reason: e.message });
  }
});

// Email and push are independent switches — you might want a phone buzz for a
// new ticket but not an email, or both, or neither while you are away.
app.post('/api/push/prefs', requireAdmin, async (req, res) => {
  try {
    const allowed = ['push_new_ticket', 'push_user_reply', 'email_new_ticket'];
    const sets = [], vals = [];
    for (const k of allowed) {
      if (typeof req.body[k] === 'boolean') { sets.push(`${k}=$${sets.length + 1}`); vals.push(req.body[k]); }
    }
    if (!sets.length) return res.json({ ok: true });
    vals.push(req.admin.id);
    await pool.query(`UPDATE admin_users SET ${sets.join(',')} WHERE id=$${vals.length}`, vals);
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, reason: e.message });
  }
});

// Prove it works on this device before trusting it with a real ticket.
app.post('/api/push/test', requireAdmin, async (req, res) => {
  if (!PUSH_READY) return res.json({ ok: false, reason: 'Push is not configured on the server.' });
  const n = (await pool.query(`SELECT COUNT(*)::int c FROM push_subscriptions WHERE admin_id=$1`, [req.admin.id])).rows[0].c;
  if (!n) return res.json({ ok: false, reason: 'No devices enrolled yet — turn on notifications first.' });
  await pushToAdmins('Support Dashboard', 'Test notification — push is working.', '/', null);
  res.json({ ok: true, devices: n });
});

app.post('/api/tickets/:id/forward', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const note = String(req.body.note || '').trim();

    const q = await pool.query(
      `SELECT t.*, a.api_key AS app_api_key, a.callback_url AS app_callback_url
         FROM tickets t LEFT JOIN apps a ON a.id = t.app_id
        WHERE t.id = $1`, [id]
    );
    if (!q.rows.length) return res.json({ ok: false, reason: 'Not found' });
    const t = q.rows[0];

    if (t.forwarded_at) {
      return res.json({ ok: true, alreadyForwarded: true, forwardedAt: t.forwarded_at });
    }

    const base = t.callback_url || t.app_callback_url;
    if (!base || !t.external_id || !t.app_api_key) {
      // Without a callback there is nowhere to forward TO. Say so rather than
      // marking it forwarded and letting it disappear into a gap.
      return res.json({
        ok: false,
        reason: 'That spawn has no callback URL registered, so it cannot receive a forward. Reply here instead.'
      });
    }

    const r = await fetch(base.replace(/\/$/, '') + '/api/hooks/ticketForward', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': t.app_api_key },
      body: JSON.stringify({
        externalId: t.external_id,
        note,
        forwardedBy: req.admin.name || req.admin.email || 'Support',
      }),
    }).then(x => x.json()).catch(err => ({ ok: false, reason: err.message }));

    if (!r || !r.ok) {
      return res.json({ ok: false, reason: 'The spawn refused the forward: ' + ((r && r.reason) || 'no response') });
    }

    await pool.query(
      `UPDATE tickets SET forwarded_at = NOW(), forwarded_by = $2, updated_at = NOW() WHERE id = $1`,
      [id, req.admin.name || req.admin.email || 'Support']
    );
    // Recorded as a note so the trail reads in order alongside the replies,
    // rather than being a flag you have to go looking for.
    await pool.query(
      `INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, sender_email, body, source)
       VALUES ($1,'note',$2,$3,$4,'dashboard')`,
      [id, req.admin.name || 'Support', req.admin.email || '',
       'Forwarded to the studio admin' + (note ? ': ' + note : '.')]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error('[ticket forward]', e.message);
    res.json({ ok: false, reason: e.message });
  }
});

app.post('/api/tickets/:id/note', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { body } = req.body;
    if (!body) return res.json({ ok: false, reason: 'body required' });

    await pool.query(
      'INSERT INTO ticket_notes (ticket_id, admin_id, body) VALUES ($1,$2,$3)',
      [id, req.admin.id, body]
    );
    res.json({ ok: true });
  } catch(e) {
    console.error('[note]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// Update ticket (status, priority)
app.patch('/api/tickets/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, priority } = req.body;

    const sets = [];
    const params = [];
    let idx = 1;

    if (status) { sets.push(`status=$${idx++}`); params.push(status); }
    if (priority) { sets.push(`priority=$${idx++}`); params.push(priority); }
    sets.push(`updated_at=NOW()`);

    params.push(id);
    await pool.query(`UPDATE tickets SET ${sets.join(',')} WHERE id=$${idx}`, params);

    res.json({ ok: true });
  } catch(e) {
    console.error('[update]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// Delete ticket
app.delete('/api/tickets/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM tickets WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) {
    console.error('[delete]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// ── Dashboard Stats ─────────────────────────────────────────────────
app.get('/api/stats', requireAdmin, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE status='open') as open_count,
        COUNT(*) FILTER (WHERE status='in_progress') as in_progress_count,
        COUNT(*) FILTER (WHERE status='resolved') as resolved_count,
        COUNT(*) FILTER (WHERE status='closed') as closed_count,
        COUNT(*) as total_count,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as today_count
      FROM tickets
    `);

    const byApp = await pool.query(`
      SELECT a.name, a.slug, a.color, COUNT(t.id) as count,
             COUNT(t.id) FILTER (WHERE t.status='open') as open_count
      FROM apps a LEFT JOIN tickets t ON t.app_id=a.id
      GROUP BY a.id ORDER BY a.name
    `);

    res.json({ ok: true, stats: stats.rows[0], byApp: byApp.rows });
  } catch(e) {
    console.error('[stats]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// ── Apps Management ─────────────────────────────────────────────────
app.get('/api/apps', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM apps ORDER BY name');
    res.json({ ok: true, apps: result.rows });
  } catch(e) {
    res.json({ ok: false, reason: 'Server error' });
  }
});

app.post('/api/apps', requireAdmin, async (req, res) => {
  try {
    const { name, slug, color } = req.body;
    if (!name || !slug) return res.json({ ok: false, reason: 'name and slug required' });
    const apiKey = 'sk_' + uuidv4().replace(/-/g, '');
    await pool.query(
      'INSERT INTO apps (name, slug, api_key, color) VALUES ($1,$2,$3,$4)',
      [name, slug, apiKey, color || '#6366f1']
    );
    res.json({ ok: true, apiKey });
  } catch(e) {
    console.error('[apps]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// ── Tenants Management ──────────────────────────────────────────────
// ── Kronara app directory: the list the mobile app reads ───────────────────
// Public and unauthenticated on purpose — the app reads it before anyone logs
// in, and it contains nothing that isn't already public (a studio's name and
// its public URL).
//
// Registered ahead of `app.get('*')`, which serves the dashboard SPA. That
// catch-all is exactly why the client also checks the response content type:
// before this route existed, a request here returned 200 text/html rather than
// a 404, so "endpoint missing" was indistinguishable from "here is the data"
// on status alone.
app.get('/api/tenants/directory', async (req, res) => {
  try {
    const result = await pool.query(
      // DISTINCT ON (base_url): one entry per studio deployment, keeping the
      // most recently seen. A studio can legitimately end up with two rows —
      // it changed its public code, or was registered by the billing flow under
      // one slug and announced itself under another — and showing the same
      // studio twice in the picker is worse than picking the fresher row.
      // The stale row still ages out via the 30-day filter below.
      `SELECT * FROM (
         SELECT DISTINCT ON (base_url)
                slug, name, member_name, base_url, member_url, logo_url, brand_color, last_seen_at
           FROM tenants
          WHERE COALESCE(listed, TRUE) = TRUE
            AND slug IS NOT NULL AND slug <> ''
            AND base_url IS NOT NULL AND base_url <> ''
            -- Drop spawns that have stopped checking in, so dead studios fall
            -- off on their own rather than lingering as broken entries.
            AND (last_seen_at IS NULL OR last_seen_at > NOW() - INTERVAL '30 days')
          ORDER BY base_url, last_seen_at DESC NULLS LAST
       ) d
       ORDER BY name ASC`
    );

    res.set('Cache-Control', 'public, max-age=300');
    res.json({
      updated: new Date().toISOString(),
      tenants: result.rows.map(r => ({
        code: r.slug,
        name: r.name,
        memberName: r.member_name || '',
        baseUrl: r.base_url,
        memberUrl: r.member_url || '',
        logoUrl: r.logo_url || '',
        brandColor: r.brand_color || '',
      })),
    });
  } catch(e) {
    console.error('[tenants/directory]', e);
    res.status(500).json({ ok: false, reason: 'Server error' });
  }
});

app.get('/api/tenants', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.*, a.name as app_name, a.slug as app_slug, a.color as app_color
       FROM tenants t LEFT JOIN apps a ON a.id=t.app_id
       ORDER BY t.created_at DESC`
    );
    res.json({ ok: true, tenants: result.rows });
  } catch(e) {
    console.error('[tenants]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

app.post('/api/tenants', requireAdmin, async (req, res) => {
  try {
    const { name, slug, ownerEmail, appId, planName, notes } = req.body;
    if (!name) return res.json({ ok: false, reason: 'name required' });
    await pool.query(
      `INSERT INTO tenants (name, slug, owner_email, app_id, plan_name, notes)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [name, slug || null, ownerEmail || null, appId || null, planName || 'starter', notes || null]
    );
    res.json({ ok: true });
  } catch(e) {
    console.error('[tenants]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

app.patch('/api/tenants/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, slug, ownerEmail, appId, planName, stripeCustomerId, notes } = req.body;

    const sets = [];
    const params = [];
    let idx = 1;

    if (name !== undefined) { sets.push(`name=$${idx++}`); params.push(name); }
    if (slug !== undefined) { sets.push(`slug=$${idx++}`); params.push(slug); }
    if (ownerEmail !== undefined) { sets.push(`owner_email=$${idx++}`); params.push(ownerEmail); }
    if (appId !== undefined) { sets.push(`app_id=$${idx++}`); params.push(appId); }
    if (planName !== undefined) { sets.push(`plan_name=$${idx++}`); params.push(planName); }
    if (notes !== undefined) { sets.push(`notes=$${idx++}`); params.push(notes); }

    if (stripeCustomerId !== undefined) {
      sets.push(`stripe_customer_id=$${idx++}`);
      params.push(stripeCustomerId);
    }

    if (sets.length === 0) return res.json({ ok: false, reason: 'Nothing to update' });

    params.push(id);
    await pool.query(`UPDATE tenants SET ${sets.join(',')} WHERE id=$${idx}`, params);
    res.json({ ok: true });
  } catch(e) {
    console.error('[tenants]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// Sync a tenant's billing info from their app's Stripe data
app.post('/api/tenants/:id/sync-stripe', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { stripeCustomerId } = req.body;

    if (!stripeCustomerId || !stripeCustomerId.startsWith('cus_'))
      return res.json({ ok: false, reason: 'Invalid Stripe customer ID' });

    // Update the tenant with the Stripe customer ID
    await pool.query(
      'UPDATE tenants SET stripe_customer_id=$1 WHERE id=$2',
      [stripeCustomerId, id]
    );

    res.json({ ok: true });
  } catch(e) {
    console.error('[sync-stripe]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

app.delete('/api/tenants/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM tenants WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) {
    console.error('[tenants]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// ── Inbound Email Webhook (Resend) ──────────────────────────────────
app.post('/api/inbound-email', async (req, res) => {
  try {
    const { from, subject, text } = req.body;
    if (!from || !text) return res.json({ ok: false });

    // Try to match to an existing ticket by the user's email
    const fromEmail = typeof from === 'string' ? from : from?.address || '';
    const tickets = await pool.query(
      `SELECT id FROM tickets WHERE from_email=$1 ORDER BY updated_at DESC LIMIT 1`,
      [fromEmail.toLowerCase()]
    );

    if (tickets.rows.length > 0) {
      const ticketId = tickets.rows[0].id;
      await pool.query(
        `INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, sender_email, body, source)
         VALUES ($1,'user',$2,$3,$4,'email')`,
        [ticketId, fromEmail, fromEmail, text]
      );
      await pool.query(`UPDATE tickets SET updated_at=NOW(), status='open' WHERE id=$1`, [ticketId]);
    }

    res.json({ ok: true });
  } catch(e) {
    console.error('[inbound]', e);
    res.json({ ok: false });
  }
});

// ── SPA Fallback ────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ───────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4500;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Support Dashboard running on port ${PORT}`);
  initDB().catch(e => {
    console.error('Failed to initialize database:', e);
  });
});
