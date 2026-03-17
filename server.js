require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));

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
    const { externalId, tenantId, fromEmail, fromName, type, subject, body } = req.body;
    if (!fromEmail || !body) return res.json({ ok: false, reason: 'fromEmail and body required' });

    const ticketId = uuidv4();
    await pool.query(
      `INSERT INTO tickets (id, app_id, external_id, tenant_id, from_email, from_name, type, subject)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [ticketId, req.app.id, externalId || null, tenantId || null,
       fromEmail, fromName || null, type || 'message', subject || '(no subject)']
    );

    await pool.query(
      `INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, sender_email, body, source)
       VALUES ($1,'user',$2,$3,$4,'app')`,
      [ticketId, fromName || fromEmail, fromEmail, body]
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

    if (status && status !== 'all') {
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
      'SELECT t.*, a.name as app_name, a.color as app_color FROM tickets t LEFT JOIN apps a ON a.id=t.app_id WHERE t.id=$1',
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

    // Send email notification to user
    const dashUrl = process.env.DASHBOARD_URL || 'http://localhost:4500';
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
            <p style="color:#6b7280;font-size:14px;">
              You can reply to this ticket in the app under "My Tickets", or simply reply to this email.
            </p>
          </div>
        </div>
      `,
      replyTo: process.env.ADMIN_EMAIL
    });

    res.json({ ok: true });
  } catch(e) {
    console.error('[reply]', e);
    res.json({ ok: false, reason: 'Server error' });
  }
});

// Add internal note
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
initDB().then(() => {
  app.listen(PORT, () => console.log(`Support Dashboard running on port ${PORT}`));
}).catch(e => {
  console.error('Failed to initialize database:', e);
  process.exit(1);
});
