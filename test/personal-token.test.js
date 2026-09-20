#!/usr/bin/env node
/**
 * Personal access token — the escape hatch for an admin's own scripts (e.g.
 * Claude Code's /dev-tracker) to call admin endpoints without going through
 * the browser login's Turnstile check, since a token can only ever be minted
 * from a session that already passed it once.
 *
 *   npm test
 */
"use strict";

const Module = require("module");
const http = require("http");
const path = require("path");

// ── Stub `pg` before server.js requires it ──────────────────────────────────
const admins = { 1: { id: 1, email: "admin@example.com", name: "Admin", personal_token: null } };
const sessions = { "sess-good": { admin_id: 1, expired: false } };

function fakeResult(sql, params) {
  const s = String(sql).replace(/\s+/g, " ").trim();

  if (/FROM sessions s\s+JOIN admin_users a/i.test(s)) {
    const sess = sessions[params[0]];
    if (!sess || sess.expired) return { rows: [] };
    const a = admins[sess.admin_id];
    return { rows: a ? [{ id: a.id, email: a.email, name: a.name }] : [] };
  }
  if (/UPDATE admin_users SET personal_token=\$1 WHERE id=\$2/i.test(s)) {
    if (admins[params[1]]) admins[params[1]].personal_token = params[0];
    return { rows: [] };
  }
  if (/SELECT id, email, name FROM admin_users WHERE personal_token=\$1/i.test(s)) {
    const hit = Object.values(admins).find(a => a.personal_token && a.personal_token === params[0]);
    return { rows: hit ? [{ id: hit.id, email: hit.email, name: hit.name }] : [] };
  }
  return { rows: [], rowCount: 0 };
}

const fakeClient = { query: async (sql, params) => fakeResult(sql, params), release() {} };
const pgStub = {
  Pool: class {
    async connect() { return fakeClient; }
    async query(sql, params) { return fakeResult(sql, params); }
  },
};

const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === "pg") return pgStub;
  return origLoad.apply(this, arguments);
};

process.env.PORT = "4600";
process.env.DATABASE_URL = "postgres://stub";
delete process.env.ADMIN_EMAIL;
delete process.env.ADMIN_PASSWORD;

require(path.join(__dirname, "..", "server.js"));

// ── Tiny HTTP helper ────────────────────────────────────────────────────────
function req(method, url, { body, headers } = {}) {
  return new Promise((resolve, reject) => {
    const data = body == null ? null : JSON.stringify(body);
    const r = http.request(
      { host: "127.0.0.1", port: 4600, path: url, method,
        headers: Object.assign(
          data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {},
          headers || {}) },
      (res) => {
        let out = "";
        res.on("data", (c) => (out += c));
        res.on("end", () => {
          let json = null;
          try { json = JSON.parse(out); } catch (_) {}
          resolve({ status: res.statusCode, headers: res.headers, body: out, json });
        });
      }
    );
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

let pass = 0, fail = 0;
const check = (name, cond, extra) => {
  if (cond) { console.log("  PASS  " + name); pass++; }
  else { console.log("  FAIL  " + name + (extra ? "  -> " + extra : "")); fail++; }
};

setTimeout(async () => {
  try {
    console.log("\ngenerating a token requires a real session");
    {
      const r = await req("POST", "/api/auth/personal-token");
      check("401 with no session at all", r.status === 401, String(r.status));
    }
    {
      const r = await req("POST", "/api/auth/personal-token", { headers: { "x-session": "not-a-real-session" } });
      check("401 with a bogus session", r.status === 401, String(r.status));
    }

    console.log("\ngenerating and using a token");
    let token;
    {
      const r = await req("POST", "/api/auth/personal-token", { headers: { "x-session": "sess-good" } });
      check("a logged-in session can mint one", r.json && r.json.ok === true, r.body.slice(0, 120));
      token = r.json && r.json.token;
      check("the token is a real string, not echoed back empty", typeof token === "string" && token.length > 20);
    }
    {
      const r = await req("GET", "/api/auth/me", { headers: { authorization: "Bearer " + token } });
      check("the minted token authenticates as that admin", r.json && r.json.ok === true && r.json.admin.id === 1,
        r.body.slice(0, 120));
    }
    {
      const r = await req("GET", "/api/auth/me", { headers: { authorization: "Bearer " + token.toUpperCase() + "x" } });
      check("a garbled token is rejected, not fuzzy-matched", r.status === 401, String(r.status));
    }
    {
      // Regenerating replaces it -- there is only ever one live token, not a list.
      const r1 = await req("POST", "/api/auth/personal-token", { headers: { "x-session": "sess-good" } });
      const newToken = r1.json.token;
      check("regenerating returns a different token", newToken !== token);
      const r2 = await req("GET", "/api/auth/me", { headers: { authorization: "Bearer " + token } });
      check("the old token stops working the moment a new one is minted", r2.status === 401, String(r2.status));
      const r3 = await req("GET", "/api/auth/me", { headers: { authorization: "Bearer " + newToken } });
      check("…and the new one works", r3.json && r3.json.ok === true);
    }

    console.log("\nthe existing session/cookie path is untouched");
    {
      const r = await req("GET", "/api/auth/me", { headers: { "x-session": "sess-good" } });
      check("a plain session header still authenticates, same as before this existed",
        r.json && r.json.ok === true && r.json.admin.id === 1);
    }

    console.log("\n" + pass + " passed, " + fail + " failed\n");
    process.exit(fail ? 1 : 0);
  } catch (e) {
    console.error("test harness error:", e);
    process.exit(1);
  }
}, 300);
