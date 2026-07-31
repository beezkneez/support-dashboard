#!/usr/bin/env node
/**
 * Kronara app directory endpoint tests.
 *
 * Runs the real server.js with `pg` stubbed, so routing, auth, validation and
 * the upsert branching are all exercised without needing Supabase credentials.
 * The stub records every query, which is how the upsert path is asserted.
 *
 *   npm test
 */
"use strict";

const Module = require("module");
const http = require("http");
const path = require("path");

// ── Stub `pg` before server.js requires it ──────────────────────────────────
const queries = [];
let tenantRows = [];       // what SELECT ... FROM tenants returns
const API_KEY = "test-key";

function fakeResult(sql, params) {
  const s = String(sql).replace(/\s+/g, " ").trim();
  queries.push({ sql: s, params });

  if (/FROM apps WHERE api_key/i.test(s)) {
    return { rows: params[0] === API_KEY ? [{ id: 7, name: "Aradia Time", slug: "aradia-time" }] : [] };
  }
  if (/SELECT id FROM tenants WHERE LOWER\(slug\)/i.test(s)) {
    const hit = tenantRows.find(t => String(t.slug).toLowerCase() === params[0]);
    return { rows: hit ? [{ id: hit.id }] : [] };
  }
  if (/FROM tenants/i.test(s) && /base_url/i.test(s) && /ORDER BY name/i.test(s)) {
    return { rows: tenantRows.filter(t => t.listed !== false) };
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

const origResolve = Module._resolveFilename;
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === "pg") return pgStub;
  return origLoad.apply(this, arguments);
};

process.env.PORT = "4599";
process.env.DATABASE_URL = "postgres://stub";
delete process.env.ADMIN_EMAIL;   // skip admin seeding
delete process.env.ADMIN_PASSWORD;

require(path.join(__dirname, "..", "server.js"));

// ── Tiny HTTP helper ────────────────────────────────────────────────────────
function req(method, url, { body, headers } = {}) {
  return new Promise((resolve, reject) => {
    const data = body == null ? null : JSON.stringify(body);
    const r = http.request(
      { host: "127.0.0.1", port: 4599, path: url, method,
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

const GOOD = {
  spawn: "aradia", code: "aradia", name: "Aradia Fitness",
  baseUrl: "https://aradiafitness.app/", memberUrl: "https://aradiafitness.app/m",
  logoUrl: "https://aradiafitness.app/logo.png", brandColor: "#8b1e2d", build: "abc123",
};
const KEYED = { headers: { "x-api-key": API_KEY } };

setTimeout(async () => {
  try {
    console.log("\nregisterTenant — auth");
    {
      const r = await req("POST", "/api/hooks/registerTenant", { body: GOOD });
      check("401 without an API key", r.status === 401, r.status + " " + r.body.slice(0, 80));
    }
    {
      const r = await req("POST", "/api/hooks/registerTenant",
        { body: GOOD, headers: { "x-api-key": "wrong" } });
      check("401 with a bad API key", r.status === 401, String(r.status));
    }

    console.log("\nregisterTenant — validation");
    for (const [label, body] of [
      ["missing code", { ...GOOD, code: "", spawn: "" }],
      ["missing name", { ...GOOD, name: "" }],
      ["missing baseUrl", { ...GOOD, baseUrl: "" }],
    ]) {
      const r = await req("POST", "/api/hooks/registerTenant", { body, ...KEYED });
      check("400 on " + label, r.status === 400, String(r.status));
    }
    {
      const r = await req("POST", "/api/hooks/registerTenant",
        { body: { ...GOOD, baseUrl: "http://insecure.example.com" }, ...KEYED });
      check("400 on a non-https baseUrl", r.status === 400, String(r.status));
    }

    console.log("\nregisterTenant — insert vs update");
    {
      tenantRows = [];
      queries.length = 0;
      const r = await req("POST", "/api/hooks/registerTenant", { body: GOOD, ...KEYED });
      const ins = queries.find(q => /INSERT INTO tenants/i.test(q.sql));
      check("ok:true", r.json && r.json.ok === true, r.body.slice(0, 100));
      check("INSERTs when the slug is unknown", !!ins);
      check("stores the app id from the API key", ins && ins.params[0] === 7, ins && String(ins.params[0]));
      check("strips the trailing slash from baseUrl",
        ins && ins.params[4] === "https://aradiafitness.app", ins && ins.params[4]);
      check("lowercases the slug", ins && ins.params[2] === "aradia", ins && ins.params[2]);
    }
    {
      tenantRows = [{ id: 42, slug: "aradia", name: "Old Name", base_url: "https://old", listed: true }];
      queries.length = 0;
      await req("POST", "/api/hooks/registerTenant", { body: { ...GOOD, name: "Aradia Fitness v2" }, ...KEYED });
      const upd = queries.find(q => /UPDATE tenants SET/i.test(q.sql));
      const ins = queries.find(q => /INSERT INTO tenants/i.test(q.sql));
      check("UPDATEs an existing slug", !!upd);
      check("does not INSERT a duplicate", !ins);
      check("updates the name", upd && upd.params[0] === "Aradia Fitness v2", upd && upd.params[0]);
      check("targets the matched row", upd && upd.params[7] === 42, upd && String(upd.params[7]));
      check("never writes `listed` (operator kill switch)",
        upd && !/\blisted\s*=/i.test(upd.sql), upd && upd.sql.slice(0, 90));
    }
    {
      // Slug matching must be case-insensitive, or a spawn re-announcing with
      // different casing would silently create a second row.
      tenantRows = [{ id: 9, slug: "Aradia", name: "X", base_url: "https://x", listed: true }];
      queries.length = 0;
      await req("POST", "/api/hooks/registerTenant", { body: GOOD, ...KEYED });
      check("matches slug case-insensitively",
        !queries.some(q => /INSERT INTO tenants/i.test(q.sql)));
    }

    console.log("\ndirectory");
    {
      tenantRows = [
        { slug: "aradia", name: "Aradia Fitness", member_name: "Aradia", base_url: "https://aradiafitness.app",
          member_url: "https://aradiafitness.app/m", logo_url: "https://aradiafitness.app/logo.png",
          brand_color: "#8b1e2d", listed: true },
      ];
      const r = await req("GET", "/api/tenants/directory");
      check("200", r.status === 200, String(r.status));
      // The whole reason the client checks content type: before this route
      // existed the SPA catch-all answered 200 text/html here.
      check("Content-Type is JSON", /application\/json/.test(r.headers["content-type"] || ""),
        r.headers["content-type"]);
      check("needs no API key", r.json && Array.isArray(r.json.tenants));
      const t = r.json.tenants[0];
      check("maps slug -> code", t && t.code === "aradia", JSON.stringify(t));
      check("maps base_url -> baseUrl", t && t.baseUrl === "https://aradiafitness.app");
      check("includes a logo", t && t.logoUrl === "https://aradiafitness.app/logo.png");
      check("has an updated timestamp", !!(r.json && r.json.updated));
      const sql = queries.filter(q => /FROM tenants/i.test(q.sql) && /ORDER BY name/i.test(q.sql)).pop();
      check("filters unlisted rows", sql && /listed/i.test(sql.sql));
      check("filters stale spawns", sql && /last_seen_at/i.test(sql.sql));
    }
    {
      tenantRows = [];
      const r = await req("GET", "/api/tenants/directory");
      check("empty directory is still valid JSON", r.json && r.json.tenants.length === 0);
    }

    console.log("\nroute precedence");
    {
      // /api/tenants (admin) must not swallow /api/tenants/directory, and the
      // SPA catch-all must not either.
      const r = await req("GET", "/api/tenants");
      check("/api/tenants still requires admin", r.status === 401 || (r.json && r.json.ok === false),
        r.status + " " + r.body.slice(0, 60));
    }

    console.log("\n" + pass + " passed, " + fail + " failed\n");
    process.exit(fail ? 1 : 0);
  } catch (e) {
    console.error("test harness error:", e);
    process.exit(1);
  }
}, 300);
