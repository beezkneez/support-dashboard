#!/usr/bin/env node
/**
 * The Kronara dashboard bridge: dashboard.kronara.app/support passes requests
 * on with SUPPORT_BRIDGE_TOKEN and the signed-in person's email. Only the
 * right secret gets in; a new person gets their own row; their pages are kept
 * so phone alerts follow them.
 *
 *   npm test
 */
"use strict";

const Module = require("module");
const http = require("http");
const path = require("path");

const admins = { 1: { id: 1, email: "jud@example.com", name: "Jud", dashboard_pages: null } };
let nextId = 2;
const sql = [];

function fakeResult(q, params) {
  const s = String(q).replace(/\s+/g, " ").trim();
  sql.push({ s, params });
  if (/SELECT id, email, name FROM admin_users WHERE LOWER\(email\)=\$1/i.test(s)) {
    const a = Object.values(admins).find(x => x.email === params[0]);
    return { rows: a ? [{ id: a.id, email: a.email, name: a.name }] : [] };
  }
  if (/INSERT INTO admin_users \(email, password, name\)/i.test(s)) {
    const a = { id: nextId++, email: params[0], name: params[2], password: params[1], dashboard_pages: null };
    admins[a.id] = a;
    return { rows: [{ id: a.id, email: a.email, name: a.name }] };
  }
  if (/UPDATE admin_users SET dashboard_pages=\$1 WHERE id=\$2/i.test(s)) {
    if (admins[params[1]]) admins[params[1]].dashboard_pages = params[0];
    return { rows: [] };
  }
  return { rows: [], rowCount: 0 };
}
const fakeClient = { query: async (q, p) => fakeResult(q, p), release() {} };
const pgStub = { Pool: class { async connect() { return fakeClient; } async query(q, p) { return fakeResult(q, p); } } };
const origLoad = Module._load;
Module._load = function (request) {
  if (request === "pg") return pgStub;
  return origLoad.apply(this, arguments);
};

process.env.PORT = "4601";
process.env.DATABASE_URL = "postgres://stub";
process.env.SUPPORT_BRIDGE_TOKEN = "bridge-secret-123";
delete process.env.ADMIN_EMAIL;
delete process.env.ADMIN_PASSWORD;
require(path.join(__dirname, "..", "server.js"));

function req(method, url, headers) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: "127.0.0.1", port: 4601, path: url, method, headers: headers || {} }, (res) => {
      let out = "";
      res.on("data", (c) => (out += c));
      res.on("end", () => { let json = null; try { json = JSON.parse(out); } catch (_) {} resolve({ status: res.statusCode, json }); });
    });
    r.on("error", reject);
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
    const bridged = (extra) => Object.assign({ "x-bridge-token": "bridge-secret-123", "x-operator-email": "Sam@Example.com",
      "x-operator-name": encodeURIComponent("Sam"), "x-operator-role": "staff", "x-operator-pages": "tickets" }, extra || {});

    let r = await req("GET", "/api/auth/me", bridged({ "x-bridge-token": "wrong-secret-123" }));
    check("a wrong bridge secret is refused", r.status === 401, String(r.status));

    r = await req("GET", "/api/auth/me", bridged({ "x-bridge-token": "" }));
    check("an empty bridge secret is refused", r.status === 401, String(r.status));

    r = await req("GET", "/api/auth/me", bridged({ "x-operator-email": "" }));
    check("the right secret but no person is refused", r.status === 401, String(r.status));

    r = await req("GET", "/api/auth/me", bridged());
    check("the right secret and a person gets in", r.json && r.json.ok === true, JSON.stringify(r.json));
    const sam = Object.values(admins).find(a => a.email === "sam@example.com");
    check("a first-time person gets their own row (email lowercased)", !!sam && r.json.admin.id === sam.id);
    check("with a password nobody knows", sam && typeof sam.password === "string" && sam.password.length > 20);
    check("their support pages are recorded for phone alerts", sam && sam.dashboard_pages === "tickets");

    r = await req("GET", "/api/auth/me", bridged({ "x-operator-email": "jud@example.com", "x-operator-role": "admin" }));
    check("an existing person reuses their row", r.json && r.json.admin.id === 1);
    check("an admin's pages are recorded as everything (NULL)", admins[1].dashboard_pages === null);

    process.env.SUPPORT_BRIDGE_TOKEN = "";
    r = await req("GET", "/api/auth/me", bridged());
    check("with no secret set on support, the bridge is closed", r.status === 401, String(r.status));

    console.log("\n" + pass + " passed, " + fail + " failed\n");
    process.exit(fail ? 1 : 0);
  } catch (e) { console.error(e); process.exit(1); }
}, 300);
