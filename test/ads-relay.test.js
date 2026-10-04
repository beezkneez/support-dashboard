// Shared Google Ads callback: forwards only to a studio that signed the state, never anywhere else.
const fs = require("fs");
const path = require("path");
const { signState, verifyState, relayHandler } = require("../lib/adsRelay");
const crypto = require("crypto");

let fails = 0;
const ok = (c, label) => { if (!c) { fails++; console.log("  FAIL  " + label); } else console.log("  ok    " + label); };

const S = "secret-one";
const good = "https://studio.example/auth/google-ads/callback";
const st = signState(S, { r: good, n: "abc" });

ok(verifyState(S, st) && verifyState(S, st).r === good, "a signed state verifies");
ok(verifyState("other", st) === null, "wrong secret is rejected");
ok(verifyState(S, st.slice(0, -2) + "xx") === null, "tampered signature is rejected");
{
  const forged = signState(S, { r: "https://evil.example/steal", n: "x" });
  ok(verifyState(S, forged) === null, "a properly signed state for the wrong path is still refused");
  for (const r of ["http://studio.example/auth/google-ads/callback", "https://studio.example/auth/google-ads/callback?x=1", "https://user:p@studio.example/auth/google-ads/callback", "javascript:alert(1)"]) {
    ok(verifyState(S, signState(S, { r, n: "x" })) === null, "refuses return URL " + r);
  }
}
ok(verifyState(S, signState(S, { r: good, n: "a" }, Date.now() - 16 * 60 * 1000)) === null, "expired state is rejected");
ok(verifyState(S, signState(S, { r: good, n: "a" }, Date.now() + 10 * 60 * 1000)) === null, "a state dated in the future is rejected");
ok(verifyState(S, "garbage") === null && verifyState(S, "") === null && verifyState("", st) === null, "garbage and empty secret are rejected");
ok(verifyState(S, st + ".extra") === null, "extra segments are rejected");
{
  // The studio side (aradia-time lib/googleAdsRelay.js) builds the state this way; pin the format here.
  const b = Buffer.from(JSON.stringify({ r: good, n: "q", t: Date.now() })).toString("base64url");
  const sig = crypto.createHmac("sha256", S).update(b).digest("base64url");
  ok(verifyState(S, b + "." + sig) !== null, "a state built the way the studio builds it verifies at the hub");
}

// Handler
const run = (query) => {
  const out = {};
  relayHandler(() => S)({ query }, {
    status(c) { out.status = c; return this; }, type() { return this; }, send(b) { out.body = b; return this; },
    set() { return this; }, redirect(c, u) { out.status = c; out.location = u; },
  });
  return out;
};
{
  const r = run({ code: "C0DE", state: st, scope: "s" });
  const u = new URL(r.location);
  ok(r.status === 302 && u.origin + u.pathname === good, "valid callback redirects to the studio");
  ok(u.searchParams.get("code") === "C0DE" && u.searchParams.get("state") === st, "code and state are passed along");
  ok(run({ code: "C0DE", state: "bad" }).status === 400, "invalid state gets a 400 and no redirect");
  ok(run({ error: "access_denied", state: st }).location.includes("error=access_denied"), "Google's error is passed along too");
  const noExtra = run({ code: "C", state: st, evil: "1" });
  ok(!noExtra.location.includes("evil"), "unknown parameters are not forwarded");
}
ok(/\/google-ads\/callback/.test(fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8")), "route is mounted in server.js");

console.log(fails ? "\n" + fails + " FAILED" : "\nall passed");
process.exit(fails ? 1 : 0);
