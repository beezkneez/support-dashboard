// The Google Ads sign-in goes through ONE shared callback address (the hub), so
// Google only ever has to know a single redirect URI no matter how many studios
// are on board. The hub just forwards the browser back to the studio that
// started the sign-in; it never holds a token.
//
// The studio signs the "state" it hands Google. The hub only forwards to the
// address inside a state that carries a valid signature, so it cannot be used
// as an open redirect, and no per-studio allowlist is needed.
//
// Keep this format identical to support-dashboard's lib/adsRelay.js.
const crypto = require("crypto");

const MAX_AGE_MS = 15 * 60 * 1000;
const RETURN_PATH = "/auth/google-ads/callback";

const b64 = (buf) => Buffer.from(buf).toString("base64url");
const mac = (secret, body) => b64(crypto.createHmac("sha256", secret).update(body).digest());

// payload: { r: return URL on the studio, n: nonce }
function signState(secret, payload, now) {
  if (!secret) throw new Error("GOOGLE_ADS_RELAY_SECRET is not set.");
  const body = b64(JSON.stringify({ r: payload.r, n: payload.n, t: now || Date.now() }));
  return body + "." + mac(secret, body);
}

// Returns the payload, or null for anything forged, malformed, expired or pointing somewhere it shouldn't.
function verifyState(secret, state, now, returnPath) {
  try {
    if (!secret || typeof state !== "string") return null;
    const [body, sig, extra] = state.split(".");
    if (!body || !sig || extra !== undefined) return null;
    const want = mac(secret, body);
    const a = Buffer.from(sig), b = Buffer.from(want);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!p || typeof p.r !== "string" || typeof p.n !== "string" || !Number.isFinite(p.t)) return null;
    if ((now || Date.now()) - p.t > MAX_AGE_MS || p.t > (now || Date.now()) + 60 * 1000) return null;
    const u = new URL(p.r);
    if (u.protocol !== "https:" || u.pathname !== (returnPath || RETURN_PATH) || u.search || u.hash || u.username || u.password) return null;
    return p;
  } catch (_) { return null; }
}

module.exports = { signState, verifyState, RETURN_PATH, MAX_AGE_MS };

// The same hub also relays Facebook Ads sign-ins. Meta only accepts redirect URIs
// listed on its app, so one hub address serves every studio, exactly as for Google.
// Same state format and secret; only the studio's return path and the parameters
// Meta sends back differ.
const FACEBOOK = {
  returnPath: "/auth/facebook-ads/callback",
  label: "Facebook Ads",
  params: ["code", "error", "error_reason", "error_description"],
};
const GOOGLE = {
  returnPath: RETURN_PATH,
  label: "Google Ads",
  params: ["code", "error", "scope", "authuser", "prompt"],
};

// Express handler for GET /google-ads/callback. Forwards Google's answer
// (code, or error) to the studio named in the signed state.
function relayHandler(secret, channel) {
  const ch = channel || GOOGLE;
  return (req, res) => {
    const p = verifyState(secret(), String(req.query.state || ""), undefined, ch.returnPath);
    if (!p) return res.status(400).type("text/plain").send("This " + ch.label + " connect link is invalid or has expired. Close this tab and try again from your studio's app.");
    const u = new URL(p.r);
    for (const k of ch.params) {
      if (typeof req.query[k] === "string") u.searchParams.set(k, req.query[k]);
    }
    u.searchParams.set("state", String(req.query.state));
    res.set("Referrer-Policy", "no-referrer");
    res.redirect(302, u.toString());
  };
}
module.exports.relayHandler = relayHandler;
module.exports.FACEBOOK = FACEBOOK;
module.exports.GOOGLE = GOOGLE;
