// ============================================================================
// middleware.mjs — Vercel Edge Firewall
//   WAF L7 (Aho-Corasick + anomaly scoring)
//   + Rate limit per-IP (Upstash/@vercel/kv cross-edge, fallback lokal)
//   + Whitelist/bypass per-IP (anti-lockout)
//   + GeoIP block by region (x-vercel-ip-country)
//   + Admin API (config/status/scan)
//
// Env:
//   WAF_ADMIN_TOKEN        default sentin-demo
//   WAF_RATE_LIMIT         default 60
//   WAF_RATE_WINDOW_MS     default 60000
//   WAF_ALLOWED_IPS        "1.2.3.4,10.0.0.0/8"  (lewati rate+waf+geo)
//   WAF_BLOCKED_COUNTRIES  "US,CN"                (blokir by country)
//   UPSTASH_KV_REST_URL / UPSTASH_KV_REST_TOKEN    (untuk rate-limit konsisten)
// ============================================================================
import { SCORE, inspectRequest } from "./src/wafcore.mjs";
import { SlidingWindowLimiter, RateLimiterKv, clientIp } from "./src/ratelimit.mjs";

const RATE_LIMIT     = Number(process.env.WAF_RATE_LIMIT     || 60);
const RATE_WINDOW_MS = Number(process.env.WAF_RATE_WINDOW_MS || 60000);
const ADMIN_TOKEN    = process.env.WAF_ADMIN_TOKEN || "sentin-demo";
const _ALLOWED       = (process.env.WAF_ALLOWED_IPS || "").split(",").map(s=>s.trim()).filter(Boolean);
const _BLOCK_COUNTRY = (process.env.WAF_BLOCKED_COUNTRIES || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);

const BYPASS_PREFIXES = ["/_next/static", "/static", "/_vercel/insights", "/favicon.ico", "/health"];

// --- Rate limiter: pilih KV kalau tersedia, fallback lokal -------------------
let _kv = null;
let _kvReady = false;
async function ensureKv() {
  if (_kvReady) return;
  try {
    if (process.env.UPSTASH_KV_REST_URL && process.env.UPSTASH_KV_REST_TOKEN) {
      // dynamic import agar noda paket tidak wajib pd project tanpa KV
      const { createClient } = await import("@vercel/kv");
      _kv = createClient({ url: process.env.UPSTASH_KV_REST_URL, token: process.env.UPSTASH_KV_REST_TOKEN });
      _kvReady = true;
    } else {
      _kv = null; _kvReady = true;   // tidak ada kv config -> pakai lokal
    }
  } catch (e) {
    _kv = null; _kvReady = true;     // import gagal di kedeplukan -> lokal
  }
}
async function getLimiter() {
  await ensureKv();
  return _kv ? new RateLimiterKv({ limit: RATE_LIMIT, windowMs: RATE_WINDOW_MS, kv: _kv })
             : new SlidingWindowLimiter({ limit: RATE_LIMIT, windowMs: RATE_WINDOW_MS });
}

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

function isAuthorized(req) {
  let q = null;
  try { q = new URL(req.url).searchParams.get("token"); } catch {}
  const h = req.headers.get("x-sentinel-token");
  return h === ADMIN_TOKEN || q === ADMIN_TOKEN;
}

function shouldInspect(pathname) {
  for (const p of BYPASS_PREFIXES) if (pathname.startsWith(p)) return false;
  return true;
}

// IP/CIDR exact match untuk whitelist
function ipAllowed(ip, allowed) {
  if (!ip || !allowed.length) return false;
  for (const entry of allowed) {
    if (entry === ip) return true;
    if (entry.includes("/")) {
      const [base, prefixStr] = entry.split("/");
      const prefix = Number(prefixStr) || 0;
      const a = ip.split(".").map(Number);
      const b = base.split(".").map(Number);
      if (a.length !== 4 || b.length !== 4) continue;
      let bits = prefix;
      let match = true;
      for (let i = 0; i < 4; i++) {
        const takes = Math.min(bits, 8);
        const mask = takes === 0 ? 0 : ((0xff << (8 - takes)) & 0xff);
        if ((a[i] & mask) !== (b[i] & mask)) { match = false; break; }
        bits -= takes;
        if (bits <= 0) break;
      }
      if (match) return true;
    }
  }
  return false;
}

function continueRequest(req, extraHeaders) {
  const headers = new Headers(req.headers);
  if (extraHeaders) for (const [k, v] of extraHeaders) headers.set(k, v);
  const isBodyReq = req.method !== "GET" && req.method !== "HEAD";
  const body = isBodyReq ? (req.__sentinelBody || "") : undefined;
  const pass = new Request(req.url, { method: req.method, headers, body });
  return Response.next ? Response.next({ request: pass }) : fetch(pass);
}

export default async function middleware(req) {
  const url = new URL(req.url);
  const ip  = clientIp(req);
  const country = (req.headers.get("x-vercel-ip-country") || "").toUpperCase();

  // --- Admin API -----------------------------------------------------------------
  if (url.pathname.startsWith("/__waf/")) {
    if (!isAuthorized(req)) return json({ error: "Unauthorized", code: "WAF_ADMIN_AUTH" }, 401);
    return dispatchAdmin(req, url, ip, country);
  }

  if (!shouldInspect(url.pathname)) {
    return continueRequest(req, hdr(ip));
  }

  const extra = hdr(ip);

  // --- WHITELIST (anti-lockout): IP terpercaya lewati SEMUA filter ----------
  if (ipAllowed(ip, _ALLOWED)) {
    extra.set("x-sentinel-whitelisted", "1");
    return continueRequest(req, extra);
  }

  // --- GEOIP block by region --------------------------------------------------
  if (_BLOCK_COUNTRY.length && country && _BLOCK_COUNTRY.includes(country)) {
    return json({ error: "Forbidden", code: "GEO_BLOCKED", ip, country }, 403);
  }

  // --- Rate limiting (kv / lokal) -------------------------------------------
  const limiter = await getLimiter();
  const bucket = await limiter.hit(ip);
  extra.set("x-sentinel-rate-limit", `${RATE_LIMIT}/${Math.round(RATE_WINDOW_MS / 1000)}s`);
  extra.set("x-sentinel-rate-remaining", String(bucket.remaining));
  extra.set("x-sentinel-rate-source", bucket.source || "local");

  if (!bucket.allowed) {
    extra.set("retry-after", String(Math.max(1, Math.ceil((bucket.retryAfterMs||0) / 1000))));
    return json({ error: "Too Many Requests", code: "RATE_LIMITED", ip,
                  retryAfterSec: Math.max(1, Math.round((bucket.retryAfterMs||0) / 1000)) }, 429);
  }

  // --- Baca body ------------------------------------------------------------
  let body = "";
  if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "OPTIONS") {
    try { body = (await req.text()).slice(0, 100_000); } catch {}
  }
  req.__sentinelBody = body;

  // --- WAF inspect -----------------------------------------------------------
  const verdict = inspectRequest(
    req.method,
    url.pathname + url.search,
    req.headers.get("user-agent") || "",
    body
  );
  if (verdict.suspicious) {
    return json({
      error: "Forbidden", code: "WAF_BLOCKED", ip,
      score: verdict.score, threshold: SCORE.THRESHOLD,
      matches: verdict.matches.slice(0, 20),
    }, 403);
  }

  return continueRequest(req, extra);
}

function hdr(ip) {
  const h = new Headers();
  h.set("x-sentinel-ip", ip);
  return h;
}

async function dispatchAdmin(req, url, ip, country) {
  const action = url.pathname.slice("/__waf/".length);
  if (!action) return json({ endpoints: ["config", "status", "scan"], ip, country, token: ADMIN_TOKEN });

  if (action === "config") {
    const kv = await ensureKv();
    return json({
      algorithm: "Aho-Corasick + anomaly scoring (CRS)",
      defaultThreshold: SCORE.THRESHOLD,
      scoreTable: SCORE,
      rateLimit: { limit: RATE_LIMIT, windowMs: RATE_WINDOW_MS, storage: _kv ? "upstash-kv" : "local" },
      bypass: BYPASS_PREFIXES,
      whitelist: _ALLOWED,
      blockCountries: _BLOCK_COUNTRY,
    });
  }

  if (action === "status") {
    const limiter = await getLimiter();
    return json({
      ip, country,
      whitelisted: ipAllowed(ip, _ALLOWED),
      rate: limiter.snapshot ? limiter.snapshot() : undefined,
      storage: _kv ? "kv" : "local",
    });
  }

  if (action === "scan") {
    let input = {};
    try { input = JSON.parse(await req.text()); }
    catch { return json({ error: "invalid JSON body", example: { path: "/login", body: "user=admin' OR 1=1--" } }, 400); }
    const verr = inspectRequest(input.method || "GET", input.path || "/", input.userAgent || "", input.body || "");
    return json({ verdict: verr.suspicious ? "BLOCK" : "PASS",
                  score: verr.score, threshold: SCORE.THRESHOLD,
                  matches: verr.matches.slice(0, 20) });
  }

  return json({ error: "unknown", action, ip }, 400);
}

export const config = {
  matcher: ["/((?!_next/static|favicon.ico|health).*)"],
};
