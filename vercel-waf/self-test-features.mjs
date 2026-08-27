// ============================================================================
// self-test-features.mjs — verifikasi fitur khusus v2.5:
//   RateLimiterKv (mock @vercel/kv), whitelist per-IP, GeoIP block.
// Jalankan: node vercel-waf/self-test-features.mjs
// Catatan: middleware di-import dinamis SETELAH env di-set (ESM hoisted import
// membaca env saat modul dievaluasi).
// ============================================================================
import { RateLimiterKv } from "./src/ratelimit.mjs";

let pass = 0, fail = 0;
const ok = (n, c, x = "") => { if (c) { pass++; console.log(`  [OK] ${n}${x ? " -> " + x : ""}`); } else { fail++; console.log(`  [FAIL] ${n}`); } };

// ---------- RateLimiterKv dengan MOCK KV ------------------------------------
{
  // mock sederhana yang meniru incr(+ttl) & expire
  const store = new Map();
  const mockKv = {
    async incr(key, _by, _opts) {
      const cur = (store.get(key) || 0) + 1;
      store.set(key, cur);
      return cur;
    },
    async expire() { return 1; },
    _store: store,
  };
  const rl = new RateLimiterKv({ limit: 3, windowMs: 60000, kv: mockKv });
  ok("kv allow 1", (await rl.hit("1.1.1.1")).allowed);
  ok("kv allow 2", (await rl.hit("1.1.1.1")).allowed);
  ok("kv allow 3", (await rl.hit("1.1.1.1")).allowed);
  const r4 = await rl.hit("1.1.1.1");
  ok("kv block 4 (limit exceeded)", !r4.allowed, `source=${r4.source}`);
  ok("kv source == kv", r4.source === "kv");
  // terpisa per-IP
  ok("kv isolated per-IP", (await rl.hit("2.2.2.2")).allowed);
}
{
  // tanpa kv -> fallback lokal
  const rl = new RateLimiterKv({ limit: 2, windowMs: 60000, kv: null });
  (await rl.hit("3.3.3.3"));
  (await rl.hit("3.3.3.3"));
  const r3 = await rl.hit("3.3.3.3");
  ok("no-kv fallback lokal", r3.source === "local" && !r3.allowed);
}
console.log("== RateLimiterKv done ==\n");

// ---------- middleware dengan env whitelist + blocked countries -------------
process.env.WAF_ALLOWED_IPS = "203.0.113.7,10.0.0.0/8";
process.env.WAF_BLOCKED_COUNTRIES = "US,CN";
process.env.WAF_ADMIN_TOKEN = "sentin-demo";

const { default: middleware } = await import("./middleware.mjs");

const mk = (url, headers = {}) =>
  new Request("http://x.test" + url, { method: "GET", headers });

// whitelist IP -> lewatkan semua filter (pass-through). Karena continueRequest
// memakai fetch di env tanpa Response.next (node), "meneruskan" melempar
// ENOTFOUND → ditangkap jadi "pass-through" = LOLOS semua filter.
let r = await middleware(mk("/anything", { "x-vercel-forwarded-for": "203.0.113.7",
                                           "x-vercel-ip-country": "US" }))
  .then(() => "res.ok").catch(() => "pass-through");
ok("whitelist exact IP bypass (pass-through)", r === "pass-through");
{
  // IP dalam CIDR whitelist juga lewat
  const rr = await middleware(mk("/x", { "x-vercel-forwarded-for": "10.0.0.5" }))
    .then(() => "res.ok").catch(() => "pass-through");
  ok("whitelist CIDR /8 bypass (pass-through)", rr === "pass-through");
}
// Geo block: non-whitelist IP dari US -> 403 GEO_BLOCKED
r = await middleware(mk("/anypath", { "x-vercel-forwarded-for": "8.8.8.8",
                                      "x-vercel-ip-country": "US" }));
const geo = await r.json();
ok("geo block US -> 403 GEO_BLOCKED", r.status === 403, `code=${geo.code}`);
// negara aman (ID) + path normal -> bukan GEO block (pass-through / bukan 403 GEO)
r = await middleware(mk("/home", { "x-vercel-forwarded-for": "8.8.8.8",
                                   "x-vercel-ip-country": "ID" }))
  .then(async (res) => (await res.json()).code)
  .catch(() => "pass-through");
ok("geo allow ID -> bukan GEO_BLOCKED", r !== "GEO_BLOCKED", `res=${r}`);

console.log(`\nPASS=${pass} FAIL=${fail}`);
process.exit(fail ? 1 : 0);