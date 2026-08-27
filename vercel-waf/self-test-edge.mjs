// ============================================================================
// self-test-edge.mjs — verifikasi rate limiter + middleware (admin/scan/block)
// Jalankan: node vercel-waf/self-test-edge.mjs
// ============================================================================
import { SlidingWindowLimiter, clientIp } from "./src/ratelimit.mjs";
import middleware from "./middleware.js";

let pass = 0, fail = 0;
const ok = (n, c, x = "") => { if (c) { pass++; console.log(`  [OK] ${n}${x ? " -> " + x : ""}`); } else { fail++; console.log(`  [FAIL] ${n}`); } };

// ---------- Unit: SlidingWindowLimiter ----------
{
  const rl = new SlidingWindowLimiter({ limit: 3, windowMs: 60000 });
  const ip = "9.9.9.9";
  ok("allow 1", rl.hit(ip).allowed);
  ok("allow 2", rl.hit(ip).allowed);
  ok("allow 3", rl.hit(ip).allowed);
  const r4 = rl.hit(ip);
  ok("block 4 (rate exceeded)", !r4.allowed);
  ok("retry-after present", r4.retryAfterMs > 0);
  ok("isolated per-IP (other IP allowed)", rl.hit("8.8.8.8").allowed);
  // window di masa lalu -> reset (simulasi detik berikutnya)
  const past = new SlidingWindowLimiter({ limit: 1, windowMs: 1 });
  const p1 = past.hit("a");
  await new Promise(r => setTimeout(r, 3));
  ok("window slide: reset allows", past.hit("a").allowed, `p1=${p1.allowed}`);
  console.log("== Unit ratelimit done ==\n");
}
async function tMain() {
  // ---------- middleware: admin auth ----------
  const mk = (url, method = "GET", headers = {}, body) => {
    const opts = { method, headers: { "content-type": "application/json", ...headers } };
    if (body) opts.body = typeof body === "string" ? body : JSON.stringify(body);
    return new Request("http://x.test" + url, opts);
  };

  // 401 tanpa token
  let r = await middleware(mk("/__waf/config"));
  ok("admin no-token -> 401", r.status === 401);

  // config dengan token
  r = await middleware(mk("/__waf/config?token=sentin-demo"));
  const cfg = await r.json();
  ok("admin config -> 200", r.status === 200, `threshold=${cfg.defaultThreshold}`);

  // scan: payload berbahaya -> BLOCK
  r = await middleware(mk("/__waf/scan?token=sentin-demo", "POST", {}, { path: "/login?id=1%27 or 1=1", body: "" }));
  const sc = await r.json();
  ok("admin scan BLOCK", r.status === 200 && sc.verdict === "BLOCK", `score=${sc.score}`);

  // scan: payload normal -> PASS
  r = await middleware(mk("/__waf/scan?token=sentin-demo", "POST", {}, { path: "/home", body: "halo dunia" }));
  const sc2 = await r.json();
  ok("admin scan PASS", sc2.verdict === "PASS");

  // ---------- 403 WAF block lewat pipeline ----------
  r = await middleware(mk("/login", "POST", {}, { token: "${jndi:ldap://evil}" }));
  ok("pipeline 403 WAF_BLOCKED", r.status === 403);
  const blk = await r.json();
  ok("reason code", blk.code === "WAF_BLOCKED", `score=${blk.score}`);

  // ---------- clientIp header ----------
  ok("clientIp from header", clientIp(mk("/", "GET", { "x-vercel-forwarded-for": "203.0.113.7" })) === "203.0.113.7");

  console.log(`\nPASS=${pass} FAIL=${fail}`);
  process.exit(fail ? 1 : 0);
}
tMain();