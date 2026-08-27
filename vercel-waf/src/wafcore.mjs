// ============================================================================
// wafcore.mjs — engine WAF portabel (Vercel Edge / Node / browser).
//
// Prinsip sama dengan engine C++ Sentinel (v2.4):
//   Decode -> Fast Match (Aho-Corasick O(N), anti-ReDoS)
//   -> Accumulate Score (anomaly scoring CRS) -> Action (pass/block)
// Tanpa dependency; hanya API Web standar.
// ============================================================================

export const SCORE = {
  THRESHOLD: 5,      // Anomalous Threat Level
  ENCODING:   2,
  NULL_BYTE:  2,
  QUOTE_RUN:  2,
  MED:        2,
  HIGH:       3,
  CRITICAL:   5,
};

const _KW = [
  // SQLi
  ["union select","SQLI",5], ["or 1=","SQLI",3], ["and 1=","SQLI",3],
  [";drop ","SQLI",3], [";delete ","SQLI",3], [";insert ","SQLI",3],
  [";update ","SQLI",3], [";alter ","SQLI",3],
  ["sleep(","SQLI",3], ["benchmark(","SQLI",3], ["pg_sleep(","SQLI",3],
  ["waitfor delay","SQLI",3], ["information_schema","SQLI",3],
  ["sysobjects","SQLI",3], ["syscolumns","SQLI",3], ["xp_cmdshell","SQLI",5],
  // XSS
  ["<script","XSS",5], ["onerror=","XSS",3], ["onload=","XSS",3],
  ["onclick=","XSS",3], ["onmouseover=","XSS",3], ["onfocus=","XSS",3],
  ["javascript:","XSS",3],
  // Traversal / LFI / leak
  ["../","TRAVERSAL",2], ["etc/passwd","TRAVERSAL",5],
  ["etc/shadow","LEAK",5], ["proc/self/environ","LEAK",5],
  [".git/config","LEAK",3], ["php://filter","LFI_RFI",5],
  ["php://input","LFI_RFI",5], ["data://text","LFI_RFI",5],
  // Exploit modern
  ["jndi:","RCE",5], ["169.254.169.254","SSRF",5],
  ["metadata.google.internal","SSRF",5],
  ["gopher://","SSRF",3], ["dict://","SSRF",3], ["file://","SSRF",3],
  // Web shell PHP
  ["eval(","RCE",3], ["assert(","RCE",3], ["system(","RCE",3],
  ["passthru(","RCE",3],
  ["$_get[","RCE",2], ["$_post[","RCE",2], ["$_request[","RCE",2],
];
for (const m of [";","|","&","`",">"])
  for (const c of ["cat ","ls ","whoami ","wget ","curl ","nc ","bash ","sh "])
    _KW.push([m + c, "CMDI", 3]);

export const KEYWORDS = _KW.slice();

// ---------------------------------------------------------------------------
// Aho-Corasick automaton — satu pass O(n), kebal ReDoS.
// ---------------------------------------------------------------------------
export class AhoCorasick {
  constructor() {
    this.goto = [new Int32Array(256).fill(-1)]; // transisi (tabel lengkap)
    this.fail = [0];
    this.out  = [[]];                           // keyword index per node
    this.outLink = [0];                         // fail-node terdekat dgn keyword
    this.metaKey = [];
  }
  insert(text, category, score) {
    const s = text.toLowerCase();
    let cur = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      let n = this.goto[cur][c];
      if (n < 0) {
        this.goto.push(new Int32Array(256).fill(-1));
        this.fail.push(0);
        this.out.push([]);
        this.outLink.push(0);
        n = this.goto.length - 1;
        this.goto[cur][c] = n;
      }
      cur = n;
    }
    this.metaKey.push({ text: s, category, score });
    this.out[cur].push(this.metaKey.length - 1);
  }
  build() {
    const q = [];
    for (let c = 0; c < 256; c++) {
      const v = this.goto[0][c];
      if (v >= 0) { this.fail[v] = 0; q.push(v); }
      else        this.goto[0][c] = 0;
    }
    while (q.length) {
      const u = q.shift();
      const f  = Math.max(this.fail[u], 0);
      this.outLink[u] = this.out[f].length ? f : this.outLink[f];
      for (let c = 0; c < 256; c++) {
        const v = this.goto[u][c];
        if (v >= 0) {
          let ff = this.fail[u];
          while (ff >= 0 && this.goto[ff][c] < 0) ff = this.fail[ff];
          this.fail[v] = ff < 0 ? 0 : this.goto[ff][c];
          q.push(v);
        } else {
          this.goto[u][c] = u === 0 ? 0 : this.goto[this.fail[u]][c];
        }
      }
    }
  }
  // scan; cb(keyIndex) dipanggil utk SETIAP keyword yg match (termasuk suffix)
  scan(text, cb) {
    let cur = 0;
    const s = String(text);
    for (let i = 0; i < s.length; i++) {
      cur = this.goto[cur][s.charCodeAt(i)];
      for (let v = cur; v > 0; v = this.outLink[v])
        for (let k = 0; k < this.out[v].length; k++) cb(this.out[v][k]);
    }
  }
}

// Automaton default yang sudah di-build (dibuat sekali, dipakai berulang)
export function buildDefaultAutomaton() {
  const ac = new AhoCorasick();
  for (const [t, cat, sc] of _KW) ac.insert(t, cat, sc);
  ac.build();
  return ac;
}

// ---------------------------------------------------------------------------
// Normalisasi ringan (state-machine decode canonical)
// ---------------------------------------------------------------------------
function isHex(c) {
  return (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
}
function hexVal(c) {
  if (c >= "0" && c <= "9") return c.charCodeAt(0) - 48;
  if (c >= "a" && c <= "f") return c.charCodeAt(0) - 87;
  return c.charCodeAt(0) - 55;
}
function normalizeOnce(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "%" && i + 2 < s.length && isHex(s[i + 1]) && isHex(s[i + 2])) {
      out += String.fromCharCode((hexVal(s[i + 1]) << 4) | hexVal(s[i + 2]));
      i += 2;
    } else if (ch === "+") {
      out += " ";
    } else {
      out += ch;
    }
  }
  return out.toLowerCase();
}

// ---------------------------------------------------------------------------
// Analisis satu payload (sudah di-lowercase oleh pemanggil) -> skor & matches
// ---------------------------------------------------------------------------
export function classifyText(text, ac) {
  ac = ac || buildDefaultAutomaton();
  const result = { score: 0, matches: [], suspicious: false };
  const add = (category, name, score) => {
    result.matches.push({ category, name, score });
    result.score += score;
  };

  // struktur abnormal pada teks mentah (lowercase sudah dilakukan pemanggil)
  let enc = 0;
  for (let i = 0; i + 2 < text.length; i++)
    if (text[i] === "%" && isHex(text[i + 1]) && isHex(text[i + 2])) enc++;
  const hasEnt = text.includes("&#");
  const hasUni = text.includes("\\u");
  let gotEnc = false;
  if (enc >= 2 || hasEnt || hasUni) { add("STRUCT", "ENCODING", SCORE.ENCODING); gotEnc = true; }
  if (text.includes("\0")) add("STRUCT", "NULL_BYTE", SCORE.NULL_BYTE);

  // decode sampai canonical (max 8 pass); tiap transformasi = +2 ENCODING
  let norm = text;
  for (let p = 0; p < 8; p++) {
    const nxt = normalizeOnce(norm);
    if (nxt === norm) break;
    if (!gotEnc) { add("STRUCT", "ENCODING", SCORE.ENCODING); gotEnc = true; }
    norm = nxt;
  }
  let quote = 0;
  for (let i = 0; i < norm.length; i++) if (norm[i] === "'") quote++;
  if (quote >= 6) add("STRUCT", "QUOTE_RUN", SCORE.QUOTE_RUN);

  // fast match Aho-Corasick
  ac.scan(norm, (ki) => {
    const m = ac.metaKey[ki];
    add(m.category, m.text, m.score);
  });

  result.suspicious = result.score >= SCORE.THRESHOLD;
  return result;
}

// ---------------------------------------------------------------------------
// Analisis penuh request (method, path+query, user-agent, body)
// ---------------------------------------------------------------------------
export function inspectRequest(method, urlPath, userAgent, body) {
  const ac = buildDefaultAutomaton();
  const pieces = [
    (method + " " + urlPath).toLowerCase(),
    (userAgent || "").toLowerCase(),
    (body || "").toLowerCase(),
  ];
  let score = 0;
  const matches = [];
  for (const piece of pieces) {
    if (!piece || !piece.trim()) continue;
    const r = classifyText(piece, ac);
    score += r.score;
    for (const m of r.matches) matches.push(m);
  }
  return { score, matches, suspicious: score >= SCORE.THRESHOLD };
}
