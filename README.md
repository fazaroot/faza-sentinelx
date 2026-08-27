# Sentinel Firewall — Unified Engine (C++ + Vercel Edge)

Firewall **layer-3/4/7** hybrid: engine C++ untuk netfilter/NFQUEUE (server/gateway) +
Vercel Edge WAF untuk aplikasi web yang di-deploy di Vercel.

## Arsitektur Gabungan

```
┌─────────────────────────────────────────────────────────────┐
│                      C++ Engine (src/)                       │
│  NFQUEUE / netfilter  →  L3/4 rule + L7 WAF (Aho-Corasick)   │
│  + Anomaly scoring CRS  +  Token Bucket  +  Persist state   │
└─────────────────────────────────────────────────────────────┘
                              ↑
                    (Unix socket /run/sentinel.sock)
                              │
┌─────────────────────────────────────────────────────────────┐
│              Vercel Edge WAF (vercel-waf/)                   │
│  Edge Middleware  →  Rate limit KV  +  GeoIP  +  Whitelist   │
│  + WAF L7 (Aho-Corasick)  +  Admin API / Dashboard           │
└─────────────────────────────────────────────────────────────┘
```

Kedua engine **menggunakan logika inspeksi yang sama** (Aho-Corasick + anomaly
scoring CRS), hanya beda runtime: C++ di kernel/userspace, JS di Edge Vercel.

---

## 📁 Struktur Repo

```
sentinel-firewall/
├── src/                    # C++ engine (NFQUEUE)
│   ├── main.cpp            # entry, NFQUEUE loop, socket server
│   ├── waf.hpp             # WAF core (Aho-Corasick + anomaly scoring)
│   ├── l4.hpp              # L4 helpers (FlowAssembler, TCP flags, SNI)
│   ├── ratelimit.hpp       # Token Bucket (C++)
│   ├── banlist.hpp         # temp ban + reputation persisten
│   ├── anomaly.hpp         # port-scan / flood detector
│   ├── rules.hpp           # rule statis (IP/CIDR/port/proto)
│   └── ac.hpp              # Aho-Corasick automaton (C++)
├── tests/                  # unit test C++
│   ├── test_logic.cpp
│   ├── test_deep.cpp
│   └── test_pipeline.cpp
├── vercel-waf/             # Vercel Edge WAF
│   ├── src/wafcore.mjs     # WAF L7 (Aho-Corasick + scoring)
│   ├── src/ratelimit.mjs   # Rate limiter (KV + fallback lokal)
│   ├── middleware.mjs      # Edge Middleware (WAF + rate + GeoIP + whitelist)
│   ├── dash.mjs            # dashboard logic
│   ├── dashboard-edge.html # dashboard web ↔ Edge API
│   ├── self-test.mjs       # wafcore test
│   ├── self-test-edge.mjs  # middleware + ratelimit test
│   ├── self-test-features.mjs # whitelist/geo/kv test
│   └── dashboard-edge.html # dashboard web
├── dashboard/              # dashboard C++ (mock + real API)
│   └── index.html
├── build/                  # binary C++ (gitignore)
├── CMakeLists.txt
└── README.md
```

---

## 🚀 C++ Engine (NFQUEUE)

### Build & Jalankan

```bash
sudo apt install build-essential cmake pkg-config \
  libnetfilter-queue-dev libnfnetlink-dev iptables socat

mkdir build && cd build
cmake .. && make -j$(nproc)

# setup iptables (WAJIB sebelum jalan)
sudo iptables -I INPUT  -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0

sudo ./sentinel-firewall 0
```

### Socket Commands (via `/run/sentinel.sock`)

| Command | Contoh | Fungsi |
|---|---|---|
| `GET_STATS` | `GET_STATS` | JSON stats |
| `GET_RULES` | `GET_RULES` | list rule |
| `ADD_RULE` | `ADD_RULE 10.0.0.0/8|TCP|80|block` | tambah rule |
| `DEL_RULE` | `DEL_RULE 5` | hapus rule |
| `GET_BANS` | `GET_BANS` | list IP ter-ban |
| `UNBAN` | `UNBAN 1.2.3.4` | cabut ban manual |
| `BAN` | `BAN 1.2.3.4 600` | ban manual 10 menit |
| `GET_WHITELIST` | `GET_WHITELIST` | list trusted IP |
| `ADD_WHITELIST` | `ADD_WHITELIST 10.0.0.0/8` | trusted IP (lewati WAF/anomaly) |
| `DEL_WHITELIST` | `DEL_WHITELIST 10.0.0.0/8` | hapus trusted |
| `SET_WAF_THRESHOLD` | `SET_WAF_THRESHOLD 12` | ubah threshold runtime |
| `GET_SNI_BLOCKS` | `GET_SNI_BLOCKS` | domain TLS diblokir |
| `ADD_SNI_BLOCK` | `ADD_SNI_BLOCK evil.com` | blokir domain TLS |
| `DEL_SNI_BLOCK` | `DEL_SNI_BLOCK evil.com` | hapus block SNI |
| `LOAD_SIGS` | `LOAD_SIGS` | hot reload signature |
| `RELOAD` | `RELOAD` | reload rule+whitelist |
| `PING` | `PING` | health check |
| `STREAM_LOGS` | `STREAM_LOGS` | live log per paket (NDJSON) |

---

## 🌐 Vercel Edge WAF (`vercel-waf/`)

Layer-7 WAF untuk aplikasi yang di-deploy di **Vercel**. Jalan di Edge Runtime.

### Fitur
1. **WAF L7** — inspeksi path+query+UA+body, Aho-Corasick + anomaly scoring CRS ≥5 → **403**
2. **Rate limiting per-IP** — deteksi IP dari `x-vercel-forwarded-for`/`x-vercel-ip`,
   sliding-window via **Upstash/@vercel/kv** (cross-edge konsisten) + fallback lokal.
3. **Whitelist per-IP/CIDR** (`WAF_ALLOWED_IPS`) — anti-lockout admin/self.
4. **GeoIP block by region** (`WAF_BLOCKED_COUNTRIES`) — blokir negara via header `x-vercel-ip-country`.
4. **Admin API** (butuh token):
   - `GET  /__waf/config`  — threshold, skala skor, rate-limit, bypass, whitelist, blockCountries
   - `GET  /__waf/status`  — IP + counter rate per-instance
   - `POST /__waf/scan`    — uji payload tanpa deploy (`verdict`/`score`/`matches`)

### Env (set di Vercel Project Settings)

| Variable | Default | Keterangan |
|---|---|---|
| `WAF_ADMIN_TOKEN` | `sentin-demo` | token admin API |
| `WAF_RATE_LIMIT` | `60` | max req/IP/window |
| `WAF_RATE_WINDOW_MS` | `60000` | panjang window (ms) |
| `WAF_ALLOWED_IPS` | *(kosong)* | whitelist IP/CIDR (anti-lockout) |
| `WAF_BLOCKED_COUNTRIES` | *(kosong)* | negara diblokir via GeoIP |
| `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` | *(auto dari Marketplace)* | rate-limit cross-edge (Upstash Redis; `@vercel/kv` deprecated) |

### Deploy
```bash
# copy folder ke project Vercel
cp -r vercel-waf /path/to/your-vercel-project/

# test lokal
cd vercel-waf && node self-test.mjs && node self-test-edge.mjs && node self-test-features.mjs

vercel dev   # preview
vercel deploy
```

### Dashboard
Buka `dashboard-edge.html` di app Vercel → isi token admin → scanner, status rate limit, config.

### API contoh
```bash
curl -X POST "$BASE/__waf/scan?token=TOKEN" \
  -H 'content-type: application/json' \
  -d '{"path":"/login?user=%27or%201=1","body":""}'
# -> {"verdict":"BLOCK","score":5,"matches":[...]}
```

---

## 🧪 Test Suite

```bash
# C++ engine
cd build && make -j$(nproc)
# tests
g++ -std=c++17 -I ../src ../tests/test_logic.cpp -o /tmp/t && /tmp/t
g++ -std=c++17 -I ../src ../tests/test_deep.cpp -o /tmp/t && /tmp/t
g++ -std=c++17 -I ../src ../tests/test_pipeline.cpp -o /tmp/t && /tmp/t

# Vercel Edge
cd vercel-waf
node self-test.mjs          # PASS=13 (wafcore)
node self-test-edge.mjs     # PASS=14 (middleware + ratelimit)
node self-test-features.mjs # PASS=11 (KV + whitelist + geoip)
```

---

## ⚠️ Batasan Jujur

| Area | Keterbatasan |
|---|---|
| C++ rate limit | Token Bucket in-memory (per process), bukan lintas-proses |
| C++ state | rule/ban/whitelist persist ke disk, cross-restart ✅ |
| Edge rate limit | @vercel/kv/Upstash diperlukan untuk konsistensi lintas-edge |
| Edge stateless | counter per-instance tanpa KV; KV + fallback lokal siap |
| GeoIP | hanya header `x-vercel-ip-country` (bukan full GeoIP database) |
| Regex kompleks | hanya di tier eksternal (digate oleh skor > 0) |
| C++ L3/4 | butuh root + NFQUEUE (tidak jalan di Android/UserLAnd) |


## 📄 Lisensi
MIT — bebas dipakai, dimodifikasi, didistribusikan.

---

> "The best time to plant a tree was 20 years ago. The second best time is
> now. Especially if the tree is a firewall."
