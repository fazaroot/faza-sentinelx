# Sentinel WAF — Vercel Edge Edition

Firewall **layer-7 (edge)** untuk aplikasi di **Vercel**. Meski kernel Android /
UserLAnd / PRoot mengunci NFQUEUE (netfilter), logika firewall ini **tetap
aktif di cloud** (Edge Runtime Vercel), persis pola Vercel Firewall / CF Workers.

> Jujur: ini menginspeksi **request HTTP** (path/query/header/body). Bukan L3/L4;
> untuk blokir berbasis IP/paket mentah yang sebenarnya tetap butuh gateway
> ber-netfilter (VPS + VPN). Edge WAF & engine C++ bersifat komplementer.

## Isi folder

```
vercel-waf/
├── src/wafcore.mjs      # engine WAF: Aho-Corasick + anomaly scoring + decode
├── src/ratelimit.mjs    # rate limiter sliding-window per-IP
├── middleware.mjs        # Vercel Edge Middleware (WAF + rate limit + admin API)
├── dash.mjs              # logika dashboard (dipakai dashboard-edge.html)
├── dashboard-edge.html   # dashboard web <-> Edge API
├── self-test.mjs         # test wafcore
└── self-test-edge.mjs    # test middleware + ratelimit
```

## Fitur

1. **WAF L7** - inspeksi path+query, UA, body; skor anomali >= threshold -> **403**.
   Skoring sama dengan engine C++ (`or 1=` +3, `union select`/`jndi:` +5, dst).
2. **Rate limiting per-IP** - deteksi IP dari header proxy, sliding-window per
   detik; lewat limit -> **429 + Retry-After**.
3. **Admin API** (butuh token):
   - `GET  /__waf/config`  -> threshold, skala skor, rate-limit, bypass
   - `GET  /__waf/status`  -> IP kini + counter rate (per-instance)
   - `POST /__waf/scan`    -> uji payload tanpa deploy (balik verdict+skor+matches)

## Env (set di Vercel)

| Variable | Default | Fungsi |
|---|---|---|
| `WAF_ADMIN_TOKEN` | `sentin-demo` | token admin API (dashboard) |
| `WAF_RATE_LIMIT` | 60 | request max per IP per window |
| `WAF_RATE_WINDOW_MS` | 60000 | panjang window (ms) |

## Deploy & pengujian

```bash
cp -r vercel-waf /path/to/project/
cd vercel-waf
node self-test.mjs          # wafcore PASS=13
node self-test-edge.mjs     # middleware + ratelimit PASS=14
vercel dev
vercel deploy
```

## Dashboard

Buka `dashboard-edge.html` di app yang sudah deploy, masukkan token admin.
Di batas atau preset berisi payload scanner.

Contoh curl API scan:

```bash
curl -s -X POST "$BASE/__waf/scan?token=sentin-demo" \
  -H "content-type: application/json" \
  -d '{"path":"/login?user=%27or%201=1","body":""}'
# -> {"verdict":"BLOCK","score":5,...}
```

## Batasan jujur

- **Edge stateless**: counter rate-limit konsisten hanya dalam satu instance;
  cross-instance butuh store eksternal (`@vercel/kv`/Upstash).
- **Body dibaca sekali** lalu didorong ulang ke app.
