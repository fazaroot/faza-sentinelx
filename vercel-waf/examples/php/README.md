# Integrasi Sentinel Edge WAF ↔ Project PHP

Ada **3 pola** integrasi, dari paling kuat ke paling simpel:

---

## Pola A — WAF Gateway (paling kuat): Vercel mem-proxy ke server PHP kamu

Semua trafik lewat Edge WAF dulu (WAF + rate-limit + GeoIP + whitelist),
yang lolos diteruskan (proxy) ke hosting PHP kamu — request **tidak pernah
genit** sampai lolos WAF.

1. Edit `vercel-waf/vercel.json`, tambahkan rewrite ke host PHP kamu:

```json
{
  "version": 2,
  "framework": null,
  "rewrites": [
    { "source": "/",            "destination": "/dashboard-edge.html" },
    { "source": "/(.*)",        "destination": "https://php-host-kamu.com/$1" }
  ]
}
```

2. Deploy (push → CI otomatis deploy).
3. Point domain kamu ke Vercel (CNAME), bukan ke hosting PHP.

PHP kamu cukup baca header `x-sentinel-ip` untuk IP asli:

```php
$ip = $_SERVER['HTTP_X_SENTINEL_IP'] ?? $_SERVER['REMOTE_ADDR'];
```

⚠️ Catatan: `x-sentinel-ip` berasal dari `x-vercel-forwarded-for`; kalau ada
client nakal set header itu sendiri, validasi juga `x-forwarded-for` chain.

---

## Pola B — Client PHP (paling simpel): PHP memanggil API WAF

Tanpa ubah infrastruktur — PHP kamu memvalidasi payload via `POST /__waf/scan`.

```php
require_once __DIR__.'/sentinel-waf.php';
SentinelWaf::configure(
    baseUrl: 'https://sentinel-edge-waf.vercel.app',
    token:   getenv('SENTINEL_WAF_TOKEN'),
    strict:  false            // true = fail-closed
);
SentinelWaf::guard();         // taruh PALING ATAS index.php / front controller
```

File: `sentinel-waf.php` (client), `demo-login.php` (demo jalan).

**.htaccess (Apache) — auto-apply ke semua request tanpa edit tiap file:**

```apache
<IfModule mod_php.c>
  php_value auto_prepend_file /absolute/path/sentinel-guard.php
</IfModule>
```

`sentinel-guard.php`:
```php
<?php
require_once __DIR__.'/sentinel-waf.php';
SentinelWaf::configure(
    baseUrl: getenv('SENTINEL_WAF_URL'),
    token:   getenv('SENTINEL_WAF_TOKEN')
);
SentinelWaf::guard();
```

**Nginx** (fastcgi): set `fastcgi_param SENTINEL_WAF_URL ...` lalu pakai
`auto_prepend_file` di `php.ini`.

---

## Pola C — Hybrid (rekomendasi produksi)

Pola A (edge proxy) **+** Pola B (guard di PHP) sebagai lapis kedua.
Kalau attacker berhasil lewat edge (mis. via origin langsung), PHP tetap
melindungi diri.

---

## Env yang perlu diset di server PHP

```bash
SENTINEL_WAF_URL=https://sentinel-edge-waf.vercel.app
SENTINEL_WAF_TOKEN=<token admin WAF>   # /__waf/scan butuh ini
SENTINEL_WAF_STRICT=0                  # 1 = fail-closed
```

## Test cepat

```bash
# dari CLI (scan endpoint):
curl -X POST "https://sentinel-edge-waf.vercel.app/__waf/scan?token=$SENTINEL_WAF_TOKEN" \\
  -H 'content-type: application/json' \\
  -d '{"path":"/login?user=%27%20OR%201=1--","method":"GET"}'
# -> {"verdict":"BLOCK","score":5,...}

# demo lokal:
php -S localhost:8080
# buka http://localhost:8080/demo-login.php
# login user: admin' OR 1=1--  -> 403 WAF_BLOCKED
```
