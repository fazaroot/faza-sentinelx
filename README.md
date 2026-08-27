# Sentinel Firewall Engine

Engine firewall userland pakai C++ + NFQUEUE (Ubuntu). Buka Unix socket di
`/run/sentinel.sock` supaya backend dashboard bisa baca stats/rules dan
kirim command tambah/hapus rule.

## 1. Install dependency (Ubuntu)

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config \
    libnetfilter-queue-dev libnfnetlink-dev iptables
```

## 2. Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

Hasil binary: `build/sentinel-firewall`

## 3. Arahkan traffic ke NFQUEUE (wajib sebelum jalanin engine)

```bash
sudo iptables -I INPUT  -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
```

> Kalau salah setup rule iptables ini bisa bikin kamu ke-lockout dari SSH.
> Test dulu di VM/local sebelum pasang di server produksi. Siapkan akses
> console cadangan (bukan cuma SSH) buat jaga-jaga.

## 4. Jalankan engine (butuh root karena akses raw netfilter)

```bash
sudo ./build/sentinel-firewall 0
```

Output normal:
```
[+] Unix socket server siap di /run/sentinel.sock
[+] Engine aktif, mendengarkan NFQUEUE #0
```

## 5. Test manual via socket (tanpa dashboard dulu)

```bash
echo "GET_STATS" | socat - UNIX-CONNECT:/run/sentinel.sock
echo "GET_RULES" | socat - UNIX-CONNECT:/run/sentinel.sock
echo "ADD_RULE 10.0.0.0/8|TCP|8080|block" | socat - UNIX-CONNECT:/run/sentinel.sock
```

(install socat kalau belum ada: `sudo apt install socat`)

## 6. Bersihkan iptables kalau mau stop testing

```bash
sudo iptables -D INPUT  -j NFQUEUE --queue-num 0
sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0
```

## v2 — engine sekarang ala ModSecurity + LiteSpeed mod_evasive

**Anomaly scoring (bukan block di match pertama)**
Dulu WAF berhenti begitu nemu 1 signature cocok. Sekarang tiap payload
dicek ke *semua* signature, tiap match punya bobot skor (3/5/6/7/8
tergantung severity), skor diakumulasi, dan paket baru diblokir kalau
skor total ≥ threshold (default 8, diatur di `WafInspector g_waf(8)`
pada `main.cpp`). Ini persis prinsip **anomaly scoring** di ModSecurity
Core Rule Set — mengurangi false positive dibanding block-di-match-pertama.

**Decode evasion**
Payload dinormalisasi dulu (decode `%XX`, `+`→spasi, lowercase) sebelum
dicocokkan ke signature, supaya percobaan bypass sederhana kayak `%27`
buat kutip satu atau `UNI%4fN` buat "UNION" tetap kedeteksi.

**Signature diperluas**: SQLi, XSS, Path Traversal (`../../etc/passwd`),
Command Injection (`; cat /etc/passwd`), indikasi LFI/RFI (`php://filter`,
remote include).

**Temporary ban list (`banlist.hpp`) — gaya fail2ban / mod_evasive**
Begitu IP ketahuan WAF atau anomaly, IP itu masuk ban list sementara
(default: WAF 5 menit, flood 1 menit, port scan 5 menit). Selama masa
ban, semua paket dari IP itu langsung **DROP tanpa perlu diinspeksi
ulang** — jauh lebih ringan buat CPU dibanding scan payload tiap paket.
Residivis (IP yang kena ban berkali-kali) durasi banned-nya eskalasi
otomatis (2x, 3x, ... maksimal 6x lipat).

## Lapis deteksi (rule → ban check → WAF scoring → anomaly)

1. **Fast path ban check** — kalau IP lagi di-ban, langsung drop, skip semua pengecekan lain.
2. **Rule statis** (`rules.hpp`) — cocokkan IP/CIDR, protokol, port.
3. **WAF scoring** (`waf.hpp`) — kalau lolos rule dan ada payload HTTP,
   hitung skor anomaly dari semua signature yang match. **Catatan:** cuma
   efektif untuk HTTP plain (port 80); HTTPS terenkripsi di layer TCP,
   perlu reverse proxy TLS-terminating kalau mau inspeksi HTTPS.
4. **Anomaly detection** (`anomaly.hpp`) — sliding window per-IP (10
   detik): >15 port berbeda → port scan; >200 paket → flood.

Field `reason` di setiap event log sekarang bisa berisi: `RULE`,
`BANNED`, `WAF:score12:SQLI:UNION_SELECT+SQLI:SQL_COMMENT`,
`ANOMALY:PORT_SCAN`, dst.

**Batasan yang jujur perlu diketahui:**
- Signature berbasis regex, threshold scoring masih perlu di-tuning
  sesuai traffic asli kamu (mulai dari log dulu, jangan langsung block
  agresif di produksi).
- Decode evasion baru single-layer (satu kali percent-decode) — belum
  menangani double-encoding berlapis atau unicode overlong.
- Anomaly & ban list stateful in-memory per proses, reset saat restart.
- Ini starter/pembelajaran, bukan pengganti ModSecurity/LiteSpeed WAF
  production yang sudah diuji bertahun-tahun terhadap traffic nyata.

## Command socket yang tersedia

| Command | Contoh | Balasan |
|---|---|---|
| `GET_STATS` | `GET_STATS` | JSON total paket, blocked, jumlah rule |
| `GET_RULES` | `GET_RULES` | JSON array semua rule |
| `ADD_RULE`  | `ADD_RULE 10.0.0.0/8\|TCP\|8080\|block` | `{"ok":true,"id":5}` |
| `DEL_RULE`  | `DEL_RULE 5` | `{"ok":true}` |
| `GET_BANS`  | `GET_BANS` | JSON array IP yang lagi di-ban sementara + sisa waktu |
| `UNBAN`     | `UNBAN 45.33.12.90` | `{"ok":true}` — cabut ban manual sebelum expired |
| `BAN`       | `BAN 203.0.113.7 600` | ban manual dari dashboard, durasi opsional (default 300 dtk) |
| `GET_WHITELIST` | `GET_WHITELIST` | JSON array IP/CIDR terpercaya |
| `ADD_WHITELIST` | `ADD_WHITELIST 10.8.0.0/24` | tambah trusted IP — lewati WAF/anomaly/auto-ban |
| `DEL_WHITELIST` | `DEL_WHITELIST 10.8.0.0/24` | hapus dari whitelist |
| `SET_WAF_THRESHOLD` | `SET_WAF_THRESHOLD 12` | ubah ambang skor WAF saat runtime, tanpa restart |
| `GET_SNI_BLOCKS` | `GET_SNI_BLOCKS` | JSON array domain TLS yang diblokir via SNI |
| `ADD_SNI_BLOCK` | `ADD_SNI_BLOCK evil.com` | blokir domain TLS — subdomain ikut kena, persisten |
| `DEL_SNI_BLOCK` | `DEL_SNI_BLOCK evil.com` | hapus dari daftar blokir SNI |
| `LOAD_SIGS` | `LOAD_SIGS` | hot reload signature dari `signatures.conf`, tanpa restart |
| `RELOAD`    | `RELOAD` | muat ulang rule+whitelist+SNI dari file state |
| `PING`      | `PING` | health check: `{"ok":true,"pong":true,"version":"2.3"}` |
| `STREAM_LOGS` | `STREAM_LOGS` | koneksi tetap terbuka, tiap paket masuk dikirim sebagai 1 baris JSON |

## v2.2 — fitur canggih tambahan

- **Persistensi state** (`/var/lib/sentinel-firewall/state.conf`) — rule dan
  whitelist otomatis tersimpan tiap perubahan dan dimuat lagi saat engine
  start, jadi konfigurasi tidak hilang saat restart.
- **Whitelist / trusted IP** — IP atau CIDR yang dipercaya dilewati dari
  ban list, WAF scoring, dan anomaly detection (mencegah self-ban kalau
  dashboard/engine ada di host yang sama), tapi tetap tunduk rule statis.
- **Anti double-encoding** — payload di-decode berulang sampai stabil
  (maks 3 pass) supaya bypass seperti `%2527 → %27 → '` tetap kedeteksi.
- **Signature baru**: Log4Shell (`${jndi:`), SSRF metadata cloud
  (`169.254.169.254`, `metadata.google.internal`), protokol berbahaya
  (`gopher://`, `dict://`, `file://`), file sensitif (`etc/shadow`,
  `.env`, `.git/config`), dan pola web shell PHP (`eval/system` +
  `$_POST/$_GET/$_REQUEST[...]`).
- **Port rule fleksibel**: rentang `"1000-2000"` dan daftar `"22,80,443"`.
- **Validasi ADD_RULE** — target harus IPv4/CIDR sah, ditolak kalau ngawur.
- **Inspeksi payload UDP** — signature WAF kini juga jalan untuk UDP,
  bukan cuma TCP.
- **Kontrol runtime**: threshold WAF bisa dituning live via socket tanpa
  recompile; ada `RELOAD` dan `PING` buat integrasi backend.
- **Dashboard**: URL Tailwind CDN yang salah sudah diganti ke Play CDN
  resmi + panel "IP Di-ban Sementara" dengan tombol unban.
- Unit test logika (matcher port/CIDR + WAF) ada di
  `tests/test_logic.cpp`:
  ```bash
  g++ -std=c++17 -I src tests/test_logic.cpp -o /tmp/test_logic && /tmp/test_logic
  ```

## v2.3 — deep inspection: anti-evasion total

**1. Reassembly payload TCP (`l4.hpp: FlowAssembler`)**
Menutup celah paling fatal WAF klasik: payload dipecah lintas paket
(`"...q=uni" + "on select..."`) agar tiap potongan tidak match signature.
Sekarang payload per-alur digabung dulu (window overlap 1KB), cap buffer
64KB per alur, alur idle >30 detik dibuang otomatis.

**2. HTTP-aware inspection (`splitHttp` + `composeForWaf`)**
Hanya request-line, User-Agent, dan body yang dipindai — header statik
(Cookie acak, Accept-Encoding, dsb) dilewatkan supaya false positive turun.
Payload non-HTTP tetap discan raw sebagai fallback.

**3. Normalisasi tambahan**
HTML entity (`&#59;` → `;`), JS unicode escape (`\u0027` → `'`), null-byte
stripping, plus multi-pass decode yang sudah ada. Base64 augment mendeteksi
blob ≥24 karakter dan menempelkan hasil dekodenya ke teks scan — dengan
aturan `'='` tengah = pemisah parameter (bug halus yang justru bikin
payload tersamar lolos kalau tidak ditangani).

**4. Prefilter kinerja**
Payload tanpa karakter khas serangan (`'"<>$;(` dll) dan tanpa run b64
panjang langsung diskip — regex mahal hanya untuk kandidat serangan.

**5. Stealth scan L4 (`tcpFlagAnomaly`)**
NULL/XMAS/SYN-FIN/SYN-RST/FIN-RST didrop cuma dari 1 byte flags header TCP,
plus auto-ban 5 menit. Tidak bisa di-dodge lewat manipulasi payload karena
tidak membaca payload sama sekali.

**6. TLS SNI filtering (`extractTlsSni`)**
ClientHello berisi hostname plaintext: domain berbahaya diblokir walau isi
sesinya terenkripsi, termasuk beacon malware keluar server (OUTPUT chain).
Kelola via socket: `ADD_SNI_BLOCK/DEL_SNI_BLOCK/GET_SNI_BLOCKS`, persisten.

**7. Signature eksternal + hot reload**
File `/var/lib/sentinel-firewall/signatures.conf`, format per baris:
```
# kategori nama skor regex
SIG SQLI CUSTOM_NEW_SQLI 6 union.{0,20}from.{0,20}users
```
Regex invalid ditolak aman. Terapkan tanpa restart: kirim `LOAD_SIGS`.

**8. Reputasi residivis persisten**
Hit count ban disimpan ke `reputation.conf`; IP yang sering kejatan tetap
ingat setelah engine restart — eskalasi durasi bannya lanjut, bukan mulai
dari nol lagi.

**Unit test lengkap**: `tests/test_logic.cpp` (matcher + WAF dasar),
`tests/test_deep.cpp` (reassembly, HTTP split, TCP flags, SNI parser,
entity/unicode/b64 evasion), dan `tests/test_pipeline.cpp` (Aho-Corasick,
skoring CRS, state-machine decode, anti-ReDoS, token bucket):
```bash
g++ -std=c++17 -I src tests/test_logic.cpp   -o /tmp/t1 && /tmp/t1
g++ -std=c++17 -I src tests/test_deep.cpp    -o /tmp/t2 && /tmp/t2
g++ -std=c++17 -I src tests/test_pipeline.cpp -o /tmp/t3 && /tmp/t3
```

## v2.4 — pipeline setara menara el: Aho-Corasick + anomaly scoring CRS

**1. Multi-stage pipeline (early-drop ala Cloudflare)**
Urutan bertingkat kencang, buang paket secepat mungkin di tahap paling depan:
```
trusted → banned → [L3/4 Token-Bucket rate limit] → TCP-flag stealth scan
  → rule statis → SNI filter → L7 inspect (decode→AC→skor) → port-scan anomaly
```
Rate-limit HTTP flood muncul di tahap jaringan (O(1) per paket) — tidak
sempat meninggalkan hot path mahal.

**2. Fast tokenization via Aho-Corasick (`ac.hpp`)**
Meneladani ModSecurity v3 / LiteSpeed: **semua** kata kunci (SQLi, XSS,
traversal, CMDI, dst) dimasukkan ke automaton & di-build sekali; setiap
payload discan dalam **satu pass O(N)** tanpa peduli jumlah keyword.
Transisi tabel lengkap + output-links ⇒ **kebal ReDoS**, biaya scan hanya
bergantung panjang teks, bukan pola/tumpukan.

**3. Anomaly scoring gaya ModSecurity CRS (default blokir ≥ 5)**
```
encoding tak lazim         +2    keyword kritikal (jndi:, etc/passwd...) +5
null-byte / quote-run      +2    keyword SQL/cmd umum                   +3
```
Tidak blokir di match pertama — payload sederhana tetap lolos (anti-HFP),
kombinasi indikator kecil yang mencurigakan otomatis tembus ambang.

**4. Deterministic state machine normalization**
Payload di-decode berulang sampai **canonical form stabil** (loop max 8
pass). Payload yang berubah bentuk ≥1x otomatis menerima +2 ENCODING
— evidence adanya upaya penyamaran, jadi `%2527` double-encoded tetap
ketatangkap. Base64 augment selalu sebelum lowercase (b64 peka kapitalisasi).

**5. Token Bucket rate limiter (`ratelimit.hpp`)**
Bucket per-IP (kapasitas burst + refill/detik), prune idle 10 menit,
tune runtime melalui `SET_RATE_LIMIT <cap> <refill>` / `GET_RATE_LIMIT`.
IP yang flooding otomatis ban 60 detik.

**Kinerja yang diukur**: payload 200.012 byte /**skan < 30 ms** (linear)
walau membawa banyak signature — real-time pada beban jaringan tinggi.

**Batasan jujur yang tersisa:** AC hanya substring (bukan regex kompleks
read) — pola seperti `\bword\b` atau alternation panjang tetap lewat ke
tier regex eksternal (yang ter-gate hanya payload tidak mencurigakan);
state machine belum menangani Unicode overlong / charset transit.

## Langkah selanjutnya

Backend (Kotlin/Ktor, Python FastAPI, Node, bebas) tinggal connect ke
`/run/sentinel.sock`, translate command di atas jadi REST endpoint
(`/api/stats`, `/api/rules`, dst) dan WebSocket buat `STREAM_LOGS`,
lalu itu yang dipanggil dashboard HTML via `$.ajax`.
