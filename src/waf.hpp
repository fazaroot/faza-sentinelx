#pragma once
// ============================================================================
// WAF Engine v3 — arsitektur ala ModSecurity v3 / LiteSpeed / Cloudflare:
//
//   Decode (state machine) -> Fast Match (Aho-Corasick O(N))
//     -> Accumulate Score (anomaly scoring) -> Action (Pass/Drop/Ban)
//
// HOT PATH TANPA REGEX BERAT: semua kata kunci disekan automaton
// Aho-Corasick dalam satu pembacaan string (kebal ReDoS, biaya scan tidak
// tergantung jumlah signature). Regex hanya dipakai untuk signature
// EKSTERNAL milik user (signatures.conf) dan hanya dievaluasi ketika
// payload sudah menunjukkan indikasi serangan (skor parsial > 0).
//
// Skala skor gaya CRS (Core Rule Set):
//   keyword SQL/cmd umum        = +3      kritikal (RCE/RCE-classic) = +5
//   encoding/entity tak lazim   = +2      struktur abnormal          = +2
//   Default blokir: total skor >= 5  (Anomalous Threat Level)
// ============================================================================

#include <string>
#include <regex>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <algorithm>

#include "ac.hpp"

constexpr int WAF_DEFAULT_THRESHOLD = 5;

struct WafSignature {
    std::string name;
    std::string category;
    int         score;
    std::regex  pattern;
};

// Satu entri kata kunci Aho-Corasick
struct AcKey {
    std::string text;
    const char* category;
    const char* name;
    int         score;
};

struct WafMatch {
    std::string name;
    std::string category;
    int         score;
};

struct WafResult {
    bool                  suspicious = false; // skor total >= threshold
    int                   totalScore = 0;
    std::vector<WafMatch> matches;
};

class WafInspector {
public:
    explicit WafInspector(int blockThreshold = WAF_DEFAULT_THRESHOLD)
        : threshold_(blockThreshold) {

        // ===================== TABEL KEYWORD AHO-CORASICK =====================
        // Semua keyword di-insert sekali, di-build sekali, lalu SEMUA paket
        // discan satu pass linear. Biaya scan tidak tergantung jumlah keyword.
        auto kw = [this](const char* cat, const char* name, int score,
                         std::initializer_list<const char*> texts) {
            for (const char* t : texts)
                acKeys_.push_back({ t, cat, name, score });
        };

        // ---- SQL Injection ----
        kw("SQLI", "UNION_SELECT",  5, {"union select"});
        kw("SQLI", "OR_TRUE",       3, {"or 1=", "and 1="});
        kw("SQLI", "STACKED_QUERY", 3, {";drop ", ";delete ", ";insert ",
                                        ";update ", ";alter "});
        kw("SQLI", "SLEEP_BENCH",   5, {"sleep(", "benchmark(", "pg_sleep(",
                                        "waitfor delay"});
        kw("SQLI", "INFO_SCHEMA",   3, {"information_schema", "sysobjects",
                                        "syscolumns"});
        kw("SQLI", "XP_CMDSHELL",   5, {"xp_cmdshell"});

        // ---- XSS ----
        kw("XSS", "SCRIPT_TAG",     5, {"<script"});
        kw("XSS", "ONEVENT_ATTR",   3, {"onerror=", "onload=", "onclick=",
                                        "onmouseover=", "onfocus="});
        kw("XSS", "JAVASCRIPT_URI", 3, {"javascript:"});

        // ---- Path Traversal ----
        kw("TRAVERSAL", "DOT_DOT_SLASH", 2, {"../"});
        kw("TRAVERSAL", "ETC_PASSWD",    5, {"etc/passwd"});

        // ---- Command Injection ----
        // meta-char + binary shell umum (";cat ", "|whoami", ...)
        for (const char* meta : {";", "|", "&", "`", ">"})
            for (const char* cmd : {"cat ", "ls ", "whoami ", "wget ",
                                    "curl ", "nc ", "bash ", "sh "})
                acKeys_.push_back({ std::string(meta) + cmd,
                                    "CMDI", "SHELL_META", 3 });

        // ---- LFI / RFI ----
        kw("LFI_RFI", "PHP_WRAPPER", 5, {"php://filter", "php://input",
                                         "data://text"});

        // ---- Eksploit modern / lain-lain ----
        kw("RCE",  "JNDI_LOOKUP",     5, {"jndi:"});              // Log4Shell
        kw("SSRF", "CLOUD_METADATA",  5, {"169.254.169.254",
                                          "metadata.google.internal"});
        kw("SSRF", "DANGEROUS_PROTO", 3, {"gopher://", "dict://", "file://"});
        kw("LEAK", "SENSITIVE_FILE",  5, {"etc/shadow", "proc/self/environ"});
        kw("LEAK", "SENSITIVE_FILE",  3, {".git/config", ".env"});

        // Web shell PHP: eval/system sendiri (+3), plus superglobal (+2)
        // atau encoding aneh (+2) otomatis capai ambang 5.
        kw("RCE", "PHP_EVAL",     3, {"eval(", "assert(", "system(",
                                      "passthru("});
        kw("RCE", "SUPERGLOBALS", 2, {"$_get[", "$_post[", "$_request["});

        for (const auto& k : acKeys_) ac_.insert(k.text);
        ac_.build();
    }

    WafResult inspect(const std::string& rawPayload) const {
        WafResult result;
        if (rawPayload.empty()) return result;

        // ---- Tahap 0: prefilter murah (early-exit traffic sehat) ----------
        if (!looksLikeAttackText(rawPayload)) return result;
        auto record = [&result](const char* cat, const char* name, int score) {
            result.matches.push_back({name, cat, score});
            result.totalScore += score;
        };

        // ---- Tahap 1: struktur abnormal pada payload MENTAH ----------------
        // Encoding tak lazim: banyak %XX sekaligus ATAU entity/unicode escape
        // (indikasi attacker menyembunyikan bentuk asli payload)
        bool hasEnt   = rawPayload.find("&#")  != std::string::npos;
        bool hasUni   = rawPayload.find("\\u") != std::string::npos;
        int  encEvts  = countEncodedEvents(rawPayload);
        bool gotEncoding = false;
        if (encEvts >= 2 || hasEnt || hasUni) {
            record("STRUCT", "ENCODING", 2);
            gotEncoding = true;
        }
        if (rawPayload.find('\x00') != std::string::npos)      // null byte injection
            record("STRUCT", "NULL_BYTE", 2);

        // ---- Tahap 2: Decode — deterministic state machine ----------------
        // decode berulang sampai CANONICAL FORM stabil (fixed point).
        // Payload yang butuh >=1 pass perubahan otomatis dapat poin
        // ENCODING (+2): bentuk mentahnya sengaja disamarkan.
        // augmentWithBase64 dipanggil DI DALAM normalize sebelum lowercase,
        // karena base64 peka kapitalisasi (mengubahnya lebih dulu = sampah).
        std::string normalized = rawPayload;
        for (int pass = 0; pass < 8; pass++) {           // state machine loop
            std::string next = normalize(normalized);
            if (next == normalized) break;               // konvergen = canonical
            if (!gotEncoding) {                          // ada transformasi = evasion attempt
                record("STRUCT", "ENCODING", 2);
                gotEncoding = true;
            }
            normalized = std::move(next);
        }

        // kutip beruntun = abnormal (obfuscation / quote-breaking)
        if (std::count(normalized.begin(), normalized.end(), '\'') >= 6)
            record("STRUCT", "QUOTE_RUN", 2);

        // ---- Tahap 3: Fast Match — Aho-Corasick satu pass O(N) ------------
        ac_.scan(normalized, [&](int ki, size_t) {
            const auto& k = acKeys_[ki];
            record(k.category, k.name, k.score);
        });

        // ---- Tahap 4: regex EKSTERNAL user, hanya bila sudah mencurigakan --
        // Payload bersih TIDAK PERNAH menyentuh regex -> aman dari ReDoS.
        if (result.totalScore > 0 && !signatures_.empty()) {
            for (const auto& sig : signatures_) {
                if (std::regex_search(normalized, sig.pattern))
                    record(sig.category.c_str(), sig.name.c_str(), sig.score);
            }
        }

        // ---- Tahap 5: verdict anomaly threshold ---------------------------
        result.suspicious = result.totalScore >= threshold_;
        return result;
    }
    // Ubah ambang skor saat runtime tanpa restart (via socket SET_WAF_THRESHOLD)
    void setThreshold(int t) { threshold_ = (t >= 1 ? t : 1); }
    int  threshold() const   { return threshold_; }

    // ---- Signature eksternal (dari file config / hot reload LOAD_SIGS) ----
    // Regex tidak valid ditolak (return false) supaya engine tetap jalan.
    bool addExternalSignature(const std::string& category, const std::string& name,
                              int score, const std::string& pattern) {
        try {
            signatures_.push_back({ name, category, score,
                                    std::regex(pattern, std::regex::icase) });
        } catch (...) { return false; }
        ++extCount_;
        return true;
    }

    // Buang semua signature eksternal (sebelum load ulang dari file).
    // Signature internal dari ctor aman karena selalu di paling depan.
    void wipeExternalSignatures() {
        if (firstExternalIdx_ == npos_ || firstExternalIdx_ >= signatures_.size()) return;
        signatures_.clear();
        extCount_ = 0;
    }

    size_t signatureCount() const { return acKeys_.size() + extCount_; }

    // Ringkasan match jadi satu string buat log, contoh: "SQLI:UNION_SELECT+SQLI:SQL_COMMENT"
    static std::string summarize(const WafResult& r) {
        std::ostringstream os;
        for (size_t i = 0; i < r.matches.size(); i++) {
            os << r.matches[i].category << ":" << r.matches[i].name;
            if (i + 1 < r.matches.size()) os << "+";
        }
        return os.str();
    }

private:
    std::vector<WafSignature> signatures_;       // HANYA regex eksternal user
    AhoCorasick               ac_;               // fast match O(N), no-ReDoS
    std::vector<AcKey>        acKeys_;           // metadata per keyword AC
    int                       extCount_ = 0;     // jumlah signature eksternal aktif

    int threshold_;
    static constexpr size_t npos_ = static_cast<size_t>(-1);
    size_t firstExternalIdx_ = npos_; // index signature eksternal pertama

    void add(const std::string& category, const std::string& name, int score, const std::string& pattern) {
        signatures_.push_back({ name, category, score, std::regex(pattern, std::regex::icase) });
    }


    // Hitung kejadian percent-encoding "%XX" pada teks mentah
    static int countEncodedEvents(const std::string& s) {
        int n = 0;
        for (size_t i = 0; i + 2 < s.size(); ++i)
            if (s[i] == '%' && isHex(s[i+1]) && isHex(s[i+2])) ++n;
        return n;
    }

    // Prefilter murah: payload harus memuat karakter khas serangan ATAU run
    // base64 panjang. Selebihnya buang tanpa regex — throughput naik drastis.
    static bool looksLikeAttackText(const std::string& s) {
        bool hasTrigger = false;
        bool lastB64    = false;
        int  b64Run     = 0;
        for (char c : s) {
            if (!hasTrigger) {
                switch (c) {
                    case '\'': case '"': case '<': case '>': case '$':
                    case ';': case '(': case '`': case '%': case '\\':
                    case '{': case '|': case '&': case '=':
                    case '.': case '/':
                        hasTrigger = true;
                }
            }
            bool cur = ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')
                        || c=='+'||c=='/'||c=='=');
            b64Run = cur ? (lastB64 ? b64Run + 1 : 1) : 0;
            lastB64 = cur;
            if (hasTrigger && b64Run >= 24) break; // dua-duanya ketemu, cukup
        }
        return hasTrigger || b64Run >= 24;
    }

    // Normalisasi berlapis (dipanggil multi-pass dari inspect): decode %XX,
    // buang NUL byte, HTML entity (&#39;/&#x27;), JS unicode (\u0027),
    // terakhir lowercase.
    static std::string normalize(const std::string& in) {
        // Pass 1: percent-decode + '+'->spasi + buang null byte (trik parser)
        std::string decoded;
        decoded.reserve(in.size());
        for (size_t i = 0; i < in.size(); i++) {
            if (in[i] == '%' && i + 2 < in.size() && isHex(in[i+1]) && isHex(in[i+2])) {
                int hi = hexVal(in[i+1]), lo = hexVal(in[i+2]);
                decoded += static_cast<char>((hi << 4) | lo);
                i += 2;
            } else if (in[i] == '+') {
                decoded += ' ';
            } else if (in[i] != '\0') {
                decoded += in[i];
            }
        }
        // Pass 2-3: entity & unicode escape
        decoded = decodeEntities(std::move(decoded));
        decoded = decodeJsUnicode(std::move(decoded));

        // Base64 augment WAJIB sebelum lowercase: mendekode blob yang huruf2
        // telah diganti kapitalisasinya menghasilkan byte sampah (base64
        // peka posisi), sehingga deteksi konten tersamar gagal total.
        augmentWithBase64(decoded);

        for (auto& c : decoded) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return decoded;
    }

    static std::string decodeEntities(std::string in) {
        std::string out; out.reserve(in.size());
        for (size_t i = 0; i < in.size();) {
            if (i + 2 < in.size() && in[i] == '&' && in[i+1] == '#') {
                bool hex = (in[i+2] == 'x' || in[i+2] == 'X');
                size_t j = i + (hex ? 3 : 2);
                int val = 0; bool digits = false;
                while (j < in.size() && isHex(in[j])) {   // cocok juga utk desimal
                    digits = true;
                    val = val * (hex ? 16 : 10) + hexVal(in[j]);
                    if (val > 300) break;                 // sanity bound
                    ++j;
                }
                if (digits && j < in.size() && in[j] == ';' && val > 0 && val < 256) {
                    out += static_cast<char>(val);
                    i = j + 1;
                    continue;
                }
            }
            out += in[i]; ++i;
        }
        return out;
    }

    static std::string decodeJsUnicode(std::string in) {
        std::string out; out.reserve(in.size());
        for (size_t i = 0; i < in.size();) {
            if (i + 5 < in.size() && in[i] == '\\' &&
                (in[i+1] == 'u' || in[i+1] == 'U') &&
                isHex(in[i+2]) && isHex(in[i+3]) && isHex(in[i+4]) && isHex(in[i+5])) {
                int v = (hexVal(in[i+2]) << 12) | (hexVal(in[i+3]) << 8) |
                        (hexVal(in[i+4]) << 4) | hexVal(in[i+5]);
                if (v > 0 && v < 256) out += static_cast<char>(v);
                i += 6;                                   // non-latin1: skip saja
                continue;
            }
            out += in[i]; ++i;
        }
        return out;
    }

    // Cari run base64 >= 24 char; kalau hasil dekodenya mayoritas printable
    // ASCII, tempel teks hasil dekode ke ujung buffer yang discan.
    // ATURAN penting: '=' di TENGAH run dianggap PEMISAH (misal "token=<blob>")
    // bukan padding — tanpa ini seluruh "token=blob..." ikut terdecode
    // salah-alaman dan payload tersamar di dalamnya lolos.
    static void augmentWithBase64(std::string& text) {
        auto isB64 = [](char c) {
            return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')
                   || c=='+'||c=='/'||c=='=';
        };
        std::string extra;
        size_t n = text.size(), i = 0;
        auto tryDecode = [&](size_t s, size_t e) -> bool {
            if (e <= s || e - s < 24) return false;
            std::string dec = b64Decode(text.substr(s, e - s));
            if (dec.size() < 6) return false;
            int printable = 0;
            for (char d : dec) if (d >= 32 && d < 127) ++printable;
            if (printable * 10 < static_cast<int>(dec.size()) * 7) return false;
            extra += "\n" + dec;
            return true;
        };

        while (i < n) {
            if (!isB64(text[i])) { ++i; continue; }

            // Kumpulkan batas run: '=' hanya sah sebagai padding penutup
            // (maksimal dua di ekor); sisanya memecah run.
            size_t j = i;
            while (j < n && isB64(text[j])) {
                if (text[j] == '=') {
                    size_t pad = 0;
                    while (j + pad < n && text[j + pad] == '=' && pad < 2) ++pad;
                    bool ending = (j + pad >= n) ||
                                  !isB64(text[j + pad]);         // benar2x akhir run
                    if (ending) { j += pad; break; }
                    break;                                        // '=' tengah -> pecah
                }
                ++j;
            }

            // Run panjang: coba decode mulai offset 0..3 (toleransi prefix
            // mis-align seperti "?q=%3D" atau fragmen path).
            if (j - i >= 24) {
                for (int off = 0; off < 4; ++off) {
                    if (j <= i + static_cast<size_t>(off) + 23) break;
                    if (tryDecode(i + off, j)) break;
                }
            }
            i = (j > i) ? j : i + 1;
        }
        if (!extra.empty()) text += extra;
    }

    static std::string b64Decode(const std::string& s) {
        auto v64 = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        };
        std::string out; out.reserve(s.size() * 3 / 4 + 1);
        int acc = 0, bits = 0;
        for (char c : s) {
            int v = v64(c);
            if (v < 0) continue;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) { bits -= 8; out += static_cast<char>((acc >> bits) & 0xFF); }
        }
        return out;
    }

    static bool isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    static int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    }
};
