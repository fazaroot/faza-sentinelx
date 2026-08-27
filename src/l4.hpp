#pragma once
// ============================================================================
// Deep inspection helpers v2.3:
//   - splitHttp       : pisah request HTTP jadi section (line/UA/body)
//                       biar WAF inspeksi section relevan saja (kurangi FP)
//   - composeForWaf   : rangkai string terbaik untuk discan
//   - FlowAssembler   : reassembly payload TCP per-alur. Tanpa ini, payload
//                       dipecah jadi 2 paket ("UNIO"+"N SELECT") lolos karena
//                       tiap paket discan sendirian
//   - tcpFlagAnomaly  : deteksi stealth scan L4 (NULL/XMAS/kombinasi ilegal)
//                       cuma baca 1 byte flags, murah, tanpa payload
//   - extractTlsSni   : ambil hostname dari TLS ClientHello (plaintext)
// ============================================================================

#include <string>
#include <cstring>
#include <cstdint>
#include <unordered_map>
#include <chrono>

// ---------------------------------------------------------------------------
// HTTP splitting
// ---------------------------------------------------------------------------
struct HttpSections {
    bool        isHttp      = false;
    std::string requestLine; // "GET /path?q=x HTTP/1.1"
    std::string uri;         // "/path?q=x"
    std::string userAgent;
    std::string body;
};

inline HttpSections splitHttp(const char* p, int n) {
    HttpSections out;
    if (!p || n < 8) return out;
    static const char* METHODS[] =
        {"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "};
    bool looksHttp = false;
    for (const char* m : METHODS) {
        size_t ml = std::strlen(m);
        if (n >= static_cast<int>(ml) && std::memcmp(p, m, ml) == 0) { looksHttp = true; break; }
    }
    if (!looksHttp) return out;

    out.isHttp = true;

    // cari akhir blok header "\r\n\r\n"
    int headEnd = -1;
    for (int i = 0; i + 3 < n; i++) {
        if (p[i] == '\r' && p[i+1] == '\n' && p[i+2] == '\r' && p[i+3] == '\n') { headEnd = i; break; }
    }
    int headLen = (headEnd >= 0) ? headEnd : n; // header belum lengkap -> pakai semua

    // request line = sampai CRLF pertama
    int lineEnd = 0;
    while (lineEnd < headLen && p[lineEnd] != '\r' && p[lineEnd] != '\n') lineEnd++;
    out.requestLine.assign(p, lineEnd);

    // URI = token kedua pada request line
    size_t sp1 = out.requestLine.find(' ');
    if (sp1 != std::string::npos) {
        size_t sp2 = out.requestLine.find(' ', sp1 + 1);
        if (sp2 != std::string::npos) out.uri = out.requestLine.substr(sp1 + 1, sp2 - sp1 - 1);
    }

    // User-Agent (kalau ada) — header lain dianggap noise
    static const char UA[] = "user-agent:";
    for (int i = lineEnd; i + static_cast<int>(sizeof(UA)) - 1 < headLen; i++) {
        if (p[i] == '\n' &&
            strncasecmp(p + i + 1, UA, sizeof(UA) - 1) == 0) {
            int s = i + 1 + static_cast<int>(sizeof(UA)) - 1;
            while (s < headLen && (p[s] == ' ' || p[s] == '\t')) s++;
            int e = s;
            while (e < headLen && p[e] != '\r' && p[e] != '\n') e++;
            out.userAgent.assign(p + s, e - s);
            break;
        }
    }

    if (headEnd >= 0 && n > headEnd + 4) out.body.assign(p + headEnd + 4, n - headEnd - 4);
    return out;
}

// Rangkai bagian paling relevan untuk dipindai. Header statik (Cookie acak,
// Accept-Encoding base64, dll) dibiarkan keluar supaya false positive turun,
// tapi request line, User-Agent, dan body tetap tercakup penuh.
inline std::string composeForWaf(const HttpSections& s, const std::string& raw) {
    if (!s.isHttp) return raw;
    std::string out = s.requestLine;
    out += "\n";
    out += s.userAgent;
    out += "\n";
    out += s.body;
    return out.empty() ? raw : out;
}

// ---------------------------------------------------------------------------
// FlowAssembler: reassembly payload TCP per alur (anti "payload-splitting")
// ---------------------------------------------------------------------------
class FlowAssembler {
public:
    // Tambah segmen baru ke alur `key`, lalu kembalikan WINDOW yang harus
    // diinspeksi: data segmen + sedikit ekor buffer sebelumnya (overlap),
    // supaya signature yang terpotong tepat di batas paket tetap cocok.
    // CATATAN aman-thread: dipanggil dari callback NFQUEUE yang single-thread.
    const std::string& append(const std::string& key, const char* seg, int len,
                              int maxBuf = 65536, int overlap = 1024) {
        auto now = std::chrono::steady_clock::now();
        pruneExpired(now);

        Flow& f = flows_[key];
        f.last = now;
        if (len <= 0) { window_.clear(); return window_; }

        // Guard memori: buffer nyaris melebihi batas -> buang isi lama,
        // prioritas ketersediaan layanan daripada kehabisan RAM.
        if (static_cast<int>(f.buf.size()) + len > maxBuf) f.buf.clear();

        int start = (overlap < static_cast<int>(f.buf.size()))
                        ? static_cast<int>(f.buf.size()) - overlap : 0;
        window_.assign(f.buf, start, std::string::npos);
        window_.append(seg, len);
        f.buf.append(seg, len);
        return window_;
    }

    void erase(const std::string& key) { flows_.erase(key); }
    size_t size() { return flows_.size(); }

private:
    struct Flow { std::string buf; std::chrono::steady_clock::time_point last; };

    void pruneExpired(std::chrono::steady_clock::time_point now) {
        for (auto it = flows_.begin(); it != flows_.end(); ) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                           now - it->second.last).count();
            if (age > 30) it = flows_.erase(it);
            else ++it;
        }
    }

    std::unordered_map<std::string, Flow> flows_;
    std::string window_; // scratch reusable
};

// ---------------------------------------------------------------------------
// Stealth scan L4: cukup baca 1 byte flags (offset 13 header TCP)
// ---------------------------------------------------------------------------
inline const char* tcpFlagAnomaly(uint8_t flags) {
    constexpr uint8_t FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08,
                      ACK = 0x10, URG = 0x20;
    (void)ACK;
    if ((flags & (SYN | FIN)) == (SYN | FIN)) return "ILLEGAL_SYN_FIN"; // selalu hostile
    if ((flags & (SYN | RST)) == (SYN | RST)) return "ILLEGAL_SYN_RST";
    if ((flags & (FIN | RST)) == (FIN | RST)) return "ILLEGAL_FIN_RST";
    if (flags == 0)                           return "NULL_SCAN";       // nmap -sN
    if ((flags & (FIN | PSH | URG)) == (FIN | PSH | URG)) return "XMAS_SCAN"; // nmap -sX
    return nullptr;
}

// ---------------------------------------------------------------------------
// TLS ClientHello -> SNI hostname (toleran truncation, aman out-of-bounds)
// ---------------------------------------------------------------------------
inline bool extractTlsSni(const uint8_t* d, int n, std::string& host) {
    if (!d || n < 6) return false;
    if (d[0] != 0x16 || d[1] != 0x03) return false;          // record handshake TLS
    if (d[5] != 0x01) return false;                          // tipe ClientHello
    int pos = 43;                                            // lewati fixed field
    auto need = [&](int k) { return pos + k <= n; };

    if (!need(1)) return false;
    int sidLen = d[pos]; pos += 1 + sidLen;                  // session id
    if (!need(2)) return false;
    int csLen = (d[pos] << 8) | d[pos + 1]; pos += 2 + csLen;// cipher suites
    if (!need(1)) return false;
    int compLen = d[pos]; pos += 1 + compLen;                // compression methods

    while (need(4)) {
        int type = (d[pos] << 8) | d[pos + 1];
        int len  = (d[pos + 2] << 8) | d[pos + 3];
        pos += 4;
        if (type == 0 && len >= 3) {                         // extension server_name
            int ep = pos + 2;                                // lewati list length
            if (ep + 3 > n || d[ep] != 0) return false;      // bukan host_name entry
            int hl = (d[ep + 1] << 8) | d[ep + 2];
            if (hl <= 0 || ep + 3 + hl > n) return false;
            host.assign(reinterpret_cast<const char*>(d) + ep + 3, hl);
            return true;
        }
        pos += len;                                          // lanjut extension berikutnya
    }
    return false;
}
