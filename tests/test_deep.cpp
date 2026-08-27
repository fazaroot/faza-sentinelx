// ============================================================================
// Test fitur deep-inspection v2.3 — standalone.
// Build: g++ -std=c++17 -I src tests/test_deep.cpp -o /tmp/test_deep
// Mencakup: splitHttp/composeForWaf, FlowAssembler (anti payload-splitting),
// tcpFlagAnomaly, extractTlsSni, normalisasi ekstra WAF (entity/unicode/b64).
// ============================================================================
#include <cassert>
#include <iostream>
#include <vector>
#include "../src/l4.hpp"
#include "../src/waf.hpp"

static std::string u16(unsigned v) {
    return std::string{ static_cast<char>((v >> 8) & 0xff),
                        static_cast<char>(v & 0xff) };
}

// Susunan sesuai spec TLS: [type 0000][ext_len][list_len][type 00][host_len][host]
// Parser membaca list_len sebagai pembatas sebelum entry, jadi extension ini
// dibangun persis mengikuti struktur tersebut (tanpa escape \x00 rancu).
static std::string makeClientHello(const std::string& host) {
    std::string body;
    body += "\x03\x03";                          // client version
    body += std::string(32, '\0');               // random
    body += std::string{'\x00'};                 // session id len = 0
    body += u16(2) + std::string("\x13\x01", 2); // cipher suites len + isi
    body += std::string{'\x01', '\x00'};         // compression methods

    std::string entry = std::string{'\x00'} + u16(host.size()) + host; // host_name entry
    std::string extData = u16(entry.size()) + entry;                   // list_len + entry
    body += u16(0) + u16(extData.size()) + extData;                    // ext server_name

    std::string hs = std::string{'\x01'};
    hs += static_cast<char>((body.size() >> 16) & 0xff);
    hs += static_cast<char>((body.size() >> 8) & 0xff);
    hs += static_cast<char>(body.size() & 0xff);
    hs += body;

    std::string rec = "\x16\x03\x01";
    rec += u16(hs.size());
    rec += hs;
    return rec;
}

int main() {
    // ---------- splitHttp ----------
    std::string req =
        "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: Mozilla/5.0 EvilAgent\r\n"
        "Cookie: c3NzaC1rZXkgcHJpdmF0ZSBlbnRyeQo=\r\n"
        "\r\n"
        "payload-body-here";
    auto sec = splitHttp(req.data(), (int)req.size());
    assert(sec.isHttp);
    assert(sec.uri == "/search?q=<script>alert(1)</script>");
    assert(sec.userAgent == "Mozilla/5.0 EvilAgent");
    assert(sec.body == "payload-body-here");
    std::cout << "[OK] splitHttp (uri/UA/body terpisah)\n";

    // composeForWaf membuang Cookie (noise/FP), tapi line+UA+body tetap ada
    std::string composed = composeForWaf(sec, req);
    assert(composed.find("Cookie") == std::string::npos);
    assert(composed.find("EvilAgent") != std::string::npos);
    assert(composed.find("payload-body-here") != std::string::npos);
    std::cout << "[OK] composeForWaf (header noise dibuang)\n";

    // non-HTTP tetap fallback raw
    assert(!splitHttp("\x00\x01binary-junk-goes-here", 22).isHttp);
    std::cout << "[OK] splitHttp fallback biner\n";

    // ---------- FlowAssembler: payload dipecah lintas paket tetap ketahuan ----------
    FlowAssembler fa;
    std::string s1 = "POST /x HTTP/1.1  q=uni";
    std::string s2 = "on select password from t";
    const std::string& w1 = fa.append("1.2.3.4:555->80", s1.data(), (int)s1.size());
    const std::string& w2 = fa.append("1.2.3.4:555->80", s2.data(), (int)s2.size());
    assert(w2.find("union select") != std::string::npos);
    (void)w1;
    WafInspector waf(WAF_DEFAULT_THRESHOLD);
    assert(waf.inspect(w2).suspicious);      // signature nyambung setelah reassembly
    fa.erase("1.2.3.4:555->80");
    std::cout << "[OK] FlowAssembler anti payload-splitting\n";

    // guard memori: buffer besar dibuang, bukan OOM
    std::string big(70000, 'A');
    fa.append("k", big.c_str(), (int)big.size());
    fa.append("k", big.c_str(), (int)big.size()); // trigger clear
    fa.erase("k");
    std::cout << "[OK] FlowAssembler guard buffer 64KB\n";

    // ---------- tcpFlagAnomaly ----------
    assert(tcpFlagAnomaly(0x03));            // SYN|FIN ilegal
    assert(tcpFlagAnomaly(0x06));            // SYN|RST ilegal
    assert(tcpFlagAnomaly(0x05));            // FIN|RST ilegal
    assert(tcpFlagAnomaly(0x00));            // NULL scan
    assert(tcpFlagAnomaly(0x29));            // XMAS: FIN|PSH|URG
    assert(!tcpFlagAnomaly(0x02));           // SYN murni (handshake sah)
    assert(!tcpFlagAnomaly(0x12));           // SYN|ACK sah
    assert(!tcpFlagAnomaly(0x18));           // PSH|ACK sah
    assert(!tcpFlagAnomaly(0x10));           // ACK sah
    std::cout << "[OK] tcpFlagAnomaly (stealth scan L4)\n";

    // ---------- extractTlsSni ----------
    auto ch = makeClientHello("evil.example.com");
    std::string host;
    assert(extractTlsSni(reinterpret_cast<const uint8_t*>(ch.data()),
                         (int)ch.size(), host));
    assert(host == "evil.example.com");
    std::string truncated = ch.substr(0, 40); // terpotong -> aman false
    assert(!extractTlsSni(reinterpret_cast<const uint8_t*>(truncated.data()),
                          (int)truncated.size(), host));
    std::string notTls = "GET / HTTP/1.1";
    assert(!extractTlsSni(reinterpret_cast<const uint8_t*>(notTls.data()), 15, host));
    std::cout << "[OK] extractTlsSni (host SNI kebaca, truncation aman)\n";

    // ---------- WAF: HTML entity evasion ----------
    auto rEnt = waf.inspect("q=1&#59;drop table users");   // &#59; -> ';'
    bool stacked = false;
    for (auto& m : rEnt.matches) if (m.name == "STACKED_QUERY") stacked = true;
    assert(stacked && rEnt.suspicious);
    std::cout << "[OK] HTML entity decode (evade &#59;) kedeteksi\n";

    // ---------- WAF: JS unicode escape evasion ----------
    auto rUni = waf.inspect("a=\\u0027 OR 1=1 -- x");
    assert(rUni.suspicious);
    std::cout << "[OK] JS unicode decode (\\u0027) kedeteksi\n";

    // ---------- WAF: base64 smuggling ----------
    auto rB64 = waf.inspect("token=dW5pb24gc2VsZWN0IHBhc3MgZnJvbSB1c2Vycw==");
    assert(rB64.suspicious);
    bool unionHit = false;
    for (auto& m : rB64.matches) if (m.name == "UNION_SELECT") unionHit = true;
    assert(unionHit);                        // terdeteksi lewat teks hasil dekode
    std::cout << "[OK] Base64 augment: blob terenkode tetap kedeteksi\n";

    // ---------- prefilter: binary polos lolos cepat ----------
    std::string junk;
    for (int i = 0; i < 100; ++i) junk.push_back((char)(0xA0 + (i % 90)));
    assert(!waf.inspect(junk).suspicious);
    std::cout << "[OK] Prefilter: payload bukan-serangan tidak discan regex\n";

    std::cout << "\nSEMUA TEST DEEP LULUS \xE2\x9C\x94\n";
}
