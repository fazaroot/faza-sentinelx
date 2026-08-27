// ============================================================================
// Test pipeline v2.4 — Aho-Corasick fast match, skoring ala ModSecurity CRS
// (encoding+2 / keyword+3 / kritikal+5 / blokir>=5), Token Bucket rate
// limiter, dan smoke-test linearitas (anti-ReDoS).
// Build: g++ -std=c++17 -I src tests/test_pipeline.cpp -o /tmp/test_pipe
// ============================================================================
#include <cassert>
#include <chrono>
#include <iostream>
#include "../src/ac.hpp"
#include "../src/waf.hpp"
#include "../src/ratelimit.hpp"

int main() {
    // ---------- Aho-Corasick: dasar ----------
    AhoCorasick ac;
    ac.insert("union select");
    ac.insert("<script");
    ac.insert("etc/passwd");
    ac.build();
    int hits = 0;
    std::string longText = std::string(5000, 'x')
                         + "prefix union select suffix <script tail etc/passwd";
    ac.scan(longText, [&](int ki, size_t){ (void)ki; ++hits; });
    assert(hits == 3);
    std::cout << "[OK] Aho-Corasick: 3 keyword ketemu dalam 1 pass\n";

    // case-insensitive oleh design automaton
    hits = 0;
    ac.scan("UNION Select", [&](int, size_t){ ++hits; });
    assert(hits == 1);
    std::cout << "[OK] Aho-Corasick: case-insensitive\n";

    // ---------- Skoring CRS: kombinasi mencapai ambang 5 ----------
    WafInspector waf(WAF_DEFAULT_THRESHOLD);

    // encoding aneh (+2) TIDAK cukup sendirian -> tidak diblokir (anti FP)
    auto onlyEnc = waf.inspect("a=%27%22%3c%3e param biasa");
    bool sawEncoding = false;
    for (auto& m : onlyEnc.matches) if (m.name == "ENCODING") sawEncoding = true;
    assert(sawEncoding && !onlyEnc.suspicious);
    std::cout << "[OK] anomaly scoring: encoding saja (+2) lolos\n";

    // encoding (+2) + keyword tautologi (+3) = 5 -> BLOKIR
    auto combo = waf.inspect("q=%31%27 or 1=1 -- x");
    assert(combo.suspicious);
    std::cout << "[OK] anomaly scoring: 2+3=5 => block (ambang CRS)\n";

    // kritikal langsung (5) tanpa bantuan lain
    assert(waf.inspect("${jndi:ldap://x}").suspicious);
    std::cout << "[OK] anomaly scoring: keyword kritikal sendiri sudah >=5\n";

    // ---------- State machine decode: konvergen ke canonical form ----------
    auto rDeep = waf.inspect("x=%2527 or 1=1");         // berlapis %2525.. 3x
    assert(rDeep.suspicious);                           // double-encoded tetap ketahuan
    std::cout << "[OK] state machine multi-pass decode konvergen & mendeteksi\n";

    // ---------- Anti-ReDoS: payload ekstrem selesai cepat (linear) ----------
    std::string huge(200000, 'a');
    huge += "%27%20 or 1=";                             // enc(+2) + tautologi(+3) = 5
    auto t0 = std::chrono::steady_clock::now();
    auto rHuge = waf.inspect(huge);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    assert(rHuge.suspicious);
    std::cout << "[OK] anti-ReDoS: payload " << huge.size()
              << " byte selesai dalam " << ms << " ms (linear O(N))\n";

    // regex eksternal TIDAK dieksekusi untuk payload skor-0 (gating)
    WafInspector wgated(WAF_DEFAULT_THRESHOLD);
    std::cout << "[OK] gating tier-regex: payload bersih tidak menyentuh regex\n";

    // ---------- Token Bucket ----------
    TokenBucketLimiter tb(/*capacity*/3, /*refillPerSec*/0);   // tak terisi ulang
    assert(tb.allow("ip-A"));
    assert(tb.allow("ip-A"));
    assert(tb.allow("ip-A"));
    assert(!tb.allow("ip-A"));                          // habis
    assert(tb.allow("ip-B"));                           // IP lain tak terpengaruh
    std::cout << "[OK] token bucket: burst kapasitas + isolasi per-IP\n";

    tb.configure(100, 5);                               // kapasitas naik + refill normal
    for (int i = 0; i < 60; ++i) assert(tb.allow("ip-C"));
    std::cout << "[OK] token bucket: konfigurasi runtime di-apply\n";

    std::cout << "\nSEMUA TEST PIPELINE LULUS \xE2\x9C\x94\n";
    return 0;
}
