// ============================================================================
// SENTINEL FIREWALL ENGINE
// Userland firewall via NFQUEUE. Menerima paket dari kernel lewat netfilter,
// mencocokkan ke rule, lalu memberi verdict ACCEPT/DROP.
// Juga membuka Unix domain socket supaya backend dashboard bisa:
//   - GET_STATS         -> statistik singkat (JSON)
//   - GET_RULES         -> daftar rule (JSON)
//   - ADD_RULE <json>   -> tambah rule baru
//   - DEL_RULE <id>     -> hapus rule
//   - STREAM_LOGS       -> client akan menerima setiap event verdict (JSON per baris)
// ============================================================================

// Glibc/userspace headers HARUS di-include sebelum header kernel (linux/*,
// libnetfilter_queue) supaya guard kompatibilitas di <linux/libc-compat.h>
// aktif dan definisi struct/IPPROTO_* dari kernel tidak duplikat dengan
// definisi glibc (menghindari error "redefinition of struct in_addr", dll).
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <csignal>
#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <unordered_set>

#include "rules.hpp"
#include "waf.hpp"
#include "ac.hpp"
#include "l4.hpp"
#include "ratelimit.hpp"
#include "anomaly.hpp"
#include "banlist.hpp"

// ---------------------------------------------------------------------------
// State global (disengaja simple untuk skeleton; boleh dibungkus class kalau
// project berkembang)
// ---------------------------------------------------------------------------
static RuleStore       g_rules;
static WafInspector    g_waf(WAF_DEFAULT_THRESHOLD); // threshold skor: bisa diubah runtime via SET_WAF_THRESHOLD
static AnomalyDetector g_anomaly;
static BanList         g_banlist;

// ---- Whitelist / trusted IP (IP server sendiri, monitoring, dst) ----------
// IP yang masuk whitelist TIDAK pernah kena auto-ban dari WAF/anomaly dan
// tidak diinspeksi payload-nya. Tetap tunduk pada rule statis.
static std::unordered_set<std::string> g_whitelist;
static std::mutex                      g_whitelistMtx;

// ---- File state: rule + whitelist dipersist agar survive restart ----------
// Format baris sederhana:
//   R|target|proto|port|action     -> rule firewall
//   W|ip_atau_cidr                 -> whitelist entry
static const char* STATE_DIR  = "/var/lib/sentinel-firewall";
static const char* STATE_PATH = "/var/lib/sentinel-firewall/state.conf";
// Signature tambahan dari file config (bisa di-hot-reload via LOAD_SIGS).
// Format per baris:  SIG <kategori> <nama> <skor> <regex>   (# = komentar)
static const char* SIG_PATH = "/var/lib/sentinel-firewall/signatures.conf";
// Reputasi residivis (ip + total hit) supaya eskalasi ban bertahan restart.
static const char* REP_PATH = "/var/lib/sentinel-firewall/reputation.conf";

static FlowAssembler                   g_flows;     // reassembly payload TCP per alur
static TokenBucketLimiter              g_rate;      // L3/4+L7 token bucket per-IP
static std::unordered_set<std::string> g_sniBlock;  // domain TLS yang diblokir via SNI
static std::mutex                      g_sniMtx;
static std::atomic<uint64_t>           g_flagDrops{0}; // NULL/XMAS/SYN-FIN dst
static std::atomic<uint64_t>           g_sniDrops{0};
static std::atomic<uint64_t>           g_rateBlocked{0}; // token bucket habis
static std::atomic<uint64_t> g_totalPackets{0};
static std::atomic<uint64_t> g_blockedPackets{0};
static std::atomic<uint64_t> g_wafBlocked{0};
static std::atomic<uint64_t> g_anomalyBlocked{0};
static std::atomic<uint64_t> g_banHits{0}; // paket yang di-drop cepat karena IP sudah di-ban
static std::atomic<bool>     g_running{true};

static const char* SOCKET_PATH = "/run/sentinel.sock";

// Daftar file descriptor client yang sedang subscribe STREAM_LOGS
static std::vector<int> g_logSubscribers;
static std::mutex       g_logSubMtx;

// ---------------------------------------------------------------------------
// Util: kirim string ke semua subscriber log (dipanggil dari packet callback)
// ---------------------------------------------------------------------------
void broadcastLog(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_logSubMtx);
    for (auto it = g_logSubscribers.begin(); it != g_logSubscribers.end(); ) {
        ssize_t sent = send(*it, line.c_str(), line.size(), MSG_NOSIGNAL);
        if (sent < 0) {
            close(*it);
            it = g_logSubscribers.erase(it);
        } else {
            ++it;
        }
    }
}

std::string nowTimestamp() {
    auto t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Whitelist / trusted IP
// ---------------------------------------------------------------------------
bool isTrusted(uint32_t srcIpHostOrder) {
    std::lock_guard<std::mutex> lock(g_whitelistMtx);
    for (const auto& entry : g_whitelist)
        if (ipInCidr(srcIpHostOrder, entry)) return true;
    return false;
}

bool whitelistAdd(const std::string& entry) {
    if (!isValidTarget(entry)) return false;
    std::lock_guard<std::mutex> lock(g_whitelistMtx);
    return g_whitelist.insert(entry).second;
}

bool whitelistDel(const std::string& entry) {
    std::lock_guard<std::mutex> lock(g_whitelistMtx);
    return g_whitelist.erase(entry) > 0;
}

std::string whitelistToJson() {
    std::lock_guard<std::mutex> lock(g_whitelistMtx);
    std::ostringstream os;
    os << "[";
    bool first = true;
    for (const auto& e : g_whitelist) {
        if (!first) os << ",";
        os << "\"" << e << "\"";
        first = false;
    }
    os << "]";
    return os.str();
}

size_t whitelistCount() {
    std::lock_guard<std::mutex> lock(g_whitelistMtx);
    return g_whitelist.size();
}

// ---------------------------------------------------------------------------
// SNI blocklist (filtrasi domain TLS tanpa harus dekripsi)
// ---------------------------------------------------------------------------
bool sniIsBlocked(const std::string& host) {
    std::lock_guard<std::mutex> lock(g_sniMtx);
    if (g_sniBlock.count(host)) return true;
    std::string dotDomain;
    for (const auto& d : g_sniBlock) {
        if (host.size() <= d.size() + 1) continue;
        dotDomain = "." + d;
        // subdomain "*.evil.com" ikut kena blokir
        if (host.compare(host.size() - dotDomain.size(), dotDomain.size(), dotDomain) == 0)
            return true;
    }
    return false;
}

bool sniAdd(const std::string& domain) {
    std::string d = domain;
    while (!d.empty() && (d.front() == '*' || d.front() == '.' || isspace((unsigned char)d.front()))) d.erase(0, 1);
    while (!d.empty() && isspace((unsigned char)d.back())) d.pop_back();
    if (d.empty()) return false;
    std::lock_guard<std::mutex> lock(g_sniMtx);
    return g_sniBlock.insert(d).second;
}

bool sniDel(const std::string& domain) {
    std::lock_guard<std::mutex> lock(g_sniMtx);
    return g_sniBlock.erase(domain) > 0;
}

std::string sniToJson() {
    std::lock_guard<std::mutex> lock(g_sniMtx);
    std::ostringstream os; os << "[";
    bool first = true;
    for (const auto& d : g_sniBlock) { if (!first) os << ","; os << "\"" << d << "\""; first = false; }
    os << "]";
    return os.str();
}

size_t sniCount() {
    std::lock_guard<std::mutex> lock(g_sniMtx);
    return g_sniBlock.size();
}

// ---------------------------------------------------------------------------
// Signature eksternal + reputasi residivis
// ---------------------------------------------------------------------------
int loadExternalSignatures() {
    g_waf.wipeExternalSignatures();       // replace-all semantics saat reload
    std::ifstream is(SIG_PATH);
    if (!is.is_open()) return 0;
    int added = 0;
    std::string line;
    while (std::getline(is, line)) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ss(line);
        std::string tag, cat, name, pattern;
        int score = 0;
        // Format longgar: [SIG] <kategori> <nama> <skor> <regex sisanya>
        ss >> tag;
        if (tag != "SIG") continue;
        if (!(ss >> cat >> name >> score)) continue;
        std::getline(ss, pattern);        // regex boleh mengandung spasi/'|'
        size_t s = pattern.find_first_not_of(' ');
        if (s != std::string::npos && g_waf.addExternalSignature(cat, name, score, pattern.substr(s)))
            ++added;
    }
    return added;
}

void saveReputation() {
    mkdir(STATE_DIR, 0755);
    auto rep = g_banlist.reputationSnapshot();
    std::ofstream os(REP_PATH, std::ios::trunc);
    if (!os.is_open()) return;
    for (const auto& p : rep) os << p.first << " " << p.second << "\n";
}

void loadReputation() {
    std::ifstream is(REP_PATH);
    if (!is.is_open()) return;
    std::string ip; int hits;
    while (is >> ip >> hits)
        if (hits > 0) g_banlist.seedReputation(ip, hits);
}

// ---------------------------------------------------------------------------
// Persistensi rule + whitelist ke file teks (survive restart engine).
// Format per baris: R|target|proto|port|action  dan  W|ip_atau_cidr
// ---------------------------------------------------------------------------
void writeStateLocked(std::ostream& os) {
    auto snap = g_rules.snapshot();
    for (const auto& r : snap)
        os << "R|" << r.target << "|" << protoToString(r.proto) << "|"
           << r.port << "|" << (r.action == Action::ALLOW ? "allow" : "block") << "\n";
    {
        std::lock_guard<std::mutex> wl(g_whitelistMtx);
        for (const auto& e : g_whitelist) os << "W|" << e << "\n";
    }
    {
        std::lock_guard<std::mutex> sl(g_sniMtx);
        for (const auto& d : g_sniBlock) os << "S|" << d << "\n";
    }
}

bool saveFirewallState() {
    mkdir(STATE_DIR, 0755); // aman kalau sudah ada
    std::ostringstream buf;
    {
        std::ofstream os(STATE_PATH, std::ios::trunc);
        if (!os.is_open()) return false;
        writeStateLocked(buf);
        os << buf.str();
    }
    return true;
}

// Return true kalau ada rule yang dimuat dari file.
bool loadFirewallState() {
    std::ifstream is(STATE_PATH);
    if (!is.is_open()) return false;

    bool loadedRule = false;
    std::string line;
    while (std::getline(is, line)) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        if (line.empty()) continue;

        if (line.rfind("W|", 0) == 0) {
            whitelistAdd(line.substr(2)); // validasi di dalamnya; entri jelek di-skip
        } else if (line.rfind("S|", 0) == 0) {
            sniAdd(line.substr(2));
        } else if (line.rfind("R|", 0) == 0) {
            std::vector<std::string> parts;
            std::stringstream ss(line.substr(2));
            std::string item;
            while (std::getline(ss, item, '|')) parts.push_back(item);
            if (parts.size() == 4 && isValidTarget(parts[0])) {
                Action action = (parts[3] == "allow") ? Action::ALLOW : Action::BLOCK;
                g_rules.add(parts[0], protoFromString(parts[1]), parts[2], action);
                loadedRule = true;
            }
        }
    }
    return loadedRule;
}

// ---------------------------------------------------------------------------
// Inti logika firewall: cocokkan paket terhadap rule, kembalikan verdict
// ---------------------------------------------------------------------------
struct PacketInfo {
    uint32_t srcIp;
    uint32_t dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    Proto    proto;
    uint8_t  tcpFlags = 0;   // byte flags TCP (buat deteksi stealth scan)
    const char* payload    = nullptr; // pointer ke data setelah header L4, bisa null
    int         payloadLen = 0;
};

bool evaluatePacket(const PacketInfo& pkt, uint64_t& matchedRuleId) {
    auto rulesCopy = g_rules.snapshot();

    // Rule diproses urut (prioritas = urutan insert). Default policy: ALLOW
    // kalau tidak ada rule yang match.
    for (const auto& r : rulesCopy) {
        if (r.proto != Proto::ANY && r.proto != pkt.proto) continue;
        if (!ipInCidr(pkt.srcIp, r.target) && !ipInCidr(pkt.dstIp, r.target)) continue;
        if (!portMatches(pkt.dstPort, r.port) && !portMatches(pkt.srcPort, r.port)) continue;

        matchedRuleId = r.id;
        return r.action == Action::ALLOW;
    }
    matchedRuleId = 0;
    return true; // default allow
}

// ---------------------------------------------------------------------------
// Callback dipanggil libnetfilter_queue untuk setiap paket yang masuk queue
// ---------------------------------------------------------------------------
static int packetCallback(struct nfq_q_handle* qh, struct nfgenmsg*,
                           struct nfq_data* nfa, void*) {
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t packetId = ph ? ntohl(ph->packet_id) : 0;

    unsigned char* rawData = nullptr;
    int len = nfq_get_payload(nfa, &rawData);

    g_totalPackets++;

    if (len < static_cast<int>(sizeof(struct iphdr)) || !rawData) {
        return nfq_set_verdict(qh, packetId, NF_ACCEPT, 0, nullptr);
    }

    struct iphdr* ip = reinterpret_cast<struct iphdr*>(rawData);
    PacketInfo pkt{};
    pkt.srcIp = ntohl(ip->saddr);
    pkt.dstIp = ntohl(ip->daddr);

    int ipHeaderLen = ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP && len >= ipHeaderLen + (int)sizeof(struct tcphdr)) {
        auto* tcp = reinterpret_cast<struct tcphdr*>(rawData + ipHeaderLen);
        pkt.srcPort = ntohs(tcp->source);
        pkt.dstPort = ntohs(tcp->dest);
        pkt.proto = Proto::TCP;
        pkt.tcpFlags = rawData[ipHeaderLen + 13]; // byte ke-13 header = FIN/SYN/RST/dst

        // Ambil payload aplikasi (setelah header TCP) buat inspeksi WAF.
        // Cuma berguna kalau traffic-nya HTTP plain (bukan HTTPS terenkripsi).
        int tcpHeaderLen = tcp->doff * 4;
        int payloadOffset = ipHeaderLen + tcpHeaderLen;
        if (len > payloadOffset) {
            pkt.payload = reinterpret_cast<const char*>(rawData + payloadOffset);
            pkt.payloadLen = len - payloadOffset;
        }
    } else if (ip->protocol == IPPROTO_UDP && len >= ipHeaderLen + (int)sizeof(struct udphdr)) {
        auto* udp = reinterpret_cast<struct udphdr*>(rawData + ipHeaderLen);
        pkt.srcPort = ntohs(udp->source);
        pkt.dstPort = ntohs(udp->dest);
        pkt.proto = Proto::UDP;

        // Inspeksi payload UDP juga (query DNS, HTTP/QUIC plaintext awal,
        // protokol kustom) supaya signature WAF tidak cuma jalan di TCP.
        int payloadOffset = ipHeaderLen + static_cast<int>(sizeof(struct udphdr));
        if (len > payloadOffset) {
            pkt.payload = reinterpret_cast<const char*>(rawData + payloadOffset);
            pkt.payloadLen = len - payloadOffset;
        }
    } else {
        pkt.srcPort = 0;
        pkt.dstPort = 0;
        pkt.proto = Proto::ANY;
    }

    char srcStr[INET_ADDRSTRLEN], dstStr[INET_ADDRSTRLEN];
    struct in_addr srcA{ htonl(pkt.srcIp) }, dstA{ htonl(pkt.dstIp) };
    inet_ntop(AF_INET, &srcA, srcStr, sizeof(srcStr));
    inet_ntop(AF_INET, &dstA, dstStr, sizeof(dstStr));
    std::string srcIpStr(srcStr);

    // ---- Fast path 0: IP trusted (whitelist) -> skip semua heuristik ----
    // Ban list, WAF scoring, dan anomaly tidak diterapkan ke IP terpercaya
    // (misal IP server sendiri / monitoring) supaya tidak terjadi self-ban.
    // Rule statis tetap berlaku di bawah.
    bool trusted = isTrusted(pkt.srcIp);

    // Key alur TCP untuk reassembly payload anti payload-splitting
    std::string tcpFlowKey;
    if (pkt.proto == Proto::TCP) {
        std::ostringstream k;
        k << srcIpStr << ":" << pkt.srcPort << "->" << pkt.dstPort;
        tcpFlowKey = k.str();
    }

    // ---- Fast path baru: stealth scan L4 (NULL/XMAS/SYN-FIN/...) ----
    // Kombinasi flag ini tidak pernah dimiliki traffic sah; cukup baca 1
    // byte header, murah, dan tidak bisa di-dodge dengan manipulasi payload.
    if (!trusted && pkt.proto == Proto::TCP) {
        if (const char* why = tcpFlagAnomaly(pkt.tcpFlags)) {
            g_flagDrops++;
            g_blockedPackets++;
            {
                std::ostringstream evt;
                evt << "{\"time\":\"" << nowTimestamp() << "\",\"src\":\"" << srcStr
                    << "\",\"dst\":\"" << dstStr << "\",\"sport\":" << pkt.srcPort
                    << ",\"dport\":" << pkt.dstPort << ",\"proto\":\""
                    << protoToString(pkt.proto)
                    << "\",\"action\":\"BLOCK\",\"reason\":\"ANOMALY:" << why
                    << "\",\"rule_id\":0}\n";
                broadcastLog(evt.str());
            }
            g_banlist.ban(srcIpStr, 300, std::string("ANOMALY:") + why);
            saveReputation(); // residivis tercatat persisten
            return nfq_set_verdict(qh, packetId, NF_DROP, 0, nullptr);
        }
    }

    // ---- Fast path: kalau IP ini sudah di-ban sementara, langsung DROP ----
    // tanpa perlu evaluasi rule/WAF/anomaly lagi. Ini yang bikin engine tetap
    // ringan walau lagi digempur satu IP nakal berulang-ulang.
    if (!trusted && g_banlist.isBanned(srcIpStr)) {
        g_banHits++;
        g_blockedPackets++;
        std::ostringstream evt;
        evt << "{\"time\":\"" << nowTimestamp() << "\",\"src\":\"" << srcStr
            << "\",\"dst\":\"" << dstStr << "\",\"sport\":" << pkt.srcPort
            << ",\"dport\":" << pkt.dstPort << ",\"proto\":\"" << protoToString(pkt.proto)
            << "\",\"action\":\"BLOCK\",\"reason\":\"BANNED\",\"rule_id\":0}\n";
        broadcastLog(evt.str());
        return nfq_set_verdict(qh, packetId, NF_DROP, 0, nullptr);
    }

    // ---- Pipeline tahap L3/L4: connection rate limit (Token Bucket) ------
    // HTTP flood / brute-force tercepat dipukul DI SINI sebelum sempat
    // menyentuh rule-matching & inspeksi payload — biaya O(1) per paket,
    // persis filosofi early-drop ala Cloudflare edge.
    if (!trusted && !g_rate.allow(srcIpStr)) {
        g_rateBlocked++;
        g_blockedPackets++;
        std::ostringstream evt;
        evt << "{\"time\":\"" << nowTimestamp() << "\",\"src\":\"" << srcStr
            << "\",\"dst\":\"" << dstStr << "\",\"sport\":" << pkt.srcPort
            << ",\"dport\":" << pkt.dstPort << ",\"proto\":\""
            << protoToString(pkt.proto)
            << "\",\"action\":\"BLOCK\",\"reason\":\"ANOMALY:L7_FLOOD\",\"rule_id\":0}\n";
        broadcastLog(evt.str());
        g_banlist.ban(srcIpStr, 60, "ANOMALY:L7_FLOOD");
        saveReputation();
        return nfq_set_verdict(qh, packetId, NF_DROP, 0, nullptr);
    }

    // ---- Lapis 1: rule statis (IP/CIDR/port/protokol) ----
    uint64_t matchedRuleId = 0;
    bool allowed = evaluatePacket(pkt, matchedRuleId);
    std::string reason = matchedRuleId ? "RULE" : "DEFAULT_ALLOW";

    // ---- Lapis 2: SNI filtering — blokir domain TLS berbahaya ----
    // ClientHello terkirim plaintext: kita bisa tahu domain tujuan walau
    // isi sesi terenkripsi. Efektif untuk beacon malware/C2 keluar server.
    if (allowed && !trusted && pkt.proto == Proto::TCP &&
        pkt.payloadLen >= 11 && pkt.payload[0] == '\x16' && pkt.payload[1] == '\x03') {
        std::string sniHost;
        if (extractTlsSni(reinterpret_cast<const uint8_t*>(pkt.payload), pkt.payloadLen, sniHost)
            && sniIsBlocked(sniHost)) {
            std::string why = "SNI:" + sniHost;
            std::ostringstream evt;
            evt << "{\"time\":\"" << nowTimestamp() << "\",\"src\":\"" << srcStr
                << "\",\"dst\":\"" << dstStr << "\",\"sport\":" << pkt.srcPort
                << ",\"dport\":" << pkt.dstPort << ",\"proto\":\""
                << protoToString(pkt.proto) << "\",\"action\":\"BLOCK\",\"reason\":\""
                << why << "\",\"rule_id\":0}\n";
            broadcastLog(evt.str());
            g_sniDrops++;
            g_blockedPackets++;
            g_banlist.ban(srcIpStr, 600, why);
            saveReputation();
            if (!tcpFlowKey.empty()) g_flows.erase(tcpFlowKey);
            return nfq_set_verdict(qh, packetId, NF_DROP, 0, nullptr);
        }
    }

    // ---- Lapis 3: WAF scoring atas payload TERASSEMBLY + HTTP-aware ----
    // Reassembly menutup celah payload dipecah lintas paket; composeForWaf
    // membatasi scan ke request-line/UA/body supaya FP dari header statik turun.
    WafResult waf;
    if (allowed && !trusted && pkt.payload && pkt.payloadLen > 0) {
        if (pkt.proto == Proto::TCP) {
            const std::string& window = g_flows.append(tcpFlowKey, pkt.payload,
                                                       std::min(pkt.payloadLen, 8192));
            HttpSections sec = splitHttp(window.data(), static_cast<int>(window.size()));
            waf = g_waf.inspect(composeForWaf(sec, window));
        } else {
            // UDP stateless: inspeksi datagram langsung
            std::string payloadStr(pkt.payload, std::min(pkt.payloadLen, 4096));
            waf = g_waf.inspect(payloadStr);
        }
        if (waf.suspicious) {
            allowed = false;
            reason = "WAF:score" + std::to_string(waf.totalScore) + ":" + WafInspector::summarize(waf);
            g_wafBlocked++;
            g_banlist.ban(srcIpStr, 300, reason); // ban 5 menit, eskalasi tiap residivis
            saveReputation();
            if (!tcpFlowKey.empty()) g_flows.erase(tcpFlowKey); // alur nakal -> buang buffer
        }
    }

    // ---- Lapis 4: anomaly detection (port scan / flood) berbasis perilaku ----
    AnomalyType anomaly = AnomalyType::NONE;
    if (!trusted) anomaly = g_anomaly.record(srcIpStr, pkt.dstPort);
    if (allowed && anomaly != AnomalyType::NONE) {
        allowed = false;
        reason = std::string("ANOMALY:") + anomalyToString(anomaly);
        g_anomalyBlocked++;
        int banSeconds = (anomaly == AnomalyType::FLOOD) ? 60 : 300; // flood: 1 menit, port scan: 5 menit
        g_banlist.ban(srcIpStr, banSeconds, reason);
        saveReputation();
    }

    if (!allowed) g_blockedPackets++;

    // Kirim event ke subscriber dashboard (format JSON per baris)
    std::ostringstream evt;
    evt << "{"
        << "\"time\":\"" << nowTimestamp() << "\","
        << "\"src\":\"" << srcStr << "\","
        << "\"dst\":\"" << dstStr << "\","
        << "\"sport\":" << pkt.srcPort << ","
        << "\"dport\":" << pkt.dstPort << ","
        << "\"proto\":\"" << protoToString(pkt.proto) << "\","
        << "\"action\":\"" << (allowed ? "ALLOW" : "BLOCK") << "\","
        << "\"reason\":\"" << reason << "\","
        << "\"rule_id\":" << matchedRuleId
        << "}\n";
    broadcastLog(evt.str());

    return nfq_set_verdict(qh, packetId, allowed ? NF_ACCEPT : NF_DROP, 0, nullptr);
}

// ---------------------------------------------------------------------------
// Thread NFQUEUE: loop utama baca dari kernel
// ---------------------------------------------------------------------------
void runNfqueueLoop(int queueNum) {
    struct nfq_handle* h = nfq_open();
    if (!h) { std::cerr << "[!] Gagal buka nfq_open, jalankan sebagai root\n"; return; }

    if (nfq_unbind_pf(h, AF_INET) < 0) { /* boleh gagal di beberapa kernel, aman diabaikan */ }
    if (nfq_bind_pf(h, AF_INET) < 0) {
        std::cerr << "[!] Gagal nfq_bind_pf\n"; return;
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, queueNum, &packetCallback, nullptr);
    if (!qh) { std::cerr << "[!] Gagal buat queue " << queueNum << "\n"; return; }

    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    int fd = nfq_fd(h);
    char buf[65536] __attribute__((aligned));

    std::cout << "[+] Engine aktif, mendengarkan NFQUEUE #" << queueNum << "\n";
    std::cout << "    Pastikan sudah dijalankan:\n"
              << "    iptables -I INPUT -j NFQUEUE --queue-num " << queueNum << "\n"
              << "    iptables -I OUTPUT -j NFQUEUE --queue-num " << queueNum << "\n";

    ssize_t received;
    while (g_running && (received = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, received);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
}

// ---------------------------------------------------------------------------
// Unix socket server: menangani command dari backend dashboard
// ---------------------------------------------------------------------------
std::string rulesToJson() {
    auto snap = g_rules.snapshot();
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < snap.size(); i++) {
        const auto& r = snap[i];
        os << "{\"id\":" << r.id
           << ",\"target\":\"" << r.target << "\""
           << ",\"proto\":\"" << protoToString(r.proto) << "\""
           << ",\"port\":\"" << r.port << "\""
           << ",\"action\":\"" << (r.action == Action::ALLOW ? "allow" : "block") << "\""
           << "}";
        if (i + 1 < snap.size()) os << ",";
    }
    os << "]";
    return os.str();
}

std::string statsToJson() {
    std::ostringstream os;
    os << "{"
       << "\"total_packets\":" << g_totalPackets.load() << ","
       << "\"blocked\":" << g_blockedPackets.load() << ","
       << "\"waf_blocked\":" << g_wafBlocked.load() << ","
       << "\"anomaly_blocked\":" << g_anomalyBlocked.load() << ","
       << "\"ban_hits\":" << g_banHits.load() << ","
       << "\"rules\":" << g_rules.snapshot().size() << ","
       << "\"trusted\":" << whitelistCount() << ","
       << "\"waf_threshold\":" << g_waf.threshold() << ","
       << "\"flag_drops\":" << g_flagDrops.load() << ","
       << "\"sni_drops\":" << g_sniDrops.load() << ","
       << "\"rate_limited\":" << g_rateBlocked.load()
       << "}";
    return os.str();
}

std::string bansToJson() {
    auto snap = g_banlist.snapshot();
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < snap.size(); i++) {
        const auto& b = snap[i];
        os << "{\"ip\":\"" << b.ip << "\""
           << ",\"remaining_seconds\":" << b.remainingSeconds
           << ",\"hit_count\":" << b.hitCount
           << ",\"reason\":\"" << b.reason << "\""
           << "}";
        if (i + 1 < snap.size()) os << ",";
    }
    os << "]";
    return os.str();
}

// Parser command super sederhana. Untuk production, ganti dengan parser JSON
// beneran (nlohmann/json) supaya lebih robust.
void handleClient(int clientFd) {
    char buf[4096];
    ssize_t n;
    while ((n = recv(clientFd, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        std::string cmd(buf);
        // buang newline trailing
        while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) cmd.pop_back();

        if (cmd == "GET_STATS") {
            std::string resp = statsToJson() + "\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd == "GET_RULES") {
            std::string resp = rulesToJson() + "\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd.rfind("ADD_RULE ", 0) == 0) {
            // Format sederhana: ADD_RULE target|proto|port|action
            // contoh: ADD_RULE 10.0.0.0/8|TCP|8080|block
            std::string args = cmd.substr(9);
            std::vector<std::string> parts;
            std::stringstream ss(args);
            std::string item;
            while (std::getline(ss, item, '|')) parts.push_back(item);

            if (parts.size() == 4 && isValidTarget(parts[0])) {
                Action action = (parts[3] == "allow") ? Action::ALLOW : Action::BLOCK;
                uint64_t id = g_rules.add(parts[0], protoFromString(parts[1]), parts[2], action);
                saveFirewallState(); // persist agar survive restart
                std::string resp = "{\"ok\":true,\"id\":" + std::to_string(id) + "}\n";
                send(clientFd, resp.c_str(), resp.size(), 0);
            } else {
                std::string err = parts.size() == 4
                    ? "target bukan IPv4/CIDR yang valid"
                    : "format salah";
                std::string resp = std::string("{\"ok\":false,\"error\":\"") + err + "\"}\n";
                send(clientFd, resp.c_str(), resp.size(), 0);
            }

        } else if (cmd.rfind("DEL_RULE ", 0) == 0) {
            uint64_t id = std::stoull(cmd.substr(9));
            bool ok = g_rules.remove(id);
            if (ok) saveFirewallState(); // persist agar survive restart
            std::string resp = std::string("{\"ok\":") + (ok ? "true" : "false") + "}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd == "GET_BANS") {
            std::string resp = bansToJson() + "\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd.rfind("UNBAN ", 0) == 0) {
            std::string ip = cmd.substr(6);
            bool ok = g_banlist.unban(ip);
            std::string resp = std::string("{\"ok\":") + (ok ? "true" : "false") + "}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd.rfind("BAN ", 0) == 0) {
            // Ban manual dari dashboard: BAN <ip> [durasi_detik, default 300]
            std::string args = cmd.substr(4);
            auto spacePos = args.find(' ');
            std::string ip    = args.substr(0, spacePos);
            int seconds       = 300;
            if (spacePos != std::string::npos) {
                try { seconds = std::max(1, std::stoi(args.substr(spacePos + 1))); }
                catch (...) { seconds = 300; }
            }
            in_addr probe{};
            if (inet_pton(AF_INET, ip.c_str(), &probe) != 1) {
                std::string resp = "{\"ok\":false,\"error\":\"IP tidak valid\"}\n";
                send(clientFd, resp.c_str(), resp.size(), 0);
            } else {
                g_banlist.ban(ip, seconds, "MANUAL");
                std::string resp = "{\"ok\":true,\"seconds\":" + std::to_string(seconds) + "}\n";
                send(clientFd, resp.c_str(), resp.size(), 0);
            }

        } else if (cmd == "GET_WHITELIST") {
            std::string resp = whitelistToJson() + "\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd.rfind("ADD_WHITELIST ", 0) == 0) {
            // IP / CIDR yang dipercaya: lewati WAF, anomaly & auto-ban
            std::string entry = cmd.substr(14);
            bool ok = whitelistAdd(entry);
            if (ok) saveFirewallState();
            std::string resp = std::string("{\"ok\":") + (ok ? "true" : "false")
                             + (ok ? "" : ",\"error\":\"bukan IPv4/CIDR valid\"") + "}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd.rfind("DEL_WHITELIST ", 0) == 0) {
            std::string entry = cmd.substr(14);
            bool ok = whitelistDel(entry);
            if (ok) saveFirewallState();
            std::string resp = std::string("{\"ok\":") + (ok ? "true" : "false") + "}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd.rfind("SET_WAF_THRESHOLD ", 0) == 0) {
            // Tuning sensitivitas WAF saat runtime, tanpa recompile/restart
            try {
                int t = std::stoi(cmd.substr(18));
                g_waf.setThreshold(t);
                std::string resp = std::string("{\"ok\":true,\"threshold\":")
                                 + std::to_string(g_waf.threshold()) + "}\n";
                send(clientFd, resp.c_str(), resp.size(), 0);
            } catch (...) {
                std::string resp = "{\"ok\":false,\"error\":\"angka tidak valid\"}\n";
                send(clientFd, resp.c_str(), resp.size(), 0);
            }

        } else if (cmd == "GET_SNI_BLOCKS") {
            std::string resp = sniToJson() + "\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd.rfind("ADD_SNI_BLOCK ", 0) == 0) {
            // Blokir domain TLS via SNI tanpa dekripsi: ADD_SNI_BLOCK evil.com
            // subdomain *.evil.com ikut kena. Tersimpan persisten.
            bool ok = sniAdd(cmd.substr(14));
            if (ok) saveFirewallState();
            std::string resp = std::string("{\"ok\":") + (ok ? "true" : "false") + "}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd.rfind("DEL_SNI_BLOCK ", 0) == 0) {
            bool ok = sniDel(cmd.substr(14));
            if (ok) saveFirewallState();
            std::string resp = std::string("{\"ok\":") + (ok ? "true" : "false") + "}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd.rfind("SET_RATE_LIMIT ", 0) == 0) {
            // Tune Token Bucket runtime: SET_RATE_LIMIT <kapasitas> <refill/detik>
            std::istringstream ss(cmd.substr(15));
            double cap = 0, rps = 0;
            if ((ss >> cap >> rps) && cap > 0 && rps > 0) {
                g_rate.configure(cap, rps);
                std::string resp = "{\"ok\":true,\"capacity\":" + std::to_string(cap)
                                 + ",\"refill_per_sec\":" + std::to_string(rps) + "}\n";
                send(clientFd, resp.c_str(), resp.size(), 0);
            } else {
                std::string resp = "{\"ok\":false,\"error\":\"butuh dua angka positif\"}\n";
                send(clientFd, resp.c_str(), resp.size(), 0);
            }

        } else if (cmd == "GET_RATE_LIMIT") {
            std::string resp = std::string("{\"capacity\":")
                             + std::to_string(g_rate.capacity())
                             + ",\"refill_per_sec\":" + std::to_string(g_rate.refillRate())
                             + ",\"tracked_ips\":" + std::to_string(g_rate.tracked()) + "}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd == "LOAD_SIGS") {
            // Hot reload signature dari signatures.conf tanpa restart engine
            int added = loadExternalSignatures();
            std::string resp = std::string("{\"ok\":true,\"added\":")
                             + std::to_string(added)
                             + ",\"total_signatures\":" + std::to_string(g_waf.signatureCount()) + "}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd == "RELOAD") {
            // Muat ulang state dari file state (berguna kalau file diedit manual)
            g_rules.clear();
            bool anyRule = loadFirewallState();
            if (!anyRule) g_rules.addDefault(); // kosong -> kembalikan default
            std::string resp = "{\"ok\":true,\"rules\":" +
                               std::to_string(g_rules.snapshot().size()) + "}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd == "PING") {
            std::string resp = "{\"ok\":true,\"pong\":true,\"version\":\"2.3\"}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);

        } else if (cmd == "STREAM_LOGS") {
            std::lock_guard<std::mutex> lock(g_logSubMtx);
            g_logSubscribers.push_back(clientFd);
            return; // fd dipegang terus buat streaming, jangan close di bawah

        } else {
            std::string resp = "{\"ok\":false,\"error\":\"command tidak dikenal\"}\n";
            send(clientFd, resp.c_str(), resp.size(), 0);
        }
    }
    close(clientFd);
}

void runSocketServer() {
    unlink(SOCKET_PATH);

    int serverFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverFd < 0) { std::cerr << "[!] Gagal buat socket\n"; return; }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(serverFd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[!] Gagal bind ke " << SOCKET_PATH << "\n"; return;
    }
    chmod(SOCKET_PATH, 0666); // sesuaikan permission produksi, ini contoh saja
    listen(serverFd, 16);

    std::cout << "[+] Unix socket server siap di " << SOCKET_PATH << "\n";

    while (g_running) {
        int clientFd = accept(serverFd, nullptr, nullptr);
        if (clientFd < 0) continue;
        std::thread(handleClient, clientFd).detach();
    }
    close(serverFd);
}

// ---------------------------------------------------------------------------
void handleSignal(int) { g_running = false; }

int main(int argc, char** argv) {
    int queueNum = 0;
    if (argc > 1) queueNum = std::atoi(argv[1]);

    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);

    // Muat rule + whitelist yang tersimpan; kalau belum ada state sama sekali,
    // pakai rule bawaan. Ini bikin konfigurasi bertahan antar restart.
    if (!loadFirewallState()) {
        std::cout << "[*] Tidak ada state tersimpan, pakai rule bawaan\n";
        g_rules.addDefault();
    } else {
        std::cout << "[+] State dimuat dari " << STATE_PATH << ": "
                  << g_rules.snapshot().size() << " rule, "
                  << whitelistCount() << " whitelist\n";
    }

    // Signature eksternal (file config) + reputasi residivis dari disk
    int extSigs = loadExternalSignatures();
    if (extSigs > 0)
        std::cout << "[+] Signature eksternal dimuat: " << extSigs
                  << " (total " << g_waf.signatureCount() << ")\n";
    loadReputation();

    std::thread socketThread(runSocketServer);
    std::thread nfqThread(runNfqueueLoop, queueNum);

    nfqThread.join();
    g_running = false;
    socketThread.detach(); // accept() akan unblock saat proses exit

    std::cout << "\n[+] Engine berhenti. Total paket: " << g_totalPackets
              << ", diblokir: " << g_blockedPackets << "\n";
    return 0;
}
