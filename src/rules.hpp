#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>

// ==================== Struktur Rule ====================
enum class Action { ALLOW, BLOCK };
enum class Proto  { TCP, UDP, ANY };

struct Rule {
    uint64_t    id;
    std::string target;      // IP atau CIDR, contoh: "192.168.1.0/24" atau "0.0.0.0/0"
    Proto       proto;
    std::string port;        // "22" atau "*" untuk semua port
    Action      action;
};

inline Proto protoFromString(const std::string& s) {
    if (s == "TCP") return Proto::TCP;
    if (s == "UDP") return Proto::UDP;
    return Proto::ANY;
}
inline std::string protoToString(Proto p) {
    switch (p) {
        case Proto::TCP: return "TCP";
        case Proto::UDP: return "UDP";
        default: return "ANY";
    }
}

// ==================== Rule Store (thread-safe) ====================
class RuleStore {
public:
    std::vector<Rule> rules;
    std::mutex mtx;
    uint64_t nextId = 1;

    void addDefault() {
        std::lock_guard<std::mutex> lock(mtx);
        rules.push_back({nextId++, "0.0.0.0/0", Proto::TCP, "22", Action::ALLOW});
        rules.push_back({nextId++, "0.0.0.0/0", Proto::UDP, "53", Action::ALLOW});
        rules.push_back({nextId++, "0.0.0.0/0", Proto::TCP, "3389", Action::BLOCK});
    }

    uint64_t add(const std::string& target, Proto proto, const std::string& port, Action action) {
        std::lock_guard<std::mutex> lock(mtx);
        uint64_t id = nextId++;
        rules.push_back({id, target, proto, port, action});
        return id;
    }

    bool remove(uint64_t id) {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = std::remove_if(rules.begin(), rules.end(),
                                  [id](const Rule& r){ return r.id == id; });
        bool found = it != rules.end();
        rules.erase(it, rules.end());
        return found;
    }

    // Kosongkan semua rule (dipakai saat load ulang state dari file
    // supaya rule bawaan tidak terduplikasi dengan rule tersimpan)
    void clear() {
        std::lock_guard<std::mutex> lock(mtx);
        rules.clear();
        nextId = 1;
    }

    // Ambil salinan snapshot rule (biar lock dilepas cepat)
    std::vector<Rule> snapshot() {
        std::lock_guard<std::mutex> lock(mtx);
        return rules;
    }
};

// ==================== Matching helper ====================

// Cek apakah IP (dalam host order uint32) masuk ke dalam CIDR "a.b.c.d/prefix"
inline bool ipInCidr(uint32_t ip, const std::string& cidr) {
    std::string addrPart = cidr;
    int prefix = 32;
    auto slashPos = cidr.find('/');
    if (slashPos != std::string::npos) {
        addrPart = cidr.substr(0, slashPos);
        prefix = std::stoi(cidr.substr(slashPos + 1));
    }
    in_addr netAddr{};
    if (inet_pton(AF_INET, addrPart.c_str(), &netAddr) != 1) return false;
    uint32_t net = ntohl(netAddr.s_addr);
    if (prefix == 0) return true; // 0.0.0.0/0 = semua IP
    uint32_t mask = prefix == 32 ? 0xFFFFFFFFu : (~0u << (32 - prefix));
    return (ip & mask) == (net & mask);
}

// Cek apakah port paket cocok dengan pola rule. Mendukung:
//   "*"           -> semua port
//   "22"          -> satu port persis
//   "1000-2000"   -> rentang inklusif
//   "22,80,443"   -> daftar port (boleh campur rentang: "22,8000-9000")
inline bool portSingle(uint16_t pktPort, const std::string& part) {
    auto dash = part.find('-');
    if (dash != std::string::npos && dash > 0 && dash + 1 < part.size()) {
        try {
            int lo = std::stoi(part.substr(0, dash));
            int hi = std::stoi(part.substr(dash + 1));
            return lo <= hi && pktPort >= lo && pktPort <= hi;
        } catch (...) { return false; }
    }
    try { return pktPort == static_cast<uint16_t>(std::stoi(part)); }
    catch (...) { return false; }
}

inline bool portMatches(uint16_t pktPort, const std::string& rulePort) {
    if (rulePort == "*") return true;
    size_t start = 0;
    while (start <= rulePort.size()) {
        size_t comma = rulePort.find(',', start);
        std::string part = (comma == std::string::npos)
                             ? rulePort.substr(start)
                             : rulePort.substr(start, comma - start);
        // trim spasi
        while (!part.empty() && isspace(static_cast<unsigned char>(part.front()))) part.erase(0, 1);
        while (!part.empty() && isspace(static_cast<unsigned char>(part.back())))  part.pop_back();
        if (!part.empty() && portSingle(pktPort, part)) return true;
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return false;
}

// Validasi target rule sebelum diterima (ADD_RULE): harus CIDR/IP IPv4 sah
inline bool isValidTarget(const std::string& cidr) {
    std::string addrPart = cidr;
    if (auto slash = cidr.find('/'); slash != std::string::npos) {
        addrPart = cidr.substr(0, slash);
        try {
            int prefix = std::stoi(cidr.substr(slash + 1));
            if (prefix < 0 || prefix > 32) return false;
        } catch (...) { return false; }
    }
    in_addr probe{};
    return inet_pton(AF_INET, addrPart.c_str(), &probe) == 1;
}
