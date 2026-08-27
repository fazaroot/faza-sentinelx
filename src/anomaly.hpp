#pragma once
// ============================================================================
// Anomaly Detector: mendeteksi pola mencurigakan berbasis perilaku, bukan
// signature. Dua kelas anomali yang dicek:
//
//  1. PORT_SCAN — satu IP sumber menghubungi banyak port berbeda dalam
//     jendela waktu singkat (indikasi scanning, misal nmap).
//  2. FLOOD     — satu IP sumber mengirim terlalu banyak paket dalam
//     jendela waktu singkat (indikasi DoS / brute force).
//
// Implementasi sengaja sederhana (sliding window in-memory, per proses).
// Untuk beban tinggi/production, pertimbangkan struktur lebih efisien
// (misal ring buffer per-IP atau eviction berbasis LRU).
// ============================================================================

#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <string>

enum class AnomalyType { NONE, PORT_SCAN, FLOOD };

struct AnomalyConfig {
    int windowSeconds      = 10;  // ukuran jendela waktu observasi
    int portScanThreshold  = 15;  // distinct port dalam window -> dicurigai scan
    int floodThreshold     = 200; // total paket dalam window -> dicurigai flood
};

class AnomalyDetector {
public:
    explicit AnomalyDetector(AnomalyConfig cfg = {}) : cfg_(cfg) {}

    // Panggil untuk setiap paket masuk. srcIp dalam format string ("1.2.3.4").
    AnomalyType record(const std::string& srcIp, uint16_t dstPort) {
        using namespace std::chrono;
        auto now = steady_clock::now();

        std::lock_guard<std::mutex> lock(mtx_);
        auto& state = table_[srcIp];

        // Buang entri di luar window
        while (!state.events.empty() &&
               duration_cast<seconds>(now - state.events.front().ts).count() > cfg_.windowSeconds) {
            state.ports.erase(state.events.front().port);
            state.events.pop_front();
        }

        state.events.push_back({now, dstPort});
        state.ports.insert(dstPort);

        if (static_cast<int>(state.events.size()) > cfg_.floodThreshold) {
            return AnomalyType::FLOOD;
        }
        if (static_cast<int>(state.ports.size()) > cfg_.portScanThreshold) {
            return AnomalyType::PORT_SCAN;
        }
        return AnomalyType::NONE;
    }

    // Bersihkan state IP tertentu, misal setelah IP diblokir manual
    void reset(const std::string& srcIp) {
        std::lock_guard<std::mutex> lock(mtx_);
        table_.erase(srcIp);
    }

private:
    struct Event { std::chrono::steady_clock::time_point ts; uint16_t port; };
    struct IpState {
        std::deque<Event> events;
        std::unordered_set<uint16_t> ports;
    };

    AnomalyConfig cfg_;
    std::unordered_map<std::string, IpState> table_;
    std::mutex mtx_;
};

inline const char* anomalyToString(AnomalyType t) {
    switch (t) {
        case AnomalyType::PORT_SCAN: return "PORT_SCAN";
        case AnomalyType::FLOOD:     return "FLOOD";
        default:                     return "NONE";
    }
}
