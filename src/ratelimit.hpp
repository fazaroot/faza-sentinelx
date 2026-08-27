#pragma once
// ============================================================================
// Token Bucket Rate Limiter per-IP — setara Cloudflare Rate Limiting /
// mod_evasive pada level aplikasi. Tiap IP punya ember token berkapasitas
// tertentu yang terisi ulang konstan tiap detik; request tanpa sisa token
// ditolak (early-drop, murah: O(1) hashmap lookup per paket).
//
// Cocok untuk memukul HTTP flood / brute force L7 yang lolos dari
// window-anomaly karena tidak pola datar tetapi tetap sangat cepat.
//
// In-memory per proses; entri idle >10 menit dibuang biar hemat RAM.
// ============================================================================

#include <unordered_map>
#include <mutex>
#include <chrono>
#include <string>

class TokenBucketLimiter {
public:
    TokenBucketLimiter(double capacity = 240.0, double refillPerSecond = 80.0)
        : cap_(capacity > 1 ? capacity : 1),
          rate_(refillPerSecond > 0 ? refillPerSecond : 1) {}

    // Konfigurasi runtime (dipanggil dari command handler socket thread).
    // Nilai atomik supaya callback NFQUEUE membaca konsisten.
    void configure(double capacity, double refillPerSecond) {
        std::lock_guard<std::mutex> lock(mtx_);
        cap_  = capacity > 1         ? capacity         : 1;
        rate_ = refillPerSecond > 0  ? refillPerSecond  : 1;
    }

    double capacity()  const { std::lock_guard<std::mutex> lock(mtx_); return cap_; }
    double refillRate()const { std::lock_guard<std::mutex> lock(mtx_); return rate_; }
    size_t tracked()   const { std::lock_guard<std::mutex> lock(mtx_); return buckets_.size(); }

    // Konsumsi 1 token untuk IP. Return false kalau kuota habis (harus ditolak).
    bool allow(const std::string& ip) {
        using clock = std::chrono::steady_clock;
        auto now = clock::now();

        std::lock_guard<std::mutex> lock(mtx_);

        // prune idle (maksimal sekali per 60 detik biar murah)
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastPrune_).count() >= 60) {
            for (auto it = buckets_.begin(); it != buckets_.end();) {
                if (std::chrono::duration_cast<std::chrono::seconds>(
                        now - it->second.last).count() > 600)
                    it = buckets_.erase(it);
                else ++it;
            }
            lastPrune_ = now;
        }

        auto nowSec = std::chrono::duration<double>(now.time_since_epoch()).count();
        auto& b     = buckets_[ip];
        b.last      = now;

        // isi ulang proporsional waktu berlalu
        if (b.tokens < cap_) {
            double earned = (nowSec - b.lastRefill) * rate_;
            b.tokens      = std::min(cap_, b.tokens + earned);
        }
        b.lastRefill = nowSec;

        if (b.tokens >= 1.0) { --b.tokens; return true; }
        return false;                                     // kehabisan kuota
    }

private:
    struct Bucket {
        double tokens;
        double lastRefill;
        std::chrono::steady_clock::time_point last;
    };

    mutable std::mutex mtx_;
    double cap_;                        // kapasitas ember (burst maksimum)
    double rate_;                       // token baru per detik (kecepatan sustain)
    std::unordered_map<std::string, Bucket> buckets_;
    std::chrono::steady_clock::time_point lastPrune_{std::chrono::steady_clock::now()};
};
