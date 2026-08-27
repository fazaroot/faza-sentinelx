#pragma once
// ============================================================================
// BanList: daftar IP yang diblokir sementara setelah ketahuan WAF/anomaly.
// Mirip mod_evasive (Apache/LiteSpeed) atau fail2ban — sekali IP ketahuan
// nakal, semua paket berikutnya dari IP itu langsung DROP tanpa perlu
// diinspeksi ulang (hemat CPU), sampai masa ban habis.
// ============================================================================

#include <unordered_map>
#include <mutex>
#include <chrono>
#include <string>
#include <vector>
#include <algorithm>

struct BanEntry {
    std::chrono::steady_clock::time_point expiresAt;
    std::string reason;
    int         hitCount = 1; // berapa kali IP ini kena ban (buat escalation)
};

class BanList {
public:
    // Ban IP selama `seconds`. Kalau IP sudah kena ban sebelumnya (aktif ATAU
    // punya reputasi residivis tersimpan), masa ban baru eskalasi (2x, 3x,...
    // maksimal 6x durasi dasar). Reputasi bertahan lewat seedReputation()
    // sehingga residivis tetap ingat meski engine di-restart.
    void ban(const std::string& ip, int seconds, const std::string& reason) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto now = std::chrono::steady_clock::now();
        auto it = table_.find(ip);
        int priorHits = 0;
        if (it != table_.end()) {
            priorHits = it->second.hitCount;
        } else {
            auto rit = reputation_.find(ip);
            if (rit != reputation_.end()) priorHits = rit->second;
        }
        int hits = priorHits > 0 ? priorHits + 1 : 1;
        int effectiveSeconds = seconds * std::min(hits, 6); // eskalasi dibatasi 6x
        table_[ip] = BanEntry{ now + std::chrono::seconds(effectiveSeconds), reason, hits };
        reputation_[ip] = std::max(reputation_[ip], hits);
    }

    // Reputasi residivis yang dimuat dari disk saat startup (tidak mengaktifkan ban)
    void seedReputation(const std::string& ip, int hits) {
        std::lock_guard<std::mutex> lock(mtx_);
        int h = std::max(1, hits);
        reputation_[ip] = std::max(reputation_[ip], h);
        // kalau IP juga aktif kena ban sekarang, sinkronkan hit count-nya
        auto it = table_.find(ip);
        if (it != table_.end()) it->second.hitCount = std::max(it->second.hitCount, h);
    }

    int getHits(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = reputation_.find(ip);
        return it != reputation_.end() ? it->second : 0;
    }

    // Snapshot reputasi residivis (buat ditulis ke disk oleh pemanggil)
    std::vector<std::pair<std::string, int>> reputationSnapshot() {
        std::lock_guard<std::mutex> lock(mtx_);
        return std::vector<std::pair<std::string, int>>(reputation_.begin(), reputation_.end());
    }

    bool isBanned(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = table_.find(ip);
        if (it == table_.end()) return false;
        if (std::chrono::steady_clock::now() > it->second.expiresAt) {
            table_.erase(it); // sudah expired, bersihkan
            return false;
        }
        return true;
    }

    bool unban(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mtx_);
        return table_.erase(ip) > 0;
    }

    // Snapshot buat ditampilkan di dashboard: IP, sisa detik, alasan, hitCount
    struct BanView { std::string ip; long remainingSeconds; std::string reason; int hitCount; };
    std::vector<BanView> snapshot() {
        std::lock_guard<std::mutex> lock(mtx_);
        auto now = std::chrono::steady_clock::now();
        std::vector<BanView> out;
        for (auto it = table_.begin(); it != table_.end(); ) {
            if (now > it->second.expiresAt) { it = table_.erase(it); continue; }
            long remaining = std::chrono::duration_cast<std::chrono::seconds>(it->second.expiresAt - now).count();
            out.push_back({ it->first, remaining, it->second.reason, it->second.hitCount });
            ++it;
        }
        return out;
    }

private:
    std::unordered_map<std::string, BanEntry> table_;
    std::unordered_map<std::string, int>      reputation_; // residivis persisten
    std::mutex mtx_;
};
