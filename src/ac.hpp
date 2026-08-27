#pragma once
// ============================================================================
// Aho-Corasick automaton — deteksi multi-keyword dalam SATU pass O(N).
//
// Ini teknik yang dipakai ModSecurity v3 / LiteSpeed untuk menghindari
// pencocokan string satu-per-satu dan sepenuhnya kebal ReDoS (tidak ada
// backtracking). Ribuan kata kunci tidak mengubah biaya scan sama sekali;
// yang menentukan hanya panjang teks masukan.
//
//     build : O(total panjang keyword)
//     scan  : O(len(text) + jumlah hasil)
//
// Transisi menggunakan tabel lengkap (goto function) sehingga tiap karakter
// hanya butuh satu lookup tanpa fallback-loop manual.
// ============================================================================

#include <string>
#include <vector>
#include <queue>
#include <cstring>
#include <algorithm>

class AhoCorasick {
public:
    AhoCorasick() { nodes_.emplace_back(); }           // root = 0

    // Panggil sebelum build(). Lowercase dilakukan otomatis saat insert &
    // scan (huruf ASCII saja, simbol dibiarkan apa adanya supaya aman).
    void insert(const std::string& kw) {
        int cur = 0;
        for (char ch : kw) {
            unsigned char c = lower(ch);
            int& nxt = nodes_[cur].next[c];
            if (nxt < 0) { nxt = static_cast<int>(nodes_.size()); nodes_.emplace_back(); }
            cur = nxt;
        }
        nodes_[cur].keyIdx.push_back(keysInserted_++);
    }

    // Bangun failure links + output links + transisi lengkap (BFS).
    void build() {
        nodes_[0].fail = -1;
        std::queue<int> q;
        for (int c = 0; c < ALPHABET; ++c) {
            int v = nodes_[0].next[c];
            if (v >= 0) { nodes_[v].fail = 0; q.push(v); }
            else        nodes_[0].next[c] = 0;             // transisi kosong -> root
        }
        while (!q.empty()) {
            int u = q.front(); q.pop();
            // output link: ancestor fail terdekat yang punya keyword.
            // SELALU >=0 (0 = tidak ada), supaya scan aman dari index negatif.
            {
                int f          = std::max(nodes_[u].fail, 0);
                const Node& nf = nodes_[f];
                nodes_[u].outLink = !nf.keyIdx.empty() ? f : nf.outLink;
            }
            for (int c = 0; c < ALPHABET; ++c) {
                int v = nodes_[u].next[c];
                if (v >= 0) {
                    nodes_[v].fail = walkFail(nodes_[u].fail, static_cast<unsigned char>(c));
                    q.push(v);
                } else {
                    // automaton lengkap: gagal -> ikuti fail link langsung
                    nodes_[u].next[c] = walkFail(nodes_[u].fail, static_cast<unsigned char>(c));
                }
            }
        }
    }

    // Scan satu kali; callback fn(keyIndex, endPos) untuk setiap temuan
    // (termasuk keyword dari suffix melalui output link).
    template <typename Fn>
    void scan(const std::string& text, Fn&& fn) const {
        int cur = 0;
        const size_t n = text.size();
        for (size_t i = 0; i < n; ++i) {
            cur = nodes_[cur].next[lower(text[i])];
            for (int v = cur; v > 0; v = nodes_[v].outLink)
                for (int ki : nodes_[v].keyIdx) fn(ki, i);
        }
    }

private:
    static constexpr int ALPHABET = 256;

    struct Node {
        int              next[ALPHABET];
        int              fail    = 0;
        int              outLink = 0;    // 0 = tidak ada ancestor berkata kunci
        std::vector<int> keyIdx;
        Node() { std::memset(next, -1, sizeof(next)); }
    };

    static unsigned char lower(char c) {
        return (c >= 'A' && c <= 'Z')
                   ? static_cast<unsigned char>(c + 32)
                   : static_cast<unsigned char>(c);
    }

    int walkFail(int state, unsigned char c) const {
        while (state != -1 && nodes_[state].next[c] < 0) state = nodes_[state].fail;
        return state == -1 ? 0 : nodes_[state].next[c];
    }

    std::vector<Node> nodes_;
    int               keysInserted_ = 0;
};
