// ============================================================================
// ratelimit.mjs — Sliding-Window Log rate limiter per-IP untuk Vercel Edge.
//
// Meneladani model Cloudflare Rate Limiting: tiap IP punya blog timestamp
// dalam jendela waktu (default 60 detik); kalau jumlah request melampaui
// limit dalam window, request berikutnya ditolak (HTTP 429) dengan header
// Retry-After.
//
// PENTING (jujur): Vercel Edge runtime itu STATELESS / bisa cold-start antar
// instance, jadi memory Map ini hanya BERLAKU DALAM SATU INSTANCE. Untuk
// rate limit yang konsisten lintas-instance di produksi, hubungkan ke store
// eksternal (mis. @vercel/kv / Upstash Redis / Vercel Blob). Kode ini tetap
// berguna untuk dev/coba dan jadi basis integrasi store.
// ============================================================================

export class SlidingWindowLimiter {
  constructor({ limit = 60, windowMs = 60000, maxPruneScan = 1000 } = {}) {
    this.limit = limit >= 1 ? limit : 1;
    this.windowMs = windowMs > 0 ? windowMs : 60000;
    // ip -> array timestamps (ms) dalam jendela
    this.table = new Map();
    this.lastPrune = Date.now();
  }

  // Konsumsi 1 request untuk IP. Return {allowed:bool, remaining, retryAfterMs}
  hit(ip) {
    const now = Date.now();
    if (now - this.lastPrune > this.windowMs) { this.prune(); this.lastPrune = now; }

    let arr = this.table.get(ip);
    if (!arr) { arr = []; this.table.set(ip, arr); }

    // buang timestamp basi (di luar jendela)
    const edge = now - this.windowMs;
    while (arr.length && arr[0] <= edge) arr.shift();

    if (arr.length >= this.limit) {
      const oldest = arr[0];
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: Math.max(0, oldest + this.windowMs - now),
        windowMs: this.windowMs,
      };
    }
    arr.push(now);
    return { allowed: true, remaining: Math.max(0, this.limit - arr.length), windowMs: this.windowMs };
  }

  prune() {
    const edge = Date.now() - this.windowMs;
    for (const [ip, arr] of this.table) {
      while (arr.length && arr[0] <= edge) arr.shift();
      if (arr.length === 0) this.table.delete(ip);
    }
  }

  // Buat auto-eksor tanpa perlu mengeksekusi list saat snapshot
  snapshot(ip = undefined) {
    const out = [];
    for (const [k, arr] of this.table) {
      if (ip && k !== ip) continue;
      out.push({ ip: k, count: arr.length, windowMs: this.windowMs });
    }
    return { limit: this.limit, windowMs: this.windowMs, entries: out };
  }
}

// Ambil IP klien di Vercel Edge (header proxy)
export function clientIp(request) {
  return (
    request.headers.get("x-vercel-forwarded-for") ||
    request.headers.get("x-vercel-ip") ||
    (request.headers.get("x-forwarded-for") || "").split(",")[0].trim() ||
    request.headers.get("x-real-ip") ||
    "unknown"
  );
}

export class RateLimiterKv {
  constructor({ limit = 60, windowMs = 60000, kv = null } = {}) {
    this.limit = limit >= 1 ? limit : 1;
    this.windowMs = windowMs > 0 ? windowMs : 60000;
    this.kv = kv;
    this.fallback = new SlidingWindowLimiter({ limit, windowMs });
    this.localCache = new Map();   // ip -> {count, ts}
    this.cacheMs = 500;            // durasi cache lokal singkat
  }

  // Kembalikan {allowed, remaining, retryAfterMs, source:"kv"|"local"}
  async hit(ip) {
    if (!this.kv) {
      const r = this.fallback.hit(ip);
      return { ...r, source: "local" };
    }
    const now = Date.now();
    const key = `sentinel:rl:${ip}`;
    try {
      // alive key (Redis) pakai TTL; INCR + EKSPRES saat window pertama
            const countNow = await this.kv.incr(key);            // INCR -> number
      // TTL disetti hanya saat key baru dibuat (race-condition-safe via NX-style check count==1)
      if (countNow === 1) await this.kv.expire(key, Math.ceil(this.windowMs / 1000));
      const remaining = Math.max(0, this.limit - countNow);
      const allowed = countNow <= this.limit;
      const retryAfterMs = allowed ? 0 : this.windowMs;
      return { allowed, remaining, retryAfterMs, windowMs: this.windowMs, source: "kv" };
    } catch (e) {
      // KV gagal -> pakai fallback lokal
      const r = this.fallback.hit(ip);
      return { ...r, source: "local-fallback" };
    }
  }
}
export default RateLimiterKv;