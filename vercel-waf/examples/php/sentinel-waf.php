<?php
/**
 * sentinel-waf.php — Client PHP untuk Sentinel Edge WAF (Vercel)
 *
 * CARA PAKAI TERCEPAT (taruh di paling atas script/index.php):
 *   require_once __DIR__.'/sentinel-waf.php';
 *   SentinelWaf::guard();            // 403 otomatis kalau BLOCK
 *
 * Konfigurasi via env / define:
 *   SENTINEL_WAF_URL    -> https://sentinel-edge-waf.vercel.app
 *   SENTINEL_WAF_TOKEN  -> token admin (dibutuhkan /__waf/scan)
 *   SENTINEL_WAF_STRICT -> '1' = fail-closed (API mati -> blokir)
 */

class SentinelWaf
{
    private static ?string $baseUrl = null;
    private static ?string $token = null;
    public static int $timeout = 3;
    public static bool $strict = false;
    public static ?array $lastVerdict = null;

    public static function configure(
        ?string $baseUrl = null,
        ?string $token = null,
        ?bool $strict = null
    ): void {
        self::$baseUrl = $baseUrl ?? (getenv('SENTINEL_WAF_URL') ?: self::$baseUrl);
        self::$token   = $token   ?? (getenv('SENTINEL_WAF_TOKEN') ?: self::$token);
        self::$strict  = $strict  ?? self::$strict;
    }

    /** GUARD: scan request saat ini; 403+exit bila BLOCK */
    public static function guard(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri    = $_SERVER['REQUEST_URI']    ?? '/';
        $ua     = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $body   = '';
        if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $body = (string) file_get_contents('php://input');
        }

        $verdict = self::scan($method, $uri, $ua, $body);
        self::$lastVerdict = $verdict;

        if (is_array($verdict) && ($verdict['verdict'] ?? '') === 'BLOCK') {
            http_response_code(403);
            header('Content-Type: application/json');
            header('X-Sentinel-Waf: blocked');
            echo json_encode([
                'error'   => 'Forbidden',
                'code'    => 'WAF_BLOCKED',
                'score'   => $verdict['score']   ?? null,
                'matches' => array_slice($verdict['matches'] ?? [], 0, 10),
            ], JSON_UNESCAPED_SLASHES);
            exit;
        }
        if ($verdict === null && self::$strict) {
            http_response_code(503);
            header('X-Sentinel-Waf: unreachable');
            exit('WAF unreachable');
        }
    }
    /** SCAN: panggil /__waf/scan; return array verdict atau null bila gagal */
    public static function scan(string $method, string $path, string $userAgent = '', string $body = ''): ?array
    {
        $url = self::endpoint('scan');
        if ($url === null) return null;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::$timeout,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
            CURLOPT_POSTFIELDS     => json_encode([
                'method'    => $method,
                'path'      => $path,
                'userAgent' => $userAgent,
                'body'      => mb_substr($body, 0, 100000),
            ]),
        ]);
        $res  = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err  = curl_error($ch);
        curl_close($ch);

        if ($res === false || $code !== 200) {
            error_log("[SentinelWaf] scan gagal: http=$code err=$err");
            return null;
        }
        $json = json_decode($res, true);
        return is_array($json) ? $json : null;
    }

    /** STATUS: cek rate-limit/whitelist/geo untuk IP client */
    public static function status(): ?array
    {
        $url = self::endpoint('status');
        if ($url === null) return null;
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => self::$timeout]);
        $res = curl_exec($ch);
        curl_close($ch);
        $json = $res === false ? null : json_decode($res, true);
        return is_array($json) ? $json : null;
    }

    private static function endpoint(string $action): ?string
    {
        self::configure();
        if (!self::$baseUrl) {
            error_log('[SentinelWaf] SENTINEL_WAF_URL belum diset');
            return null;
        }
        $url = rtrim(self::$baseUrl, '/') . '/__waf/' . $action;
        if (self::$token) $url .= '?token=' . rawurlencode(self::$token);
        return $url;
    }

    /** IP asli dari header edge (bila request lewat Vercel WAF dulu) */
    public static function clientIp(): string
    {
        foreach (['HTTP_X_SENTINEL_IP', 'HTTP_X_VERCEL_FORWARDED_FOR', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $k) {
            if (!empty($_SERVER[$k])) return trim(explode(',', $_SERVER[$k])[0]);
        }
        return 'unknown';
    }
}
