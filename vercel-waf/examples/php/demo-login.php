<?php
/**
 * demo-login.php — contoh endpoint login yang diproteksi Sentinel Edge WAF.
 * Jalankan:  php -S localhost:8080  lalu buka http://localhost:8080/demo-login.php
 */
require_once __DIR__ . '/sentinel-waf.php';

SentinelWaf::configure(
    baseUrl: getenv('SENTINEL_WAF_URL')   ?: 'https://sentinel-edge-waf.vercel.app',
    token:   getenv('SENTINEL_WAF_TOKEN') ?: 'GANTI-DENGAN-TOKEN-ADMIN',
    strict:  false
);

// 1) WAF GUARD — 403 otomatis kalau payload dianggap serangan
SentinelWaf::guard();

header('Content-Type: application/json; charset=utf-8');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $user  = trim($input['user'] ?? '');
    $pass  = (string) ($input['pass'] ?? '');

    // 2) Contoh scan manual utk field spesifik (mis. validasi tambahan)
    $verdict = SentinelWaf::scan('POST', '/login', $_SERVER['HTTP_USER_AGENT'] ?? '', "user=$user&pass=$pass");

    if ($verdict === null) {
        http_response_code(503);
        echo json_encode(['error' => 'WAF unreachable']);
        exit;
    }
    if ($verdict['verdict'] === 'BLOCK') {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden', 'detail' => $verdict]);
        exit;
    }

    // (dummy auth — ganti dengan DB asli kamu)
    if ($user === 'admin' && $pass === 's3cr3t') {
        echo json_encode(['ok' => true, 'msg' => 'login sukses', 'ip' => SentinelWaf::clientIp(), 'waf' => $verdict]);
    } else {
        http_response_code(401);
        echo json_encode(['ok' => false, 'msg' => 'kredensial salah']);
    }
    exit;
}
?>
<!-- Form demo untuk dicoba di browser -->
<form method="POST" action="demo-login.php" style="font-family:sans-serif;max-width:320px;margin:4rem auto;display:grid;gap:.5rem">
  <h2>Demo Login (dilindungi Sentinel WAF)</h2>
  <input name="user" placeholder="user (coba: admin' OR 1=1--)">
  <input name="pass" type="password" placeholder="pass">
  <button>login</button>
  <p style="font-size:12px;color:#888">Coba user: <code>admin' OR 1=1--</code> → akan 403 WAF_BLOCKED</p>
</form>
