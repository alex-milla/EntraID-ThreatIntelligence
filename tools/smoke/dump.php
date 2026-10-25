<?php
/**
 * dump.php — Imprime líneas concretas del HTML renderizado (depuración).
 * Uso: php tools/smoke/dump.php <ruta> <desde> <hasta>
 */
declare(strict_types=1);

$route = $argv[1] ?? '/admin';
$from  = (int)($argv[2] ?? 1);
$to    = (int)($argv[3] ?? 5);
$port  = 8896;
$root  = dirname(__DIR__, 2);
$base  = "http://127.0.0.1:$port";

$server = proc_open(['php', '-S', "127.0.0.1:$port", '-t', $root . '/public_html', $root . '/tools/smoke/router.php'],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root . '/public_html');
sleep(2);

function req(string $url, ?string $cookie = null, ?array $post = null): array
{
    $opts = ['method' => $post === null ? 'GET' : 'POST', 'ignore_errors' => true, 'follow_location' => 0];
    $h = [];
    if ($cookie !== null) { $h[] = 'Cookie: ' . $cookie; }
    if ($post !== null) { $h[] = 'Content-Type: application/x-www-form-urlencoded'; $opts['content'] = http_build_query($post); }
    $opts['header'] = implode("\r\n", $h);
    $body = @file_get_contents($url, false, stream_context_create(['http' => $opts]));
    $nc = $cookie;
    foreach ($http_response_header ?? [] as $x) {
        if (stripos($x, 'Set-Cookie:') === 0) { $nc = explode(';', trim(substr($x, 11)))[0]; }
    }
    return [$body, $nc];
}

[$login, $c] = req("$base/admin/login");
preg_match('/name="csrf_token"\s+value="([^"]+)"/', (string)$login, $m);
req("$base/admin/login", $c, ['username' => 'admin', 'password' => 'admin', 'csrf_token' => $m[1] ?? '']);
[$html] = req($base . $route, $c);

$lines = preg_split('/\R/', (string)$html);
for ($i = $from - 1; $i < min($to, count($lines)); $i++) {
    printf("%4d| %s\n", $i + 1, substr($lines[$i], 0, 400));
}

proc_terminate($server);
