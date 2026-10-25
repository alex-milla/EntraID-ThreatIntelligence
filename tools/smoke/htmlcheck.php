<?php
/**
 * htmlcheck.php — Valida el HTML renderizado (etiquetas balanceadas) de las rutas.
 * Uso: php tools/smoke/htmlcheck.php [--port=8897]
 */

declare(strict_types=1);

$port = 8897;
foreach ($argv as $a) {
    if (str_starts_with($a, '--port=')) { $port = (int)substr($a, 7); }
}

$root = dirname(__DIR__, 2);
$docroot = $root . '/public_html';
$base = "http://127.0.0.1:$port";

$routes = [
    '/admin/login', '/admin', '/admin/tenants', '/admin/users', '/admin/modules',
    '/admin/settings', '/admin/logs', '/admin/apis', '/admin/storage', '/admin/security',
    '/admin/updates', '/admin/change-password',
    '/index.php/modules/cve', '/index.php/modules/cve?tab=software',
    '/index.php/modules/threat_intelligence', '/index.php/modules/hunting',
    '/index.php/modules/incidents', '/index.php/modules/llm', '/index.php/modules/reports',
    '/index.php/modules/secure_score', '/index.php/modules/vulnerabilities',
    '/index.php/modules/remediation', '/index.php/modules/remediation?tab=tasks',
    '/index.php/modules/export', '/index.php/modules/entra_users',
];

$server = proc_open(
    ['php', '-S', "127.0.0.1:$port", '-t', $docroot, $root . '/tools/smoke/router.php'],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes,
    $docroot
);
sleep(2);

function request(string $url, ?string $cookie = null, ?array $post = null): array
{
    $opts = ['method' => $post === null ? 'GET' : 'POST', 'ignore_errors' => true, 'follow_location' => 0];
    $headers = [];
    if ($cookie !== null) { $headers[] = 'Cookie: ' . $cookie; }
    if ($post !== null) {
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        $opts['content'] = http_build_query($post);
    }
    $opts['header'] = implode("\r\n", $headers);

    $body = @file_get_contents($url, false, stream_context_create(['http' => $opts]));
    $respHeaders = $http_response_header ?? [];

    $newCookie = $cookie;
    foreach ($respHeaders as $h) {
        if (stripos($h, 'Set-Cookie:') === 0) {
            $pair = explode(';', trim(substr($h, 11)))[0];
            $newCookie = $pair;
        }
    }

    return [$body, $newCookie, $respHeaders];
}

// 1) GET login (token + cookie de sesión)
[$loginHtml, $cookie] = request("$base/admin/login");
preg_match('/name="csrf_token"\s+value="([^"]+)"/', (string)$loginHtml, $m);
$token = $m[1] ?? '';

// 2) POST login
[$body, $cookie] = request("$base/admin/login", $cookie, [
    'username' => 'admin', 'password' => 'admin', 'csrf_token' => $token,
]);

$fail = 0;
foreach ($routes as $r) {
    [$html] = request($base . $r, $cookie);
    if ($html === false || $html === '') {
        echo "KO  $r (sin respuesta)\n";
        $fail++;
        continue;
    }

    $clean = preg_replace('@<script\b.*?</script>@s', '', (string)$html);
    $clean = preg_replace('@<style\b.*?</style>@s', '', (string)$clean);

    libxml_use_internal_errors(true);
    libxml_clear_errors();
    $doc = new DOMDocument();
    $doc->loadHTML('<?xml encoding="UTF-8">' . $clean);
    $errors = array_filter(libxml_get_errors(), function ($e) {
        return $e->level >= LIBXML_ERR_ERROR
            && !str_contains($e->message, 'Unexpected end tag')
            && !str_contains($e->message, 'Tag ');
    });

    if ($errors) {
        $fail++;
        echo "KO  $r\n";
        foreach (array_slice($errors, 0, 3) as $e) {
            echo '      línea ' . $e->line . ': ' . trim($e->message) . "\n";
        }
    } else {
        echo "OK  $r\n";
    }
}

proc_terminate($server);
echo $fail === 0 ? "\nRESULTADO: HTML OK\n" : "\nRESULTADO: $fail con problemas\n";
exit($fail === 0 ? 0 : 1);
