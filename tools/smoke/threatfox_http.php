<?php
/**
 * threatfox_http.php — Guardias del transporte HTTP de ThreatFox (v0.4.28.18).
 *
 *   php tools/smoke/threatfox_http.php
 *
 * Comprueba por código fuente que el cliente fuerza HTTP/1.1 y reintenta ante
 * errores de red y respuestas 429/5xx, sin hacer peticiones reales.
 */

declare(strict_types=1);

$root = dirname(__DIR__, 2);
$src = (string)@file_get_contents($root . '/public_html/includes/threatfox_api.php');

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    if ($ok) {
        echo "OK   {$label}\n";
        return;
    }
    $fail++;
    echo "FALLO {$label}" . ($detail !== '' ? ' — ' . $detail : '') . "\n";
}

check('HTTP/1.1 forzado', str_contains($src, 'CURL_HTTP_VERSION_1_1')
    && str_contains($src, 'CURLOPT_HTTP_VERSION'));
check('HTTP/1.1 protegido con defined()', str_contains($src, "defined('CURL_HTTP_VERSION_1_1')"));
check('Reintentos acotados (3)', str_contains($src, 'RETRIES = 3'));
check('Backoff presente', str_contains($src, 'RETRY_DELAY_US')
    && str_contains($src, 'usleep('));
check('Bucle de reintento en call() y en el export',
    substr_count($src, '$attempt < self::RETRIES') >= 2);
check('Conexión nueva en reintentos',
    str_contains($src, 'CURLOPT_FRESH_CONNECT') && str_contains($src, 'CURLOPT_FORBID_REUSE'));
check('Reintento ante 429 y 5xx', str_contains($src, '$status === 429 || $status >= 500')
    && str_contains($src, '$http === 429 || $http >= 500'));
check('Error incluye curl_errno', str_contains($src, "curl_errno(")
    && str_contains($src, "'Error de red (curl ' . \$errno"));
check('Contrato client_error intacto', str_contains($src, "'query_status' => 'client_error'"));
check('Sin curl_error crudo en el mensaje final',
    !str_contains($src, "return \$this->error('Error de red: ' . \$err)"));

echo PHP_EOL . ($fail === 0
    ? 'RESULTADO: OK (' . $total . ' comprobaciones)'
    : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
