<?php
/**
 * threatfox_http.php — Guardias del transporte HTTP de ThreatFox (v0.4.28.20).
 *
 *   php tools/smoke/threatfox_http.php
 *
 * Comprueba por código fuente la compatibilidad del cliente (opciones cURL
 * opcionales, compresión, fallback de stream y degradación a 1 día), sin hacer
 * peticiones reales.
 */

declare(strict_types=1);

$root = dirname(__DIR__, 2);
$src = (string)@file_get_contents($root . '/public_html/includes/threatfox_api.php');
$ingest = (string)@file_get_contents($root . '/public_html/includes/threatfox_ingest.php');

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
check('Helper de opciones opcional',
    str_contains($src, 'function setOptionalCurlOption')
    && str_contains($src, 'function applyOptionalCurlOptions')
    && str_contains($src, 'catch (Throwable'));
$optionArrays = '';
if (preg_match_all('/curl_setopt_array\([^;]*?\]\);/s', $src, $matches)) {
    $optionArrays = implode("\n", $matches[0]);
}
check('Opciones opcionales fuera del array validado',
    !str_contains($optionArrays, 'CURLOPT_HTTP_VERSION')
    && !str_contains($optionArrays, 'CURLOPT_FRESH_CONNECT')
    && !str_contains($optionArrays, 'CURLOPT_FORBID_REUSE'), $optionArrays);
check('Timeouts configurados', str_contains($src, 'TIMEOUT = 60')
    && str_contains($src, 'CONNECT_TIMEOUT = 15')
    && substr_count($src, 'CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT') >= 2);
check('Reintento ante 429 y 5xx', str_contains($src, '$status === 429 || $status >= 500')
    && str_contains($src, '$http === 429 || $http >= 500'));
check('Error incluye curl_errno', str_contains($src, "curl_errno(")
    && str_contains($src, "'Error de red (curl ' . \$errno"));
check('Contrato client_error intacto', str_contains($src, "'query_status' => 'client_error'"));
check('Sin curl_error crudo en el mensaje final',
    !str_contains($src, "return \$this->error('Error de red: ' . \$err)"));

// --- v0.4.28.20: payload comprimido, fallback y degradación -----------------
check('Cabeceras: gzip y Connection close',
    str_contains($src, "Accept-Encoding: gzip, deflate") && str_contains($src, "Connection: close"));
check('Decodificación gzip/zlib', str_contains($src, 'function decodeBody')
    && str_contains($src, 'gzdecode') && str_contains($src, 'gzuncompress'));
check('Fallback de stream HTTP/1.1', str_contains($src, 'function callViaStream')
    && str_contains($src, 'stream_context_create')
    && str_contains($src, "'protocol_version' => 1.1")
    && str_contains($src, 'file_get_contents'));
check('Fallback se intenta tras cURL', str_contains($src, '$stream = $this->callViaStream($json)'));
check('Corte de transferencia (curl 18) no se reintenta',
    str_contains($src, 'CURLE_PARTIAL_FILE') && str_contains($src, 'if ($errno === $partial)'));
check('Degradación a 1 día en la ingesta',
    str_contains($ingest, '$days > 1') && str_contains($ingest, '$api->getIocs(1)'));

echo PHP_EOL . ($fail === 0
    ? 'RESULTADO: OK (' . $total . ' comprobaciones)'
    : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
