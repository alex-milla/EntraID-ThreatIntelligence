<?php
/**
 * Probe CLI del E2E del transporte LLM.
 *
 * Uso:
 *   php tools/smoke/llm-probe.php profile-create <provider> <url> <model> <key|-> [<max_tokens>]
 *   php tools/smoke/llm-probe.php profile-delete <id>
 *   php tools/smoke/llm-probe.php profile-state <id>
 *
 * `-` en un campo de texto significa cadena vacía (PowerShell omite los
 * argumentos vacíos).
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$cmd = (string)($argv[1] ?? '');

function arg(int $i): string
{
    global $argv;
    $v = trim((string)($argv[$i] ?? ''));
    return $v === '-' ? '' : $v;
}

if ($cmd === 'profile-create') {
    $provider = arg(2);
    $url = arg(3);
    $model = arg(4);
    $key = arg(5);
    $maxTokens = (int)(arg(6) !== '' ? arg(6) : 1024);

    if ($provider === '' || $url === '') {
        fwrite(STDERR, "Uso: profile-create <provider> <url> <model> <key|-> [max_tokens]\n");
        exit(2);
    }

    $id = llm_profile_save([
        'name'       => 'E2E transporte LLM (' . $provider . ')',
        'provider'   => $provider,
        'api_url'    => $url,
        'model'      => $model,
        'max_tokens' => $maxTokens,
        'api_key'    => $key,
    ]);
    echo json_encode(['id' => $id], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'profile-delete') {
    $id = (int)($argv[2] ?? 0);
    if ($id > 0) {
        llm_profile_delete($id);
    }
    echo json_encode(['deleted' => $id], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'profile-state') {
    $id = (int)($argv[2] ?? 0);
    $p = $id > 0 ? llm_profile_get($id) : null;
    echo json_encode([
        'exists'   => $p !== null,
        'provider' => $p['provider'] ?? null,
        'api_url'  => $p['api_url'] ?? null,
        'model'    => $p['model'] ?? null,
        'has_key'  => $p !== null && (string)($p['api_key'] ?? '') !== '',
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

fwrite(STDERR, "Comando no soportado: {$cmd}\n");
exit(2);
