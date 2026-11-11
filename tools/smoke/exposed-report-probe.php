<?php
/**
 * Probe CLI del E2E de Equipos expuestos.
 *
 * Uso:
 *   php tools/smoke/exposed-report-probe.php profile-create <url>
 *   php tools/smoke/exposed-report-probe.php profile-delete <id>
 *   php tools/smoke/exposed-report-probe.php profile-state <id>
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$cmd = (string)($argv[1] ?? '');

if ($cmd === 'profile-create') {
    $url = trim((string)($argv[2] ?? ''));
    if ($url === '') {
        fwrite(STDERR, "Falta la URL del LLM falso\n");
        exit(2);
    }
    $id = llm_profile_save([
        'name'       => 'E2E Equipos expuestos (fake)',
        'provider'   => 'ollama',
        'api_url'    => $url,
        'model'      => 'e2e-fake-model',
        'max_tokens' => 1024,
        'api_key'    => '',
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
    $profile = $id > 0 ? llm_profile_get($id) : null;
    echo json_encode([
        'exists'   => $profile !== null,
        'provider' => $profile['provider'] ?? null,
        'model'    => $profile['model'] ?? null,
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

fwrite(STDERR, "Comando no soportado: {$cmd}\n");
exit(2);
