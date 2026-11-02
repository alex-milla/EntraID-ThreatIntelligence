<?php
/**
 * Probe CLI del E2E de Incidentes Story.
 *
 * Uso:
 *   php tools/smoke/incident-story-probe.php profile-create <url>
 *   php tools/smoke/incident-story-probe.php state
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
        'name'       => 'E2E Incident Story (fake)',
        'provider'   => 'ollama',
        'api_url'    => $url,
        'model'      => 'e2e-fake-model',
        'max_tokens' => 512,
        'api_key'    => '',
    ]);
    echo json_encode(['id' => $id], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'state') {
    $store = new IncidentStoryStore();
    $cases = $store->listCases(50);
    $latest = $cases[0] ?? null;
    $full = $latest !== null ? $store->getCase((int)$latest['id']) : null;
    echo json_encode([
        'count'         => count($cases),
        'id'            => $latest !== null ? (int)$latest['id'] : 0,
        'verdict'       => $latest['triage_verdict'] ?? null,
        'triage_at'     => $latest['triage_at'] ?? null,
        'triage_length' => $full !== null && is_array($full['triage']) ? strlen((string)json_encode($full['triage'])) : 0,
        'triage_keys'   => $full !== null && is_array($full['triage']) ? array_keys($full['triage']) : [],
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

fwrite(STDERR, "Comando no soportado: {$cmd}\n");
exit(2);
