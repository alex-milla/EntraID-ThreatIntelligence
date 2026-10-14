<?php
/**
 * sync-worker.php — Worker de sincronización en SEGUNDO PLANO.
 *
 * Lo llama el propio servidor (petición "fire-and-forget") para ejecutar un
 * tramo de un job de sincronización y encadenar el siguiente. NO usa la sesión
 * del usuario (por eso no la bloquea). Se autoriza con el token aleatorio del
 * job (guardado en `sync_jobs`).
 *
 * URL: /sync-worker.php?job=<id>&token=<token>
 */

declare(strict_types=1);

require_once __DIR__ . '/config/bootstrap.php';

@ignore_user_abort(true);
@set_time_limit(0);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

$jobId = (int)($_GET['job'] ?? 0);
$token = (string)($_GET['token'] ?? '');

if ($jobId <= 0 || $token === '') {
    http_response_code(400);
    echo '{"error":"bad request"}';
    exit;
}

$module = ModuleManager::get('threat_intelligence');
if (!($module instanceof Module_ThreatIntelligence)) {
    http_response_code(503);
    echo '{"error":"module unavailable"}';
    exit;
}

$state = [];
try {
    $state = $module->runSyncJob($jobId, $token);
} catch (Throwable $e) {
    try {
        Database::query(
            "UPDATE sync_jobs SET status='error', message=?, finished_at=datetime('now'), updated_at=datetime('now') WHERE id=?",
            [substr($e->getMessage(), 0, 500), $jobId]
        );
    } catch (Throwable $e2) { /* noop */ }
    $state = ['success' => false, 'done' => true, 'error' => $e->getMessage()];
}

// Responder al llamante y "soltar" la conexión: el trabajo pesado ya está hecho
// en este tramo; lo que quede se encadena abajo en una nueva petición.
echo json_encode([
    'ok'     => true,
    'done'   => !empty($state['done']),
    'status' => (string)($state['status'] ?? ''),
]);

if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
} else {
    if (ob_get_level() > 0) { @ob_end_flush(); }
    @flush();
}

// Encadenar el siguiente tramo si el job sigue activo.
if (empty($state['done'])) {
    $base = (string)($state['base_url'] ?? '');
    $tk   = (string)($state['token'] ?? '');
    if ($base !== '' && $tk !== '') {
        background_request(rtrim($base, '/') . '/sync-worker.php?job=' . $jobId . '&token=' . rawurlencode($tk));
    }
}
