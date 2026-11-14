<?php
/**
 * ai-queue-worker.php — drena la cola de informes IA por CVE.
 *
 * Pensado para cron (recomendado, cada 5 minutos):
 *
 *   php /ruta/a/public_html/ai-queue-worker.php
 *
 * Recoge los informes que quedaron en `pending` (o `running` huérfanos) y los
 * procesa uno a uno respetando el cerrojo único de trabajos de IA: si en ese
 * momento está corriendo otro trabajo (equipos expuestos, traducción,
 * asistente…), no lo pisa y termina sin hacer nada.
 *
 * No requiere sesión en CLI. Por HTTP solo funciona con sesión de admin.
 */

declare(strict_types=1);

require_once __DIR__ . '/config/bootstrap.php';

$isCli = (PHP_SAPI === 'cli');

if (!$isCli) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    Auth::requireAdmin();
}

if (function_exists('release_session_lock')) {
    release_session_lock();
}
@ignore_user_abort(true);
@set_time_limit(0);

try {
    $result = CveReportAi::runQueue('cve-queue-worker', 200);
} catch (Throwable $e) {
    $result = ['success' => false, 'error' => $e->getMessage()];
}

$payload = [
    'success'   => !empty($result['success']),
    'processed' => (int)($result['processed'] ?? 0),
    'done'      => (int)($result['done'] ?? 0),
    'failed'    => (int)($result['failed'] ?? 0),
    'locked'    => !empty($result['locked']),
    'ids'       => $result['ids'] ?? [],
    'error'     => $result['error'] ?? null,
];

if ($isCli) {
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), PHP_EOL;
    exit(!empty($result['success']) ? 0 : 1);
}

echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if (function_exists('finish_response')) {
    finish_response();
}
