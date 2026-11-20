<?php
/**
 * unit42-worker.php — descarga los ficheros nuevos del repo Unit42-timely-threat-intel.
 *
 * Cron recomendado (cada 6 horas):
 *
 *   0 0,6,12,18 * * * php /ruta/a/public_html/unit42-worker.php >/dev/null 2>&1
 *
 * Opciones:
 *   --status    solo muestra el estado local (sin descargar).
 *   --reparse   vuelve a parsear lo ya guardado, sin descargar nada.
 *
 * Solo compara blob SHAs: los ficheros ya descargados y sin cambios NO se bajan.
 * En CLI no requiere sesión; por HTTP solo funciona con sesión de administrador.
 */

declare(strict_types=1);

require_once __DIR__ . '/config/bootstrap.php';

$isCli = (PHP_SAPI === 'cli');
$args = $isCli ? array_slice($argv, 1) : [];

if (!$isCli) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    Auth::requireAdmin();
    $args = array_filter(explode(' ', (string)($_GET['args'] ?? '')));
}

if (function_exists('release_session_lock')) {
    release_session_lock();
}
@ignore_user_abort(true);
@set_time_limit(0);

$statusOnly = in_array('--status', $args, true);
$reparse = in_array('--reparse', $args, true);

try {
    if ($statusOnly) {
        echo json_encode(['success' => true, 'status' => Unit42Feed::status()], JSON_UNESCAPED_UNICODE) . PHP_EOL;
        exit(0);
    }

    if ($reparse) {
        $out = Unit42Feed::reparse();
        echo json_encode(['success' => true] + $out, JSON_UNESCAPED_UNICODE) . PHP_EOL;
        exit(0);
    }

    $summary = Unit42Feed::sync();
    echo json_encode([
        'success'   => (bool)($summary['ok'] ?? false),
        'total'     => (int)($summary['total'] ?? 0),
        'added'     => (int)($summary['added'] ?? 0),
        'updated'   => (int)($summary['updated'] ?? 0),
        'unchanged' => (int)($summary['unchanged'] ?? 0),
        'errors'    => $summary['errors'] ?? [],
    ], JSON_UNESCAPED_UNICODE) . PHP_EOL;

    exit(($summary['ok'] ?? false) ? 0 : 1);
} catch (Throwable $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE) . PHP_EOL;
    exit(1);
}
