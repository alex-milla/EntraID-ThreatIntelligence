<?php
/**
 * ti-tracker-run.php — Refresco diario del Seguimiento TI.
 *
 * Ejecuta las búsquedas guardadas contra la base local de IOCs ThreatFox
 * (storage/threatfox.sqlite, sin red) y actualiza los IOCs vistos y las
 * novedades. Las búsquedas configuradas contra la API en vivo se omiten.
 *
 * Ejecución recomendada por CLI, después de threatfox-ingest.php:
 *
 *   php /ruta/a/public_html/cron/threatfox-ingest.php --days=1 \
 *       >> /ruta/a/public_html/storage/threatfox-cron.log 2>&1
 *   php /ruta/a/public_html/cron/ti-tracker-run.php \
 *       >> /ruta/a/public_html/storage/ti-tracker-cron.log 2>&1
 *
 * También puede llamarse por URL con el token de CRON_TOKEN:
 *
 *   https://tu-dominio.com/cron/ti-tracker-run.php?token=TU_CRON_TOKEN
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';

$isCli = PHP_SAPI === 'cli';

if (!$isCli) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    $token = (string)($_GET['token'] ?? '');
    if (CRON_TOKEN === '' || !hash_equals(CRON_TOKEN, $token)) {
        http_response_code(403);
        echo json_encode(['error' => 'Token inválido'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

require_once CONFIG_PATH . '/bootstrap.php';

if (function_exists('release_session_lock')) {
    release_session_lock();
}
@ignore_user_abort(true);
@set_time_limit(0);
@ini_set('memory_limit', '256M');

$logs = [];
$log = static function (string $message) use ($isCli, &$logs): void {
    $line = '[' . date('Y-m-d H:i:s') . '] ' . $message;
    $logs[] = $line;
    if ($isCli) {
        echo $line . PHP_EOL;
    }
};

$ok = true;
$result = [];

$log('=== Seguimiento TI iniciado ===');

try {
    $store = new TiTrackerStore();
    $searches = $store->listSearches();
    $log('Búsquedas guardadas: ' . count($searches));

    foreach ($searches as $search) {
        $name = (string)$search['name'];
        $filters = TiTrackerRunner::filtersFor($search);

        if ((string)($filters['source'] ?? 'db') === 'api') {
            $log('OMITIDA (API en vivo): ' . $name);
            continue;
        }

        try {
            $exec = TiTrackerRunner::execute($store, $search);
            $rows = (int)$exec['result']['rows'];
            $new = (int)$exec['result']['new'];
            $result[] = ['search' => $name, 'rows' => $rows, 'new' => $new];
            $log(sprintf('%s: %d IOCs, %d nuevos', $name, $rows, $new));
        } catch (Throwable $e) {
            $ok = false;
            $log('ERROR en «' . $name . '»: ' . $e->getMessage());
        }
    }
} catch (Throwable $e) {
    $ok = false;
    $log('ERROR: ' . $e->getMessage());
}

$log($ok ? '=== Seguimiento TI finalizado ===' : '=== Seguimiento TI finalizado con errores ===');

if ($isCli) {
    exit($ok ? 0 : 1);
}

http_response_code($ok ? 200 : 500);
echo json_encode([
    'success' => $ok,
    'result'  => $result,
    'logs'    => $logs,
    'time'    => date('c'),
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
