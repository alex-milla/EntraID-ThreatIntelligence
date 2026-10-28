<?php
/**
 * threatfox-ingest.php — Ingesta diaria de IOCs de ThreatFox (abuse.ch).
 *
 * Ejecución recomendada por CLI (cron del hosting):
 *
 *   php /ruta/a/public_html/cron/threatfox-ingest.php --days=1 \
 *       >> /ruta/a/public_html/storage/threatfox-cron.log 2>&1
 *
 * Opciones:
 *   --days=N      Días a descargar (1-7, por defecto 1).
 *   --backfill     Descarga el histórico completo (~6 meses) por bloques.
 *   --purge        Borra los IOCs con más de 6 meses (la fuente los expira).
 *
 * También puede llamarse por URL con el token de CRON_TOKEN:
 *
 *   https://tu-dominio.com/cron/threatfox-ingest.php?token=TU_CRON_TOKEN
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

$args = [];
if ($isCli) {
    foreach (array_slice($argv ?? [], 1) as $arg) {
        if (preg_match('/^--([a-z0-9-]+)(?:=(.*))?$/i', $arg, $match)) {
            $args[strtolower($match[1])] = $match[2] ?? '1';
        }
    }
} else {
    $args = $_GET;
}

$days = isset($args['days']) ? (int)$args['days'] : THREATFOX_DEFAULT_DAYS;
$days = max(1, min(THREATFOX_DAYS_MAX, $days));
$doBackfill = !empty($args['backfill']) && (string)$args['backfill'] !== '0';
$doPurge = !empty($args['purge']) && (string)$args['purge'] !== '0';

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

$log('=== ThreatFox iniciado ===');

try {
    if ($doBackfill) {
        $log('Modo: histórico completo (~6 meses)');
        $result['backfill'] = ThreatfoxIngest::backfill();
        $log('Importadas: ' . $result['backfill']['rows'] . ' filas');
        $log('Total en la base: ' . $result['backfill']['total'] . ' IOCs');
    } else {
        $log('Modo: ingesta diaria de ' . $days . ' día(s)');
        $result['daily'] = ThreatfoxIngest::run($days);
        $log('Recibidas: ' . $result['daily']['received']);
        $log('Escritas: ' . $result['daily']['written']);
        $log('Total en la base: ' . $result['daily']['total'] . ' IOCs');
    }

    if ($doPurge) {
        $store = new ThreatfoxStore();
        $result['purged'] = $store->purgeExpired();
        $log('IOCs expirados eliminados: ' . $result['purged']);
    }
} catch (Throwable $e) {
    $ok = false;
    $log('ERROR: ' . $e->getMessage());
}

$log($ok ? '=== ThreatFox finalizado ===' : '=== ThreatFox finalizado con errores ===');

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
