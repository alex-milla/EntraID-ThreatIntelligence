<?php
/**
 * Cron — Sincronización programada de todos los tenants activos.
 * Ejecutar vía cron del hosting compartido, p.ej. cada hora:
 *
 *   0 * * * * php /ruta/a/public_html/cron/sync.php >> /ruta/a/storage/cron.log 2>&1
 *
 * O vía URL protegida con token:
 *
 *   0 * * * * curl -s "https://tu-dominio.com/cron/sync.php?token=TU_CRON_TOKEN"
 */

declare(strict_types=1);

// Este script puede ejecutarse vía CLI o vía web
$isCli = PHP_SAPI === 'cli';

// Si es vía web, verificar token
if (!$isCli) {
    $token = $_GET['token'] ?? '';
    if (empty(CRON_TOKEN) || !hash_equals(CRON_TOKEN, $token)) {
        http_response_code(403);
        echo json_encode(['error' => 'Token inválido']);
        exit;
    }
    header('Content-Type: application/json');
}

// Cargar bootstrap (sin iniciar sesión de usuario)
require_once __DIR__ . '/../config/config.php';
require_once INCLUDES_PATH . '/helpers.php';
require_once INCLUDES_PATH . '/encryption.php';
require_once INCLUDES_PATH . '/graph_client.php';
require_once INCLUDES_PATH . '/tenant_manager.php';
require_once INCLUDES_PATH . '/module_manager.php';

// Inicializar BD
Database::getInstance();
ModuleManager::init();

$log = function (string $msg) use ($isCli): void {
    $line = '[' . date('Y-m-d H:i:s') . '] ' . $msg;
    if ($isCli) {
        echo $line . "\n";
    } else {
        echo $line . "\n";
    }
};

$log('=== Iniciando sincronización programada ===');

// Obtener todos los tenants activos
$tenants = TenantManager::getActive();
$log(sprintf('Tenants activos: %d', count($tenants)));

$totalSuccess = 0;
$totalErrors = 0;

foreach ($tenants as $tenant) {
    $tenantId = (int)$tenant['id'];
    $log(sprintf('--- Sincronizando tenant: %s (ID: %d) ---', $tenant['name'], $tenantId));

    $results = ModuleManager::syncAll($tenantId);

    foreach ($results as $moduleKey => $result) {
        if ($result['success']) {
            $log(sprintf('  [%s] OK — %d registros', $moduleKey, $result['records'] ?? 0));
            $totalSuccess++;
        } else {
            $log(sprintf('  [%s] ERROR — %s', $moduleKey, $result['error'] ?? 'Error desconocido'));
            $totalErrors++;
        }
    }
}

$log(sprintf('=== Finalizado: %d OK, %d errores ===', $totalSuccess, $totalErrors));

if (!$isCli) {
    echo json_encode([
        'success' => true,
        'tenants' => count($tenants),
        'ok'      => $totalSuccess,
        'errors'  => $totalErrors,
        'time'    => date('c'),
    ]);
}
