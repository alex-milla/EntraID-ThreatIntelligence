<?php
/**
 * Bootstrap — inicialización de la aplicación.
 * Carga configuración, inicia sesión y registra el autoloader.
 */

declare(strict_types=1);

// Prevenir acceso directo
if (!defined('ROOT_PATH')) {
    require_once __DIR__ . '/config.php';
}

// ============================================================
// Autoloader de clases
// ============================================================

spl_autoload_register(function (string $class): void {
    // TenantManager -> tenant_manager (soporta snake_case en nombres de archivo)
    $snake = strtolower(preg_replace('/([a-z0-9])([A-Z])/', '$1_$2', $class) ?? $class);
    $paths = [
        INCLUDES_PATH . '/' . strtolower(str_replace('\\', '/', $class)) . '.php',
        INCLUDES_PATH . '/' . strtolower($class) . '.php',
        INCLUDES_PATH . '/' . $snake . '.php',
        CONFIG_PATH . '/' . strtolower($class) . '.php',
        CONFIG_PATH . '/' . $snake . '.php',
        MODULES_PATH . '/' . strtolower($class) . '.php',
    ];
    foreach ($paths as $path) {
        if (file_exists($path)) {
            require_once $path;
            return;
        }
    }
});

// ============================================================
// Inicializar sesión segura
// ============================================================

if (session_status() === PHP_SESSION_NONE) {
    // Detecta HTTPS aunque haya un proxy/CDN delante
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https');

    // Configuración segura de sesión
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_secure', $isHttps ? '1' : '0');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.gc_maxlifetime', '7200'); // 2 horas

    session_name('ENTRAID_TI_SESSION');
    session_start();

    // Regenerar ID de sesión periódicamente
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } elseif (time() - $_SESSION['created'] > 1800) {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
}

// ============================================================
// Cargar helpers y clases base
// ============================================================

require_once INCLUDES_PATH . '/helpers.php';
require_once INCLUDES_PATH . '/llm_prompts.php';
require_once INCLUDES_PATH . '/encryption.php';
require_once INCLUDES_PATH . '/csrf.php';
require_once INCLUDES_PATH . '/session.php';
require_once INCLUDES_PATH . '/auth.php';
require_once INCLUDES_PATH . '/router.php';
require_once INCLUDES_PATH . '/graph_client.php';
require_once INCLUDES_PATH . '/tenant_manager.php';
require_once INCLUDES_PATH . '/module_manager.php';
require_once CONFIG_PATH . '/database.php';

// Inicializar base de datos (crea el esquema si no existe)
Database::getInstance();

// ============================================================
// Inicializar gestor de módulos
// ============================================================

ModuleManager::init();
