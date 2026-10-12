<?php
/**
 * Entry Point — index.php
 * Punto de entrada único de la aplicación. Todas las peticiones
 * pasan por aquí (front controller pattern).
 */

declare(strict_types=1);

// Bootstrap: carga configuración, sesión, BD y módulos
require_once __DIR__ . '/config/bootstrap.php';

// ============================================================
// Inicializar router global
// ============================================================

$router = new Router();
$GLOBALS['router'] = $router;

// Los módulos se cargan en el bootstrap (antes de este punto);
// sus rutas se registran ahora que el router ya existe
ModuleManager::registerAllRoutes($router);

// Middleware global CSRF
Csrf::middleware();

// ============================================================
// Rutas públicas
// ============================================================

$router->get('/', function () {
    if (Auth::check()) {
        redirect(base_url('admin'));
    }
    redirect(base_url('admin/login'));
});

$router->get('/login', function () {
    redirect(base_url('admin/login'));
});

// ============================================================
// Rutas de administración
// ============================================================

$router->group('/admin', function (Router $r) {
    // Públicas
    $r->get('login', [AdminController::class, 'login']);
    $r->post('login', [AdminController::class, 'login']);
    $r->get('logout', [AdminController::class, 'logout']);

    // Protegidas
    $r->get('', [AdminController::class, 'dashboard']);
    $r->get('dashboard', [AdminController::class, 'dashboard']);

    // Gestión de tenants (solo admin)
    $r->get('tenants', [AdminController::class, 'tenants']);
    $r->get('tenant/edit', [AdminController::class, 'tenantEdit']);
    $r->post('tenant/edit', [AdminController::class, 'tenantEdit']);
    $r->post('tenant/delete', [AdminController::class, 'tenantDelete']);
    $r->post('tenant/toggle', [AdminController::class, 'tenantToggle']);

    // Gestión de usuarios (solo admin)
    $r->get('users', [AdminController::class, 'users']);
    $r->post('user/create', [AdminController::class, 'userCreate']);
    $r->post('user/delete', [AdminController::class, 'userDelete']);

    // Gestión de módulos (solo admin)
    $r->get('modules', [AdminController::class, 'modules']);
    $r->post('module/toggle', [AdminController::class, 'moduleToggle']);

    // Configuración (solo admin)
    $r->get('settings', [AdminController::class, 'settings']);
    $r->post('settings/save', [AdminController::class, 'settingsSave']);

    // Cambio de contraseña
    $r->get('change-password', [AdminController::class, 'changePassword']);
    $r->post('change-password', [AdminController::class, 'changePassword']);
});

// ============================================================
// Rutas de módulos (protegidas, registradas por cada módulo)
// ============================================================

// Los módulos registran sus propias rutas en boot() vía $GLOBALS['router']

$router->get('/modules/{moduleKey}', function ($params) {
    Auth::require();
    $module = ModuleManager::get($params['moduleKey']);
    if (!$module) {
        http_response_code(404);
        require VIEWS_PATH . '/errors/404.php';
        return;
    }
    $module->index($params);
});

// ============================================================
// API (requiere autenticación por sesión o token)
// ============================================================

// Las rutas /api/* se procesan en api/index.php
// El .htaccess redirige /api/* a api/index.php

// ============================================================
// Despachar
// ============================================================

$router->dispatch();
