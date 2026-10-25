<?php
/**
 * Router de desarrollo para `php -S`, emula las reglas de .htaccess del proyecto:
 *   /api/*    -> api/index.php
 *   /admin/*  -> admin/index.php
 *   /*        -> index.php  (front controller)
 *
 * Uso:
 *   php -S 127.0.0.1:8899 -t public_html tools/smoke/router.php
 *
 * No se despliega al hosting: vive fuera de public_html.
 */

declare(strict_types=1);

$root = dirname(__DIR__, 2) . '/public_html';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
$file = $root . $path;

// Archivos reales (css, js, fuentes, imágenes) se sirven tal cual.
if ($path !== '/' && is_file($file)) {
    return false;
}

if (str_starts_with($path, '/api')) {
    $_SERVER['SCRIPT_NAME'] = '/api/index.php';
    require $root . '/api/index.php';
    return true;
}

if (str_starts_with($path, '/admin')) {
    $_SERVER['SCRIPT_NAME'] = '/admin/index.php';
    require $root . '/admin/index.php';
    return true;
}

$_SERVER['SCRIPT_NAME'] = '/index.php';
require $root . '/index.php';
return true;
