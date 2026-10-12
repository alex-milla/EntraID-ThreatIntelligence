<?php
/**
 * Diagnóstico — diagnostic.php
 * Súbelo a la raíz de public_html y accede a /diagnostic.php
 * para ver qué falla exactamente. BÓRRALO después de diagnosticar.
 */

declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');

echo "=== DIAGNÓSTICO EntraID TI ===\n\n";

// 1. Versión PHP
echo "1. PHP version: " . PHP_VERSION . "\n";
echo "   SAPI: " . php_sapi_name() . "\n\n";

// 2. Extensiones necesarias
$required = ['pdo', 'pdo_sqlite', 'curl', 'openssl', 'mbstring', 'json', 'session'];
echo "2. Extensiones:\n";
foreach ($required as $ext) {
    $loaded = extension_loaded($ext);
    echo "   $ext: " . ($loaded ? 'OK' : 'FALTA') . "\n";
}
echo "\n";

// 3. Funciones necesarias
echo "3. Funciones:\n";
$funcs = ['curl_init', 'openssl_encrypt', 'password_hash', 'random_bytes', 'mb_strtolower'];
foreach ($funcs as $fn) {
    echo "   $fn: " . (function_exists($fn) ? 'OK' : 'FALTA') . "\n";
}
echo "\n";

// 4. Permisos de escritura
echo "4. Permisos:\n";
$paths = [
    __DIR__ => 'public_html (raíz)',
    __DIR__ . '/storage' => 'storage/',
    __DIR__ . '/storage/cache' => 'storage/cache/',
    __DIR__ . '/storage/exports' => 'storage/exports/',
];
foreach ($paths as $path => $label) {
    $exists = is_dir($path);
    $writable = $exists && is_writable($path);
    echo "   $label: " . ($exists ? 'existe' : 'NO EXISTE') . ' / ' . ($writable ? 'escribible' : 'NO escribible') . "\n";
}
echo "\n";

// 5. Intentar crear la BD
echo "5. Prueba SQLite:\n";
try {
    $testDb = __DIR__ . '/storage/test_diagnostic.sqlite';
    @unlink($testDb);
    $pdo = new PDO('sqlite:' . $testDb);
    $pdo->exec('CREATE TABLE test (id INTEGER)');
    $pdo->exec('INSERT INTO test VALUES (1)');
    $row = $pdo->query('SELECT * FROM test')->fetch();
    echo "   SQLite funciona: OK (fila id=" . $row['id'] . ")\n";
    unlink($testDb);
} catch (Throwable $e) {
    echo "   SQLite ERROR: " . $e->getMessage() . "\n";
}
echo "\n";

// 6. Módulos de Apache (si está disponible)
echo "6. Apache modules:\n";
if (function_exists('apache_get_modules')) {
    $modules = apache_get_modules();
    foreach (['mod_rewrite', 'mod_headers', 'mod_deflate'] as $mod) {
        echo "   $mod: " . (in_array($mod, $modules) ? 'OK' : 'NO') . "\n";
    }
} else {
    echo "   (apache_get_modules no disponible — probablemente PHP-FPM/CGI)\n";
}
echo "\n";

// 7. Variables de servidor relevantes
echo "7. Servidor:\n";
echo "   DOCUMENT_ROOT: " . ($_SERVER['DOCUMENT_ROOT'] ?? 'N/A') . "\n";
echo "   SCRIPT_FILENAME: " . ($_SERVER['SCRIPT_FILENAME'] ?? 'N/A') . "\n";
echo "   REQUEST_URI: " . ($_SERVER['REQUEST_URI'] ?? 'N/A') . "\n";
echo "   HTTP_HOST: " . ($_SERVER['HTTP_HOST'] ?? 'N/A') . "\n";
echo "\n";

// 8. Intentar cargar el bootstrap
echo "8. Prueba de carga del código:\n";
try {
    // Simular .env mínimo
    if (!file_exists(__DIR__ . '/.env')) {
        file_put_contents(__DIR__ . '/.env', "APP_NAME=Test\nAPP_ENV=development\nAPP_DEBUG=true\nAPP_URL=http://" . ($_SERVER['HTTP_HOST'] ?? 'localhost') . "\nENCRYPTION_KEY=" . base64_encode(random_bytes(32)) . "\nSESSION_SECRET=" . bin2hex(random_bytes(32)) . "\n");
        echo "   .env creado automáticamente para pruebas\n";
    }

    require_once __DIR__ . '/config/config.php';
    echo "   config.php: OK\n";

    require_once __DIR__ . '/config/database.php';
    echo "   database.php: OK\n";

    $db = Database::getInstance();
    echo "   Conexión BD: OK\n";

    $tables = $db->query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN);
    echo "   Tablas creadas: " . count($tables) . "\n";
    foreach ($tables as $t) echo "     - $t\n";

} catch (Throwable $e) {
    echo "   ERROR: " . $e->getMessage() . "\n";
    echo "   Archivo: " . $e->getFile() . ":" . $e->getLine() . "\n";
    echo "   Trace:\n" . $e->getTraceAsString() . "\n";
}

echo "\n=== FIN DIAGNÓSTICO ===\n";
echo "BORRA ESTE ARCHIVO (diagnostic.php) después de usarlo.\n";
