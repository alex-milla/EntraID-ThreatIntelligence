<?php
/**
 * Setup — Asistente de instalación inicial.
 *
 * SÚBELO A LA RAÍZ, ejecútalo en el navegador, y luego BÓRRALO.
 *
 * Verifica requisitos, crea directorios, genera .env con claves seguras,
 * e inicializa la base de datos SQLite.
 */

declare(strict_types=1);

// Mostrar todos los errores para diagnóstico
error_reporting(E_ALL);
ini_set('display_errors', '1');

header('Content-Type: text/html; charset=utf-8');

$rootPath = __DIR__;
$results = [];
$errors = [];
$warnings = [];

function ok(string $msg): void { global $results; $results[] = ['ok', $msg]; }
function warn(string $msg): void { global $warnings; $warnings[] = $msg; }
function err(string $msg): void { global $errors; $errors[] = $msg; }

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Setup — EntraID Threat Intelligence</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f5f5f5; }
        h1 { color: #1a1a2e; }
        .card { background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .ok { color: #16a34a; }
        .warn { color: #d97706; }
        .err { color: #dc2626; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge-ok { background: #dcfce7; color: #16a34a; }
        .badge-warn { background: #fef3c7; color: #d97706; }
        .badge-err { background: #fee2e2; color: #dc2626; }
        pre { background: #1a1a2e; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 13px; }
        .btn { display: inline-block; padding: 10px 20px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 500; }
        .btn:hover { background: #1d4ed8; }
        .btn-danger { background: #dc2626; }
        .btn-danger:hover { background: #b91c1c; }
        table { width: 100%; border-collapse: collapse; }
        td, th { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
        th { font-weight: 600; color: #374151; }
        code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
    </style>
</head>
<body>
    <h1>Setup — EntraID Threat Intelligence</h1>

<?php

// ============================================================
// 1. Verificar versión de PHP
// ============================================================

$phpVersion = PHP_VERSION;
$phpOk = version_compare($phpVersion, '7.4.0', '>=');
if ($phpOk) {
    $verBadge = version_compare($phpVersion, '8.4.0', '>=') ? ' (8.4 OK)' : '';
    ok("PHP $phpVersion$verBadge (requerido: >= 7.4, recomendado: 8.x)");
} else {
    err("PHP $phpVersion — se requiere PHP 7.4 o superior");
}

// ============================================================
// 2. Verificar extensiones
// ============================================================

$requiredExts = [
    'pdo'         => 'PDO (requerido para SQLite)',
    'pdo_sqlite'  => 'PDO SQLite (base de datos)',
    'curl'        => 'cURL (llamadas a Microsoft Graph)',
    'openssl'     => 'OpenSSL (cifrado AES-256)',
    'mbstring'    => 'Mbstring (cadenas multibyte)',
    'json'        => 'JSON (APIs)',
    'session'     => 'Session (autenticación)',
];

echo '<div class="card"><h2>Extensiones PHP</h2><table>';
echo '<tr><th>Extensión</th><th>Descripción</th><th>Estado</th></tr>';
foreach ($requiredExts as $ext => $desc) {
    $loaded = extension_loaded($ext);
    echo '<tr>';
    echo '<td><code>' . $ext . '</code></td>';
    echo '<td>' . $desc . '</td>';
    echo '<td>' . ($loaded
        ? '<span class="badge badge-ok">OK</span>'
        : '<span class="badge badge-err">FALTA</span>') . '</td>';
    echo '</tr>';
    if ($loaded) {
        ok("$ext: $desc");
    } else {
        err("Falta la extensión $ext — $desc");
    }
}
echo '</table></div>';

// ============================================================
// 3. Verificar permisos de escritura
// ============================================================

echo '<div class="card"><h2>Permisos de escritura</h2><table>';
echo '<tr><th>Ruta</th><th>Estado</th><th>Acción</th></tr>';

$dirs = [
    $rootPath . '/storage'         => 'storage/',
    $rootPath . '/storage/cache'   => 'storage/cache/',
    $rootPath . '/storage/exports' => 'storage/exports/',
];

$allWritable = true;
foreach ($dirs as $dir => $label) {
    $exists = is_dir($dir);
    $writable = $exists && is_writable($dir);

    echo '<tr>';
    echo '<td><code>' . $label . '</code></td>';

    if (!$exists) {
        // Intentar crear
        $created = @mkdir($dir, 0755, true);
        if ($created) {
            @chmod($dir, 0755);
            echo '<td><span class="badge badge-ok">Creado</span></td>';
            echo '<td>Directorio creado automáticamente</td>';
            ok("$label: creada automáticamente");
        } else {
            echo '<td><span class="badge badge-err">NO EXISTE</span></td>';
            echo '<td>Crea el directorio manualmente con permisos 755</td>';
            err("$label: no existe y no se pudo crear");
            $allWritable = false;
        }
    } elseif (!$writable) {
        // Intentar cambiar permisos
        @chmod($dir, 0755);
        $nowWritable = is_writable($dir);
        if ($nowWritable) {
            echo '<td><span class="badge badge-ok">Corregido</span></td>';
            echo '<td>Permisos ajustados a 755</td>';
            ok("$label: permisos corregidos");
        } else {
            echo '<td><span class="badge badge-err">NO ESCRIBIBLE</span></td>';
            echo '<td>Cambia permisos a 755 o 775 vía FTP/cPanel</td>';
            err("$label: no es escribible");
            $allWritable = false;
        }
    } else {
        echo '<td><span class="badge badge-ok">OK</span></td>';
        echo '<td>Escribible</td>';
        ok("$label: escribible");
    }
    echo '</tr>';
}
echo '</table></div>';

// ============================================================
// 4. Generar .env si no existe
// ============================================================

$envPath = $rootPath . '/.env';
$envCreated = false;

if (!file_exists($envPath)) {
    echo '<div class="card"><h2>Archivo .env</h2>';

    // Detectar URL automáticamente (respetando proxies)
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https');
    $protocol = $isHttps ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $appUrl = $protocol . '://' . $host;

    // Detectar si estamos en un subdirectorio
    $scriptDir = dirname($_SERVER['SCRIPT_NAME'] ?? '');
    if ($scriptDir !== '/' && $scriptDir !== '\\' && $scriptDir !== '.') {
        $appUrl .= rtrim($scriptDir, '/');
    }

    $encryptionKey = base64_encode(random_bytes(32));
    $sessionSecret = bin2hex(random_bytes(32));
    $cronToken = bin2hex(random_bytes(32));

    $envContent = <<<ENV
# ============================================================
# EntraID Threat Intelligence — Configuración
# Generado automáticamente por setup.php
# ============================================================

APP_NAME=EntraID Threat Intelligence
APP_ENV=production
APP_DEBUG=false
APP_URL=$appUrl
APP_TIMEZONE=Europe/Madrid

# Seguridad — CLAVES GENERADAS AUTOMÁTICAMENTE (NO COMPARTIR)
ENCRYPTION_KEY=$encryptionKey
SESSION_SECRET=$sessionSecret

# Base de datos
DB_PATH=storage/database.sqlite

# Catálogo público de CVEs (opcional)
CVE_DB_PATH=storage/cve.sqlite
NVD_API_KEY=

# LLM (configurar manualmente si se usa)
LLM_PROVIDER=
LLM_API_KEY=
LLM_API_URL=
LLM_MODEL=
LLM_MAX_TOKENS=2048

# Cron
CRON_TOKEN=$cronToken
CRON_SYNC_INTERVAL=3600
ENV;

    $written = @file_put_contents($envPath, $envContent);
    if ($written) {
        @chmod($envPath, 0640);
        echo '<p><span class="badge badge-ok">Creado</span> Archivo .env generado con claves seguras.</p>';
        echo '<pre>' . htmlspecialchars("APP_URL=$appUrl\nENCRYPTION_KEY=$encryptionKey\nSESSION_SECRET=$sessionSecret\nCRON_TOKEN=$cronToken") . '</pre>';
        ok('.env: creado con claves aleatorias seguras');
        $envCreated = true;
    } else {
        echo '<p><span class="badge badge-err">ERROR</span> No se pudo crear .env. Crea el archivo manualmente copiando .env.example</p>';
        err('.env: no se pudo crear automáticamente');
    }
    echo '</div>';
} else {
    ok('.env: ya existe');
    $envCreated = true;
}

// ============================================================
// 5. Probar carga del bootstrap
// ============================================================

echo '<div class="card"><h2>Prueba de la aplicación</h2>';

if ($envCreated && $allWritable && empty($errors)) {
    try {
        // Cargar bootstrap completo (config + helpers + BD + módulos)
        require_once $rootPath . '/config/bootstrap.php';
        ok('bootstrap.php: cargado correctamente (config, helpers, sesión, BD)');

        $db = Database::getInstance();
        ok('Conexión SQLite: establecida');

        $tables = $db->query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN);
        echo '<p><span class="badge badge-ok">OK</span> Base de datos inicializada con ' . count($tables) . ' tablas:</p>';
        echo '<pre>' . implode(', ', $tables) . '</pre>';
        ok('Base de datos: ' . count($tables) . ' tablas creadas');

        // Verificar usuario admin
        $admin = Database::fetchOne("SELECT username, role FROM users WHERE username = 'admin'");
        if ($admin) {
            echo '<p><span class="badge badge-ok">OK</span> Usuario admin encontrado (credenciales: admin / admin)</p>';
            ok('Usuario admin: existe');
        }

        // Los módulos ya se cargan en bootstrap (ModuleManager::init)
        $modules = Database::fetchAll("SELECT module_key, is_active FROM modules ORDER BY module_key");
        echo '<p><span class="badge badge-ok">OK</span> Módulos cargados: ' . count($modules) . '</p>';
        foreach ($modules as $m) {
            echo '<span class="badge ' . ($m['is_active'] ? 'badge-ok' : 'badge-warn') . '">'
                . htmlspecialchars($m['module_key']) . '</span> ';
        }
        echo '<br>';
        ok('Módulos: ' . count($modules) . ' registrados');

    } catch (Throwable $e) {
        echo '<p><span class="badge badge-err">ERROR</span> ' . htmlspecialchars($e->getMessage()) . '</p>';
        echo '<pre>' . htmlspecialchars($e->getFile() . ':' . $e->getLine() . "\n" . $e->getTraceAsString()) . '</pre>';
        err('Bootstrap: ' . $e->getMessage());
    }
} else {
    echo '<p><span class="badge badge-warn">SALTA</span> Corrige los errores anteriores antes de probar la aplicación.</p>';
}
echo '</div>';

// ============================================================
// 6. Detectar mod_rewrite
// ============================================================

echo '<div class="card"><h2>mod_rewrite</h2>';
if (function_exists('apache_get_modules')) {
    $modules = apache_get_modules();
    $hasRewrite = in_array('mod_rewrite', $modules);
    echo '<p>' . ($hasRewrite
        ? '<span class="badge badge-ok">OK</span> mod_rewrite está habilitado'
        : '<span class="badge badge-warn">NO</span> mod_rewrite no detectado') . '</p>';
    if (!$hasRewrite) {
        warn('mod_rewrite no disponible — usarás URLs con /index.php/ (ej: /admin/index.php/login)');
    }
} else {
    echo '<p><span class="badge badge-warn">?</span> No se puede detectar (PHP-FPM/CGI). Prueba si las URLs limpias funcionan.</p>';
    warn('No se pudo detectar mod_rewrite — prueba las URLs limpias después del setup');
}
echo '</div>';

// ============================================================
// 7. Resumen final
// ============================================================

echo '<div class="card"><h2>Resumen</h2>';

echo '<table>';
echo '<tr><th>Comprobación</th><th>Resultados</th></tr>';
echo '<tr><td>PHP</td><td>' . (count(array_filter($results, fn($r) => $r[0] === 'ok' && str_contains($r[1], 'PHP'))) > 0 ? '<span class="badge badge-ok">OK</span>' : '<span class="badge badge-err">ERROR</span>') . '</td></tr>';
echo '<tr><td>Extensiones</td><td>' . (count(array_filter($errors, fn($e) => str_contains($e, 'extensión'))) === 0 ? '<span class="badge badge-ok">OK</span>' : '<span class="badge badge-err">FALTAN</span>') . '</td></tr>';
echo '<tr><td>Permisos</td><td>' . ($allWritable ? '<span class="badge badge-ok">OK</span>' : '<span class="badge badge-err">ERROR</span>') . '</td></tr>';
echo '<tr><td>.env</td><td>' . ($envCreated ? '<span class="badge badge-ok">OK</span>' : '<span class="badge badge-err">ERROR</span>') . '</td></tr>';
echo '</table>';

echo '<h3>Total: ' . count($results) . ' OK, ' . count($warnings) . ' avisos, ' . count($errors) . ' errores</h3>';

if (empty($errors)) {
    echo '<div style="background:#dcfce7;padding:16px;border-radius:8px;margin-top:16px;">';
    echo '<h3 style="color:#16a34a;margin-top:0;">Setup completado</h3>';
    echo '<p>La aplicación está lista. Accede al panel de administración:</p>';
    echo '<p><a class="btn" href="' . htmlspecialchars(($protocol ?? 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/') . '/admin/') . '">Ir al login (admin / admin)</a></p>';
    echo '<p><strong>IMPORTANTE:</strong> Borra este archivo <code>setup.php</code> y <code>diagnostic.php</code> del servidor.</p>';
    echo '<p>Después de iniciar sesión, cambia la contraseña del usuario admin.</p>';
    echo '</div>';
} else {
    echo '<div style="background:#fee2e2;padding:16px;border-radius:8px;margin-top:16px;">';
    echo '<h3 style="color:#dc2626;margin-top:0;">Hay errores que corregir</h3>';
    echo '<ul>';
    foreach ($errors as $e) {
        echo '<li>' . htmlspecialchars($e) . '</li>';
    }
    echo '</ul>';
    echo '</div>';
}

echo '</div>';

// ============================================================
// 8. Información del servidor (colapsable)
// ============================================================

echo '<div class="card"><h2>Información del servidor</h2>';
echo '<pre>';
echo 'PHP Version:       ' . PHP_VERSION . "\n";
echo 'SAPI:              ' . php_sapi_name() . "\n";
echo 'OS:                ' . PHP_OS . "\n";
echo 'DOCUMENT_ROOT:     ' . ($_SERVER['DOCUMENT_ROOT'] ?? 'N/A') . "\n";
echo 'SCRIPT_FILENAME:   ' . ($_SERVER['SCRIPT_FILENAME'] ?? 'N/A') . "\n";
echo 'HTTP_HOST:         ' . ($_SERVER['HTTP_HOST'] ?? 'N/A') . "\n";
echo 'REQUEST_URI:       ' . ($_SERVER['REQUEST_URI'] ?? 'N/A') . "\n";
echo 'Memory Limit:      ' . ini_get('memory_limit') . "\n";
echo 'Max Execution:     ' . ini_get('max_execution_time') . "\n";
echo 'Upload Max:        ' . ini_get('upload_max_filesize') . "\n";
echo 'Post Max:          ' . ini_get('post_max_size') . "\n";
echo 'Allow URL Fopen:   ' . (ini_get('allow_url_fopen') ? 'Sí' : 'No') . "\n";
echo '</pre>';
echo '</div>';

?>

<div class="card" style="background:#fee2e2;">
    <h2 style="color:#dc2626;">IMPORTANTE — Seguridad</h2>
    <p>Después de completar el setup, <strong>borra estos archivos del servidor</strong>:</p>
    <ul>
        <li><code>setup.php</code> (este archivo)</li>
        <li><code>diagnostic.php</code></li>
    </ul>
    <p>Si dejas estos archivos en el servidor, cualquier persona podría reconfigurar la aplicación.</p>
</div>

</body>
</html>
