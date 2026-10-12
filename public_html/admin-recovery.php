<?php
/**
 * Admin Recovery — Diagnóstico y recuperación (USAR Y BORRAR).
 *
 * Sube este archivo a la raíz de la web (junto a index.php).
 * Requiere sesión iniciada como ADMIN (la que ya usas: admin/admin).
 *
 * GET                    → informe de diagnóstico copiable
 * GET ?download=db       → descarga la base de datos SQLite
 * GET ?download=activity → descarga el log de auditoría
 * GET ?download=errors   → descarga el log de errores PHP
 * POST action=reset      → reset de tu propia contraseña (bcrypt verificado)
 *
 * SEGURIDAD: BORRA ESTE ARCHIVO DEL SERVIDOR CUANDO TERMINES.
 */

declare(strict_types=1);

require_once __DIR__ . '/config/bootstrap.php';

Auth::requireAdmin();

// ============================================================
// Descargas (solo las tres rutas permitidas)
// ============================================================

if (isset($_GET['download'])) {
    $what = $_GET['download'];
    $allowed = [
        'db'       => [DB_PATH, 'database.sqlite', 'application/octet-stream'],
        'activity' => [STORAGE_PATH . '/activity.log', 'activity.log', 'text/plain'],
        'errors'   => [STORAGE_PATH . '/php_errors.log', 'php_errors.log', 'text/plain'],
    ];
    if (!isset($allowed[$what])) {
        http_response_code(400);
        exit('Descarga no válida');
    }
    [$file, $name, $mime] = $allowed[$what];
    if (!is_file($file)) {
        http_response_code(404);
        exit("No existe: $name (ruta: $file)");
    }
    header('Content-Type: ' . $mime);
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Content-Length: ' . filesize($file));
    header('Cache-Control: no-store');
    readfile($file);
    exit;
}

// ============================================================
// Reset de contraseña (el propio admin)
// ============================================================

$resetResult = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'reset') {
    Csrf::validateOrFail();
    $new = (string)($_POST['new_password'] ?? '');
    $confirm = (string)($_POST['new_password_confirm'] ?? '');
    if ($new === '' || strlen($new) < 8) {
        $resetResult = ['ok' => false, 'msg' => 'La contraseña debe tener al menos 8 caracteres'];
    } elseif ($new !== $confirm) {
        $resetResult = ['ok' => false, 'msg' => 'Las contraseñas no coinciden'];
    } elseif ($new === 'admin') {
        $resetResult = ['ok' => false, 'msg' => 'No puedes usar "admin" como contraseña'];
    } else {
        try {
            $hash = Encryption::hashPassword($new);
            $ok = Database::update(
                "UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = datetime('now') WHERE id = ?",
                [$hash, Auth::id()]
            );
            // Verificación post-escritura: releer y verificar
            $row = Database::fetchOne("SELECT password_hash FROM users WHERE id = ?", [Auth::id()]);
            if ($row && Encryption::verifyPassword($new, $row['password_hash'])) {
                log_activity('user.password_reset_recovery', ['rows' => $ok]);
                $resetResult = ['ok' => true, 'msg' => 'Contraseña guardada y VERIFICADA contra la base de datos. Cierra sesión y entra con la nueva. Después BORRA este archivo.'];
            } else {
                $resetResult = ['ok' => false, 'msg' => 'FALLO: la verificación post-escritura no pasó. La escritura no llegó a la BD. Copia el informe de abajo y pásalo al desarrollador.'];
            }
        } catch (Throwable $e) {
            $resetResult = ['ok' => false, 'msg' => 'ERROR del servidor: ' . $e->getMessage()];
        }
    }
}

// ============================================================
// Informe de diagnóstico
// ============================================================

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Admin Recovery — USAR Y BORRAR</title>
    <style>
        body { font-family: ui-monospace, 'Cascadia Code', Consolas, monospace; background: #0f172a; color: #e2e8f0; max-width: 900px; margin: 30px auto; padding: 0 20px; }
        h1 { color: #f97316; font-size: 1.3rem; } h2 { color: #fdba74; font-size: 1rem; margin-top: 2em; border-bottom: 1px solid #334155; padding-bottom: 4px; }
        .warn { background: #7f1d1d; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-weight: bold; }
        .ok { color: #4ade80; } .bad { color: #f87171; }
        pre { background: #1e293b; padding: 14px; border-radius: 8px; overflow-x: auto; font-size: 12px; white-space: pre-wrap; }
        a.btn { display: inline-block; padding: 8px 14px; margin: 4px 6px 4px 0; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px; font-size: 13px; }
        a.btn:hover { background: #1d4ed8; }
        input { padding: 8px; border-radius: 6px; border: 1px solid #475569; background: #1e293b; color: #e2e8f0; width: 240px; }
        button { padding: 8px 18px; background: #ea580c; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
        .msg { padding: 10px 14px; border-radius: 6px; margin: 10px 0; }
        .msg-ok { background: #14532d; } .msg-bad { background: #7f1d1d; }
    </style>
</head>
<body>

<div class="warn">⚠ BORRA admin-recovery.php DEL SERVIDOR CUANDO TERMINES. Este archivo da acceso de diagnóstico y reset con tu sesión de admin.</div>

<h1>Admin Recovery — Diagnóstico</h1>

<?php if ($resetResult): ?>
    <div class="msg <?= $resetResult['ok'] ? 'msg-ok' : 'msg-bad' ?>"><?= htmlspecialchars($resetResult['msg']) ?></div>
<?php endif; ?>

<?php
// ---------- Informe copiable ----------
ob_start();
echo "=== INFORME ADMIN RECOVERY — " . date('c') . " ===\n\n";

echo "--- ENTORNO ---\n";
echo "PHP: " . PHP_VERSION . " | SAPI: " . php_sapi_name() . "\n";
echo "Argon2id disponible: " . (defined('PASSWORD_ARGON2ID') ? 'SI' : 'NO (bcrypt fallback activo)') . "\n";
echo "memory_limit: " . ini_get('memory_limit') . " | display_errors: " . ini_get('display_errors') . "\n";
echo "ROOT_PATH: " . ROOT_PATH . "\n";
echo "APP_URL: " . APP_URL . "\n\n";

echo "--- BASE DE DATOS ---\n";
echo "DB_PATH: " . DB_PATH . "\n";
echo "Existe: " . (is_file(DB_PATH) ? 'SI' : 'NO') . " | Tamaño: " . (is_file(DB_PATH) ? filesize(DB_PATH) : 0) . " bytes | Modificada: " . (is_file(DB_PATH) ? date('Y-m-d H:i:s', filemtime(DB_PATH)) : '-') . "\n";
echo "Directorio escribible: " . (is_writable(dirname(DB_PATH)) ? 'SI' : 'NO') . "\n";
try {
    $count = Database::fetchOne("SELECT COUNT(*) AS c FROM users");
    echo "Tabla users accesible: SI (" . $count['c'] . " usuarios)\n";
} catch (Throwable $e) {
    echo "Tabla users accesible: NO — " . $e->getMessage() . "\n";
}

echo "\n--- ARCHIVOS SQLITE EN LA INSTALACION (busca duplicados) ---\n";
$found = 0;
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(ROOT_PATH, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if ($f->isFile() && preg_match('/\.sqlite(-journal|-wal|-shm)?$/', $f->getFilename())) {
        $rel = str_replace('\\', '/', substr($f->getPathname(), strlen(ROOT_PATH) + 1));
        if (str_starts_with($rel, 'storage/backups/')) continue;
        echo "  $rel — " . $f->getSize() . " bytes — mod " . date('Y-m-d H:i:s', $f->getMTime()) . "\n";
        $found++;
    }
}
if (!$found) echo "  (ninguno encontrado — ¡ANOMALIA si la tabla users es accesible!)\n";

echo "\n--- CONTENIDO DE storage/ ---\n";
foreach (scandir(STORAGE_PATH) as $item) {
    if ($item === '.' || $item === '..') continue;
    $p = STORAGE_PATH . '/' . $item;
    echo "  $item " . (is_dir($p) ? '[dir]' : (is_file($p) ? '[' . filesize($p) . ' bytes, mod ' . date('Y-m-d H:i:s', filemtime($p)) . ']' : '')) . "\n";
}

echo "\n--- USUARIOS (hashes truncados por seguridad) ---\n";
try {
    $users = Database::fetchAll("SELECT id, username, email, role, must_change_password, updated_at, substr(password_hash, 1, 7) AS algo, length(password_hash) AS hash_len, last_login_at FROM users ORDER BY id");
    foreach ($users as $u) {
        echo "  #{$u['id']} {$u['username']} <{$u['email']}> rol={$u['role']} must_change={$u['must_change_password']} actualizada={$u['updated_at']} ultimo_login={$u['last_login_at']} algoritmo={$u['algo']} len={$u['hash_len']}\n";
    }
} catch (Throwable $e) {
    echo "  ERROR: " . $e->getMessage() . "\n";
}

echo "\n--- PRUEBA DE HASHING EN ESTE SERVIDOR ---\n";
try {
    $t0 = microtime(true);
    $h = Encryption::hashPassword('test-diagnostico');
    $ms = round((microtime(true) - $t0) * 1000);
    $algo = str_starts_with($h, '$argon2') ? 'argon2id' : (str_starts_with($h, '$2y$') ? 'bcrypt' : 'desconocido:' . substr($h, 0, 10));
    $verifies = Encryption::verifyPassword('test-diagnostico', $h) ? 'SI' : 'NO';
    echo "  hashPassword OK: algoritmo=$algo en {$ms}ms | verifyPassword: $verifies\n";
} catch (Throwable $e) {
    echo "  hashPassword ERROR: " . $e->getMessage() . "\n";
}

echo "\n--- ULTIMAS 40 LINEAS DE activity.log ---\n";
$alog = STORAGE_PATH . '/activity.log';
if (is_file($alog)) {
    $lines = array_slice(file($alog) ?: [], -40);
    echo implode('', $lines);
} else {
    echo "  (activity.log no existe)\n";
}

echo "\n--- ULTIMAS 20 LINEAS DE php_errors.log ---\n";
$elog = STORAGE_PATH . '/php_errors.log';
if (is_file($elog)) {
    $lines = array_slice(file($elog) ?: [], -20);
    echo implode('', $lines);
} else {
    echo "  (php_errors.log no existe)\n";
}

echo "\n=== FIN DEL INFORME ===\n";
$report = ob_get_clean();
?>

<h2>Informe (cópialo entero y pásalo al desarrollador)</h2>
<pre><?= htmlspecialchars($report) ?></pre>

<h2>Descargar datos</h2>
<a class="btn" href="?download=db">Base de datos (database.sqlite)</a>
<a class="btn" href="?download=activity">activity.log</a>
<a class="btn" href="?download=errors">php_errors.log</a>

<h2>Reset de tu contraseña (verificado)</h2>
<form method="POST">
    <?= Csrf::field() ?>
    <input type="hidden" name="action" value="reset">
    <p>Nueva contraseña (mín. 8, no puede ser "admin"): <input type="password" name="new_password" required minlength="8"></p>
    <p>Repetir: <input type="password" name="new_password_confirm" required minlength="8"></p>
    <button type="submit">Guardar y verificar</button>
</form>

</body>
</html>
