<?php
/**
 * Updater — Sistema de actualizaciones desde GitHub.
 *
 * Basado en el patrón del M4 CMS: la release publicada es la fuente de
 * verdad. Se sincroniza mediante un manifiesto SHA-256 (copia solo lo
 * nuevo/cambiado, borra lo gestionado que desaparece), NUNCA toca los
 * datos del usuario (.env, BD, logs, .htaccess raíz) y crea un backup
 * del código antes de cada operación, restaurable desde el panel.
 *
 * Flujo: GET /releases/latest → ZIP → extraer → localizar public_html/
 * → sync por hash → VERSION → opcache_reset.
 */

declare(strict_types=1);

// ============================================================
// Configuración del updater (adaptar por proyecto)
// ============================================================

function updater_config(): array
{
    // Token opcional: variable de entorno o fichero FUERA del web root.
    // Solo sirve para subir el rate limit de la API en repos públicos.
    $token = getenv('GITHUB_TOKEN') ?: '';
    $tokenFile = dirname(ROOT_PATH) . '/.github_token';
    if (!$token && @is_file($tokenFile)) {
        $token = trim((string)@file_get_contents($tokenFile));
    }

    return [
        'repo_owner'   => 'alex-milla',
        'repo_name'    => 'EntraID-ThreatIntelligence',
        'token'        => $token,

        'version_file' => ROOT_PATH . '/VERSION',
        'manifest'     => STORAGE_PATH . '/.manifest.json',
        'backup_base'  => STORAGE_PATH . '/backups',

        // Estado del usuario / runtime: nunca se copian ni entran en backups.
        // El .htaccess raíz puede estar personalizado en el hosting.
        'sensitive' => [
            '.env',
            '.htaccess',
            'storage/database.sqlite',
            'storage/activity.log',
            'storage/php_errors.log',
        ],

        // Directorios cortados por primer segmento.
        'skip_dirs' => ['.git', '.github'],

        // Prefijos de ruta excluidos del manifiesto y de los backups.
        'skip_prefixes' => [
            'storage/cache/',
            'storage/exports/',
            'storage/backups/',
        ],

        // Utilidades que se borran SIEMPRE al actualizar (el updater solo
        // corre en instalaciones ya montadas; nunca reinyectamos el setup).
        'force_delete' => ['setup.php', 'diagnostic.php', 'admin-recovery.php'],
    ];
}

/**
 * Versión instalada (fichero VERSION; "0.0.0" si no existe).
 */
function updater_installed_version(): string
{
    $cfg = updater_config();
    $v = @file_get_contents($cfg['version_file']);
    return $v ? trim($v) : '0.0.0';
}

// ============================================================
// Funciones puras: manifiesto, sync, backup, restore
// ============================================================

/**
 * Borrado recursivo de un directorio.
 */
function updater_rrmdir(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $dir . '/' . $item;
        is_dir($path) ? updater_rrmdir($path) : @unlink($path);
    }
    @rmdir($dir);
}

/**
 * ¿Debe excluirse una ruta relativa (sensitive / skipDirs / skipPrefixes)?
 */
function updater_is_excluded(string $rel, array $cfg): bool
{
    $rel = str_replace('\\', '/', $rel);
    if (in_array($rel, $cfg['sensitive'], true)) {
        return true;
    }
    $first = explode('/', $rel)[0];
    if (in_array($first, $cfg['skip_dirs'], true)) {
        return true;
    }
    foreach ($cfg['skip_prefixes'] as $prefix) {
        if (str_starts_with($rel, $prefix)) {
            return true;
        }
    }
    return false;
}

/**
 * Construye el manifiesto `ruta => sha256` de un directorio (ordenado).
 */
function updater_build_manifest(string $dir, array $cfg): array
{
    $manifest = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($dir) + 1));
        if (updater_is_excluded($rel, $cfg)) {
            continue;
        }
        $manifest[$rel] = hash_file('sha256', $file->getPathname());
    }
    ksort($manifest);
    return $manifest;
}

/**
 * Carga el manifiesto instalado; acepta el wrapper {version, files} o el
 * mapa pelado (compatibilidad hacia atrás).
 */
function updater_load_manifest(string $path): array
{
    if (!is_file($path)) {
        return [];
    }
    $data = safe_json_decode((string)@file_get_contents($path), []);
    if (!is_array($data)) {
        return [];
    }
    return isset($data['files']) && is_array($data['files']) ? $data['files'] : $data;
}

/**
 * Guarda el manifiesto con wrapper {version, generated_at, files}.
 */
function updater_save_manifest(string $path, string $version, array $files): bool
{
    return @file_put_contents(
        $path,
        json_encode(
            ['version' => $version, 'generated_at' => gmdate('c'), 'files' => $files],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        )
    ) !== false;
}

/**
 * Núcleo: sincroniza $src (web root de la release) sobre $appRoot.
 * Copia nuevos/cambiados, borra los gestionados que desaparecen,
 * ejecuta force_delete y guarda el manifiesto nuevo.
 *
 * @return array{copied:int, skipped:int, deleted:int, errors:array, manifest:array}
 */
function updater_sync_from_source(string $src, string $appRoot, string $version, array $cfg): array
{
    $result = ['copied' => 0, 'skipped' => 0, 'deleted' => 0, 'errors' => [], 'manifest' => []];

    // Manifiesto nuevo desde la fuente de la release
    $newManifest = updater_build_manifest($src, $cfg);

    // Utilidades prohibidas: fuera del manifiesto nuevo
    foreach ($cfg['force_delete'] as $bad) {
        unset($newManifest[$bad]);
    }

    if (!is_dir($appRoot)) {
        $result['errors'][] = "Directorio de aplicación no encontrado: $appRoot";
        return $result;
    }

    // Copiar solo lo que difiere
    foreach ($newManifest as $rel => $hash) {
        $dest = $appRoot . '/' . $rel;

        // Defensa zip-slip: la ruta relativa no puede salir de la raíz
        if (str_contains($rel, '..')) {
            $result['errors'][] = "Ruta sospechosa en la release: $rel";
            continue;
        }

        $destDir = dirname($dest);
        if (!is_dir($destDir) && !@mkdir($destDir, 0755, true)) {
            $result['errors'][] = "No se pudo crear el directorio: $rel";
            continue;
        }

        if (is_file($dest) && hash_file('sha256', $dest) === $hash) {
            $result['skipped']++;
            continue;
        }

        if (@copy($src . '/' . $rel, $dest)) {
            $result['copied']++;
        } else {
            $result['errors'][] = "No se pudo copiar: $rel";
        }
    }

    // Borrar gestionados que ya no están (los no gestionados nunca se tocan)
    $oldManifest = updater_load_manifest($cfg['manifest']);
    foreach ($oldManifest as $rel => $hash) {
        if (!isset($newManifest[$rel])) {
            $dest = $appRoot . '/' . $rel;
            if (is_file($dest) && @unlink($dest)) {
                $result['deleted']++;
            }
        }
    }

    // Lista negra: borrar si existen
    foreach ($cfg['force_delete'] as $bad) {
        $dest = $appRoot . '/' . $bad;
        if (is_file($dest)) {
            @unlink($dest);
        }
    }

    // Guardar manifiesto
    if (!updater_save_manifest($cfg['manifest'], $version, $newManifest)) {
        $result['errors'][] = 'No se pudo guardar el manifiesto';
    }

    $result['manifest'] = $newManifest;
    return $result;
}

/**
 * Crea .htaccess (deny) + index.php (403) en la carpeta de backups
 * si faltan (defensa en profundidad, también para hostings sin .htaccess).
 */
function updater_ensure_backup_guards(string $dir): void
{
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    if (!is_file($dir . '/.htaccess')) {
        @file_put_contents(
            $dir . '/.htaccess',
            "# Denegar todo acceso web\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n"
        );
    }
    if (!is_file($dir . '/index.php')) {
        @file_put_contents($dir . '/index.php', "<?php\nhttp_response_code(403);\nexit('Forbidden');\n");
    }
}

/**
 * Copia el código actual a storage/backups/backup_<fecha>/.
 *
 * @return array{dir:string, files:int, errors:array}
 */
function updater_create_backup(string $appRoot, array $cfg): array
{
    $backupDir = $cfg['backup_base'] . '/backup_' . date('Ymd_His');
    $errors = [];
    $count = 0;

    updater_ensure_backup_guards($cfg['backup_base']);

    // Evitar colisión de nombre si se crea más de un backup en el mismo segundo
    $i = 1;
    while (is_dir($backupDir)) {
        $backupDir = $cfg['backup_base'] . '/backup_' . date('Ymd_His') . '_' . (++$i);
    }

    if (!@mkdir($backupDir, 0755, true)) {
        return ['dir' => '', 'files' => 0, 'errors' => ["No se pudo crear el backup en $backupDir"]];
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($appRoot, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($appRoot) + 1));

        // Nunca respaldar los propios backups ni lo excluido
        if (str_starts_with($rel, 'storage/backups/')) {
            continue;
        }
        if (updater_is_excluded($rel, $cfg)) {
            continue;
        }

        $dest = $backupDir . '/' . $rel;
        $destDir = dirname($dest);
        if (!is_dir($destDir) && !@mkdir($destDir, 0755, true)) {
            $errors[] = "Backup: no se pudo crear el directorio de $rel";
            continue;
        }
        if (@copy($file->getPathname(), $dest)) {
            $count++;
        } else {
            $errors[] = "Backup: no se pudo copiar $rel";
        }
    }

    // El manifiesto forma parte del estado: se respalda para restaurarlo
    if (is_file($cfg['manifest'])) {
        @copy($cfg['manifest'], $backupDir . '/storage/.manifest.json');
    }

    return ['dir' => $backupDir, 'files' => $count, 'errors' => $errors];
}

/**
 * Restaura un backup sobre la instalación (con backup previo del estado
 * actual, devuelto en 'pre').
 *
 * @return array{pre:array, restored:int, errors:array}
 */
function updater_restore_backup(string $backupDir, string $appRoot, array $cfg): array
{
    $errors = [];
    $restored = 0;

    // Backup previo del estado actual
    $pre = updater_create_backup($appRoot, $cfg);

    $manifestSrc = $backupDir . '/storage/.manifest.json';
    $manifestFiles = is_file($manifestSrc)
        ? array_keys(updater_load_manifest($manifestSrc))
        : [];

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($backupDir, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($backupDir) + 1));

        // El manifiesto no se copia a la app (se restaura aparte)
        if ($rel === 'storage/.manifest.json') {
            continue;
        }
        if (updater_is_excluded($rel, $cfg)) {
            continue;
        }

        $dest = $appRoot . '/' . $rel;
        $destDir = dirname($dest);
        if (!is_dir($destDir) && !@mkdir($destDir, 0755, true)) {
            $errors[] = "Restore: no se pudo crear el directorio de $rel";
            continue;
        }
        if (@copy($file->getPathname(), $dest)) {
            $restored++;
        } else {
            $errors[] = "Restore: no se pudo copiar $rel";
        }
    }

    // Restaurar el manifiesto del backup (si no traía, borrar el actual
    // para que el siguiente sync lo regenere desde cero)
    if (is_file($manifestSrc)) {
        @copy($manifestSrc, $cfg['manifest']);
    } elseif (is_file($cfg['manifest'])) {
        @unlink($cfg['manifest']);
    }

    return ['pre' => $pre, 'restored' => $restored, 'errors' => $errors];
}

/**
 * Lista los backups existentes (más recientes primero).
 * @return array<int, array{name:string, files:int, date:string}>
 */
function updater_list_backups(array $cfg, int $limit = 15): array
{
    $out = [];
    $dirs = glob($cfg['backup_base'] . '/backup_*') ?: [];
    usort($dirs, fn($a, $b) => strcmp($b, $a));
    foreach (array_slice($dirs, 0, $limit) as $dir) {
        $name = basename($dir);
        if (!preg_match('/^backup_\d{8}_\d{6}(_\d+)?$/', $name)) {
            continue;
        }
        $count = 0;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $f) {
            if ($f->isFile()) {
                $count++;
            }
        }
        if (preg_match('/(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/', $name, $m)) {
            $date = "{$m[1]}-{$m[2]}-{$m[3]} {$m[4]}:{$m[5]}:{$m[6]}";
        } else {
            $date = $name;
        }
        $out[] = ['name' => $name, 'files' => $count, 'date' => $date];
    }
    return $out;
}

// ============================================================
// Red y ZIP
// ============================================================

/**
 * GET a la API de GitHub. Devuelve ['ok', 'data', 'error', 'status'].
 */
function updater_github_api_get(string $url, string $token): array
{
    $headers = ['Accept: application/vnd.github+json', 'User-Agent: EntraID-TI-Updater'];
    if ($token !== '') {
        $headers[] = 'Authorization: Bearer ' . $token;
    }

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_HTTPHEADER     => $headers,
        ]);
        $body = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            return ['ok' => false, 'data' => null, 'error' => "cURL: $err", 'status' => 0];
        }
        if ($status === 403) {
            return ['ok' => false, 'data' => null, 'error' => 'Rate limit de la API de GitHub alcanzado. Reintenta en unos minutos o configura GITHUB_TOKEN.', 'status' => 403];
        }
        if ($status === 404) {
            return ['ok' => false, 'data' => null, 'error' => 'Recurso no encontrado (¿hay releases publicadas?).', 'status' => 404];
        }
        if ($status !== 200) {
            return ['ok' => false, 'data' => null, 'error' => "HTTP $status", 'status' => $status];
        }
        return ['ok' => true, 'data' => safe_json_decode((string)$body, []), 'error' => '', 'status' => $status];
    }

    // Fallback sin cURL
    $ctx = stream_context_create([
        'http' => ['timeout' => 15, 'header' => implode("\r\n", $headers)],
    ]);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) {
        return ['ok' => false, 'data' => null, 'error' => 'No se pudo conectar con GitHub (sin cURL ni allow_url_fopen).', 'status' => 0];
    }
    return ['ok' => true, 'data' => safe_json_decode($body, []), 'error' => '', 'status' => 200];
}

/**
 * Descarga un fichero (el ZIP de la release) a $dest.
 */
function updater_download_file(string $url, string $dest, string $token): array
{
    if (function_exists('curl_init')) {
        $headers = ['User-Agent: EntraID-TI-Updater'];
        if ($token !== '') {
            $headers[] = 'Authorization: Bearer ' . $token;
        }
        $fp = @fopen($dest, 'wb');
        if (!$fp) {
            return [false, "No se pudo escribir en $dest"];
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FILE             => $fp,
            CURLOPT_TIMEOUT          => 120,
            CURLOPT_SSL_VERIFYPEER   => true,
            CURLOPT_SSL_VERIFYHOST   => 2,
            CURLOPT_FOLLOWLOCATION   => true,
            CURLOPT_MAXREDIRS        => 5,
            CURLOPT_HTTPHEADER       => $headers,
        ]);
        curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);
        fclose($fp);
        if ($err !== '') {
            return [false, "cURL: $err"];
        }
        return [true, ''];
    }

    // Fallback sin cURL
    $ctx = stream_context_create([
        'http' => [
            'timeout'         => 120,
            'follow_location' => 1,
            'max_redirects'   => 5,
            'header'          => "User-Agent: EntraID-TI-Updater\r\n" . ($token !== '' ? "Authorization: Bearer $token\r\n" : ''),
        ],
    ]);
    $data = @file_get_contents($url, false, $ctx);
    if ($data === false) {
        return [false, 'Descarga fallida (sin cURL ni allow_url_fopen)'];
    }
    return [@file_put_contents($dest, $data) !== false, ''];
}

/**
 * Extrae un ZIP con tres vías: ZipArchive → PharData → unzip (exec).
 */
function updater_extract_zip(string $zip, string $dest): array
{
    if (class_exists('ZipArchive')) {
        $za = new ZipArchive();
        if ($za->open($zip) === true) {
            // Defensa zip-slip: rechazar entradas con ..
            for ($i = 0; $i < $za->numFiles; $i++) {
                $entry = $za->getNameIndex($i);
                if (str_contains($entry, '..')) {
                    $za->close();
                    return [false, 'El ZIP contiene rutas maliciosas (zip-slip)'];
                }
            }
            $za->extractTo($dest);
            $za->close();
            return [true, ''];
        }
        return [false, 'ZipArchive no pudo abrir el ZIP descargado'];
    }

    if (class_exists('PharData')) {
        try {
            $phar = new PharData($zip);
            $phar->extractTo($dest, null, true);
            return [true, ''];
        } catch (Throwable $e) {
            return [false, 'PharData: ' . $e->getMessage()];
        }
    }

    if (function_exists('exec')) {
        @mkdir($dest, 0755, true);
        $out = [];
        $code = 0;
        exec('unzip ' . escapeshellarg($zip) . ' -d ' . escapeshellarg($dest) . ' 2>&1', $out, $code);
        if ($code === 0) {
            return [true, ''];
        }
        return [false, 'unzip: ' . implode("\n", $out)];
    }

    return [false, 'No hay vía de extracción disponible (ZipArchive, PharData ni unzip). Contacta con tu hosting.'];
}

/**
 * Consulta la última release publicada. Devuelve:
 * ['ok', 'version', 'tag', 'name', 'notes', 'zipball_url', 'published_at', 'error']
 * Fallback: si no hay releases, usa el último tag.
 */
function updater_latest_release(array $cfg): array
{
    $api = "https://api.github.com/repos/{$cfg['repo_owner']}/{$cfg['repo_name']}";

    $res = updater_github_api_get($api . '/releases/latest', $cfg['token']);
    if ($res['ok'] && !empty($res['data']['tag_name'])) {
        $d = $res['data'];
        return [
            'ok'           => true,
            'version'      => ltrim((string)$d['tag_name'], 'v'),
            'tag'          => (string)$d['tag_name'],
            'name'         => (string)($d['name'] ?? $d['tag_name']),
            'notes'        => (string)($d['body'] ?? ''),
            'zipball_url'  => (string)($d['zipball_url'] ?? ($api . '/zipball/' . $d['tag_name'])),
            'published_at'  => (string)($d['published_at'] ?? ''),
            'error'        => '',
        ];
    }

    // Fallback a tags
    $res = updater_github_api_get($api . '/tags?per_page=1', $cfg['token']);
    if ($res['ok'] && !empty($res['data'][0]['name'])) {
        $tag = (string)$res['data'][0]['name'];
        return [
            'ok'          => true,
            'version'     => ltrim($tag, 'v'),
            'tag'         => $tag,
            'name'        => 'Tag ' . $tag,
            'notes'       => '',
            'zipball_url' => "https://github.com/{$cfg['repo_owner']}/{$cfg['repo_name']}/archive/refs/tags/{$tag}.zip",
            'published_at'=> '',
            'error'       => '',
        ];
    }

    return [
        'ok' => false, 'version' => '', 'tag' => '', 'name' => '', 'notes' => '',
        'zipball_url' => '', 'published_at' => '', 'error' => $res['error'] ?: 'Sin releases ni tags',
    ];
}

/**
 * Ejecuta la actualización completa: backup → descarga → extracción →
 * localizar public_html/ → sync → VERSION → opcache_reset.
 *
 * @return array{success:bool, message:string, details:array}
 */
function updater_run_update(array $cfg, array $release): array
{
    // 1. Backup PRIMERO
    $backup = updater_create_backup(ROOT_PATH, $cfg);
    if ($backup['dir'] === '') {
        return ['success' => false, 'message' => 'No se pudo crear el backup previo: ' . implode('; ', $backup['errors']), 'details' => $backup];
    }

    // 2. Descargar ZIP de la release
    $tmpZip = tempnam(sys_get_temp_dir(), 'entraid_upd_');
    [$dlOk, $dlErr] = updater_download_file($release['zipball_url'], $tmpZip, $cfg['token']);
    if (!$dlOk || !is_file($tmpZip) || filesize($tmpZip) < 1024) {
        @unlink($tmpZip);
        return ['success' => false, 'message' => 'Descarga fallida o ZIP corrupto: ' . $dlErr, 'details' => []];
    }

    // 3. Extraer
    $tmpDir = sys_get_temp_dir() . '/entraid_upd_' . bin2hex(random_bytes(4));
    [$exOk, $exErr] = updater_extract_zip($tmpZip, $tmpDir);
    @unlink($tmpZip);
    if (!$exOk) {
        updater_rrmdir($tmpDir);
        return ['success' => false, 'message' => 'Extracción fallida: ' . $exErr, 'details' => []];
    }

    // 4. Localizar la raíz web (repo-sha/public_html)
    $srcWeb = null;
    foreach (glob($tmpDir . '/*') ?: [] as $entry) {
        if (is_dir($entry . '/public_html')) {
            $srcWeb = $entry . '/public_html';
            break;
        }
    }
    if ($srcWeb === null) {
        updater_rrmdir($tmpDir);
        return ['success' => false, 'message' => 'El ZIP no contiene la estructura esperada (public_html/)', 'details' => []];
    }

    // 5. Sincronizar
    $sync = updater_sync_from_source($srcWeb, ROOT_PATH, $release['version'], $cfg);

    // 6. Limpiar temporales
    updater_rrmdir($tmpDir);

    if (!empty($sync['errors'])) {
        return ['success' => false, 'message' => 'Errores durante la sincronización: ' . implode('; ', array_slice($sync['errors'], 0, 5)), 'details' => $sync];
    }

    if ($sync['copied'] + $sync['deleted'] === 0) {
        // Nada que hacer, pero el backup ya está hecho: mensaje informativo
        return ['success' => true, 'message' => 'Ya estabas al día (ningún fichero cambiado).', 'details' => $sync];
    }

    // 7. Escribir VERSION y limpiar OPcache
    @file_put_contents($cfg['version_file'], $release['version']);
    if (function_exists('opcache_reset')) {
        @opcache_reset();
    }

    $sync['backup'] = basename($backup['dir']);
    return [
        'success' => true,
        'message' => "Actualizado a {$release['tag']}: {$sync['copied']} ficheros copiados, {$sync['deleted']} borrados, {$sync['skipped']} sin cambios. Backup: " . basename($backup['dir']),
        'details' => $sync,
    ];
}
