<?php
/**
 * CveFeed — descarga e importación de los feeds oficiales de NVD (CVE 2.0).
 *
 * Desacopla la descarga del procesado: el feed se guarda como fichero en
 * storage/cve-import/ y después se importa por lotes, con reanudación en ambos
 * sentidos (bytes con HTTP Range y registros ya procesados). Así una
 * reconstrucción no depende de miles de peticiones al API ni sufre los
 * desplazamientos de paginación de un catálogo que cambia durante el crawl.
 *
 * Los feeds son los mismos que publica NVD en
 * https://nvd.nist.gov/vuln/data-feeds (esquema CVE API 2.0):
 *
 *   nvdcve-2.0-modified.json.gz   últimos 8 días (actualizado cada 2 h)
 *   nvdcve-2.0-recent.json.gz     últimos 8 días publicados
 *   nvdcve-2.0-YYYY.json.gz       un año completo
 *
 * El fichero puede descargarse aquí o subirse por FTP/SFTP a
 * storage/cve-import/ desde cualquier máquina: el import es idéntico.
 */

declare(strict_types=1);

/**
 * Lector incremental del array "vulnerabilities" de un feed .json.gz.
 *
 * No carga el fichero entero en memoria (un año completo puede superar los
 * 400 MB descomprimidos): recorre el gzip en bloques y va extrayendo objeto a
 * objeto del array de nivel superior.
 */
final class JsonArrayStream
{
    /**
     * @return Generator<int, array>
     */
    public static function elements(string $gzPath, string $key = 'vulnerabilities'): Generator
    {
        if (!is_file($gzPath)) {
            throw new RuntimeException('No existe el fichero: ' . $gzPath);
        }
        $fh = gzopen($gzPath, 'rb');
        if ($fh === false) {
            throw new RuntimeException('No se pudo abrir el fichero gzip: ' . $gzPath);
        }

        try {
            $needle = '"' . $key . '"';
            $head = '';
            $offset = -1;
            $searchFrom = 0;

            // Fase 1: localizar la clave y el '[' de su array.
            while ($offset < 0) {
                $pos = strpos($head, $needle, $searchFrom);
                if ($pos === false) {
                    if (strlen($head) > 1048576) {
                        throw new RuntimeException('El feed no contiene la clave "' . $key . '".');
                    }
                    $chunk = gzread($fh, 65536);
                    if ($chunk === false || $chunk === '') {
                        throw new RuntimeException('El feed no contiene la clave "' . $key . '".');
                    }
                    $head .= $chunk;
                    continue;
                }

                $i = $pos + strlen($needle);
                $len = strlen($head);
                // Puede que falten bytes para ver ':' y '[': pedir más.
                if ($i >= $len) {
                    $chunk = gzread($fh, 65536);
                    if ($chunk === false || $chunk === '') {
                        throw new RuntimeException('El feed terminó buscando la clave "' . $key . '".');
                    }
                    $head .= $chunk;
                    continue;
                }

                while ($i < $len && ctype_space($head[$i])) {
                    $i++;
                }
                if ($i >= $len) {
                    $chunk = gzread($fh, 65536);
                    if ($chunk === false || $chunk === '') {
                        throw new RuntimeException('El feed terminó buscando la clave "' . $key . '".');
                    }
                    $head .= $chunk;
                    continue;
                }
                if ($head[$i] !== ':') {
                    // Falso positivo (texto de una descripción): seguir buscando.
                    $searchFrom = $pos + strlen($needle);
                    continue;
                }
                $i++;
                while ($i < $len && ctype_space($head[$i])) {
                    $i++;
                }
                if ($i >= $len) {
                    $chunk = gzread($fh, 65536);
                    if ($chunk === false || $chunk === '') {
                        throw new RuntimeException('El feed terminó buscando la clave "' . $key . '".');
                    }
                    $head .= $chunk;
                    continue;
                }
                if ($head[$i] !== '[') {
                    throw new RuntimeException('La clave "' . $key . '" del feed no apunta a un array.');
                }

                $offset = $i + 1;
            }

            // Fase 2: extraer elementos de nivel 1 del array.
            $buf = substr($head, $offset);
            unset($head);
            $i = 0;
            $n = strlen($buf);

            $depth = 0;
            $inString = false;
            $escape = false;
            $current = '';

            while (true) {
                if ($i >= $n) {
                    $chunk = gzread($fh, 262144);
                    if ($chunk === false || $chunk === '') {
                        break;
                    }
                    $buf = $chunk;
                    $i = 0;
                    $n = strlen($chunk);
                }
                $ch = $buf[$i++];

                if ($inString) {
                    if ($depth > 0) {
                        $current .= $ch;
                    }
                    if ($escape) {
                        $escape = false;
                    } elseif ($ch === '\\') {
                        $escape = true;
                    } elseif ($ch === '"') {
                        $inString = false;
                    }
                    continue;
                }

                if ($ch === '"') {
                    $inString = true;
                    if ($depth > 0) {
                        $current .= $ch;
                    }
                    continue;
                }
                if ($ch === '{') {
                    $depth++;
                    $current .= $ch;
                    continue;
                }
                if ($ch === '}') {
                    if ($depth <= 0) {
                        throw new RuntimeException('JSON del feed mal formado (llave de cierre inesperada).');
                    }
                    $depth--;
                    $current .= $ch;
                    if ($depth === 0) {
                        $item = json_decode($current, true);
                        $current = '';
                        if (!is_array($item)) {
                            throw new RuntimeException('Elemento JSON no válido en el feed.');
                        }
                        yield $item;
                    }
                    continue;
                }
                if ($depth > 0) {
                    $current .= $ch;
                    continue;
                }
                if ($ch === ']') {
                    break; // fin del array
                }
                // A nivel 0 solo quedan comas y espacios: se ignoran.
            }

            if ($current !== '' || $depth !== 0) {
                throw new RuntimeException('El feed terminó de forma inesperada (JSON truncado).');
            }
        } finally {
            gzclose($fh);
        }
    }
}

final class CveFeed
{
    private const BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/2.0/';
    private const MIN_YEAR = 1988;
    private const DEFAULT_BATCH = 200;

    /**
     * Nombre de fichero del feed a partir de su alias.
     * Acepta: modified, recent, year:YYYY.
     */
    public static function feedName(string $what): ?string
    {
        $what = strtolower(trim($what));
        if ($what === 'modified' || $what === 'recent') {
            return 'nvdcve-2.0-' . $what . '.json.gz';
        }
        if (preg_match('/^year:(\d{4})$/', $what, $m)) {
            $year = (int)$m[1];
            if ($year < self::MIN_YEAR || $year > (int)date('Y') + 1) {
                return null;
            }
            return 'nvdcve-2.0-' . $year . '.json.gz';
        }
        return null;
    }

    public static function storageDir(): string
    {
        $dbPath = defined('CVE_DB_PATH') ? (string)CVE_DB_PATH : (STORAGE_PATH . '/cve.sqlite');
        $dir = rtrim(dirname($dbPath), '/\\') . DIRECTORY_SEPARATOR . 'cve-import';
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        return $dir;
    }

    /**
     * Descarga un feed a storage/cve-import/. Reanuda por HTTP Range si existe
     * un .part previo y verifica tamaño/SHA-256 contra el .meta oficial.
     *
     * @return array{ok:bool,file?:string,bytes?:int,skipped?:bool,verified?:bool,message?:string,error?:string}
     */
    public function download(string $what, ?callable $onProgress = null): array
    {
        $name = self::feedName($what);
        if ($name === null) {
            return ['ok' => false, 'error' => 'Feed no válido. Usa modified, recent o year:YYYY.'];
        }
        if (!function_exists('curl_init')) {
            return ['ok' => false, 'error' => 'La extensión cURL de PHP no está disponible.'];
        }

        $dir = self::storageDir();
        $dest = $dir . DIRECTORY_SEPARATOR . $name;
        $part = $dest . '.part';
        $url = self::BASE_URL . $name;

        $meta = $this->fetchMeta($name);

        if (is_file($dest)) {
            $check = $this->verifyFile($dest, $meta);
            if ($check['ok']) {
                $bytes = (int)$check['bytes'];
                $this->register($name, $what, 'downloaded', $bytes, $bytes, 0, 0, 0, null);
                return [
                    'ok'       => true,
                    'skipped'  => true,
                    'file'     => $dest,
                    'bytes'    => $bytes,
                    'verified' => $check['verified'],
                    'message'  => 'Feed ya descargado y verificado.',
                ];
            }
            // Fichero corrupto o de otra versión: se vuelve a descargar.
            @unlink($dest);
        }

        $resume = is_file($part) ? (int)filesize($part) : 0;
        $startedAt = microtime(true);

        $fp = @fopen($part, $resume > 0 ? 'ab' : 'wb');
        if ($fp === false) {
            return ['ok' => false, 'error' => 'No se pudo escribir en ' . $part];
        }

        $ch = curl_init($url);
        $opts = [
            CURLOPT_FILE             => $fp,
            CURLOPT_FOLLOWLOCATION   => true,
            CURLOPT_MAXREDIRS        => 3,
            CURLOPT_CONNECTTIMEOUT   => 15,
            CURLOPT_TIMEOUT          => 0,
            // Fichero grande y estático: solo se aborta si la conexión queda
            // realmente muerta (sin llegar a 256 B/s durante 2 minutos).
            CURLOPT_LOW_SPEED_LIMIT  => 256,
            CURLOPT_LOW_SPEED_TIME   => 120,
            CURLOPT_SSL_VERIFYPEER   => true,
            CURLOPT_SSL_VERIFYHOST   => 2,
            CURLOPT_USERAGENT        => 'EntraID-TI-CVE/1.0',
        ];
        if ($resume > 0) {
            $opts[CURLOPT_RESUME_FROM] = $resume;
        }
        curl_setopt_array($ch, $opts);

        $ok = curl_exec($ch);
        $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        curl_close($ch);
        fclose($fp);
        $elapsed = microtime(true) - $startedAt;

        if ($ok === false) {
            $bytes = is_file($part) ? (int)filesize($part) : 0;
            $this->register($name, $what, 'error', $bytes, $bytes, 0, 0, 0,
                substr($error . sprintf(' (cURL %d, %.1f s)', $errno, $elapsed), 0, 500));
            return [
                'ok'    => false,
                'error' => $error . sprintf(' (cURL %d, %.1f s)', $errno, $elapsed)
                    . ($bytes > 0 ? ' — se conservan ' . number_format($bytes) . ' bytes para reanudar.' : ''),
            ];
        }

        // El servidor puede ignorar Range y devolver 200 completo: reiniciar.
        if ($resume > 0 && $http === 200) {
            @unlink($part);
            return $this->download($what, $onProgress);
        }
        // 416: el .part ya contenía el fichero completo; se valida abajo.
        if ($http === 416 && $resume > 0) {
            @rename($part, $dest);
        } elseif ($http !== 200 && $http !== 206) {
            $this->register($name, $what, 'error', $resume, $resume, 0, 0, 0, 'HTTP ' . $http);
            return ['ok' => false, 'error' => 'NVD respondió HTTP ' . $http . ' al descargar ' . $name];
        }

        if (!@rename($part, $dest)) {
            return ['ok' => false, 'error' => 'No se pudo renombrar el fichero descargado.'];
        }

        $check = $this->verifyFile($dest, $meta);
        $bytes = (int)$check['bytes'];
        if (!$check['ok']) {
            @unlink($dest);
            $this->register($name, $what, 'error', $bytes, $bytes, 0, 0, 0, (string)$check['error']);
            return ['ok' => false, 'error' => 'Verificación del feed fallida: ' . (string)$check['error']];
        }

        $this->register($name, $what, 'downloaded', $bytes, $bytes, 0, 0, 0, null);

        if ($onProgress !== null) {
            $onProgress(['type' => 'downloaded', 'file' => $dest, 'bytes' => $bytes]);
        }

        return [
            'ok'       => true,
            'file'     => $dest,
            'bytes'    => $bytes,
            'skipped'  => false,
            'verified' => $check['verified'],
            'message'  => sprintf(
                'Feed descargado: %s (%s MB en %.1f s%s).',
                $name,
                number_format($bytes / 1048576, 1),
                $elapsed,
                $check['verified'] ? ', verificado con SHA-256' : ''
            ),
        ];
    }

    /**
     * Importa un fichero de storage/cve-import/ por lotes, reutilizando el
     * upsert de la sincronización. Reanudable: guarda items_done en
     * cve_import_files y sigue desde ahí en la siguiente llamada.
     *
     * @return array{ok:bool,done:bool,items_done:int,inserted:int,updated:int,skipped:int,error?:string}
     */
    public function import(string $filename, float $budgetSeconds = 0, ?callable $onProgress = null): array
    {
        $filename = basename(trim($filename));
        if ($filename === '') {
            return ['ok' => false, 'done' => false, 'items_done' => 0, 'inserted' => 0, 'updated' => 0, 'skipped' => 0, 'error' => 'Falta el nombre de fichero.'];
        }
        $path = self::storageDir() . DIRECTORY_SEPARATOR . $filename;
        if (!is_file($path)) {
            return ['ok' => false, 'done' => false, 'items_done' => 0, 'inserted' => 0, 'updated' => 0, 'skipped' => 0,
                'error' => 'No existe el fichero en storage/cve-import: ' . $filename];
        }

        $row = CveDatabase::fetchOne("SELECT * FROM cve_import_files WHERE filename = ?", [$filename]);
        if (!$row) {
            $size = (int)filesize($path);
            $this->register($filename, 'manual', 'downloaded', $size, $size, 0, 0, 0, null);
            $row = CveDatabase::fetchOne("SELECT * FROM cve_import_files WHERE filename = ?", [$filename]);
        }
        if (!$row) {
            return ['ok' => false, 'done' => false, 'items_done' => 0, 'inserted' => 0, 'updated' => 0, 'skipped' => 0,
                'error' => 'No se pudo registrar la importación.'];
        }

        $id = (int)$row['id'];
        if ((string)$row['status'] === 'done') {
            return ['ok' => true, 'done' => true, 'items_done' => (int)$row['items_done'],
                'inserted' => (int)$row['inserted'], 'updated' => (int)$row['updated'],
                'skipped' => (int)$row['skipped'], 'message' => 'Ese feed ya se importó.'];
        }

        $alreadyDone = max(0, (int)$row['items_done']);
        $inserted = (int)$row['inserted'];
        $updated = (int)$row['updated'];
        $skipped = (int)$row['skipped'];
        $batchSize = self::DEFAULT_BATCH;
        $deadline = $budgetSeconds > 0 ? microtime(true) + $budgetSeconds : INF;
        $sync = new CveSync();
        $batch = [];
        $seen = 0;
        $done = $alreadyDone;

        CveDatabase::query(
            "UPDATE cve_import_files
             SET status = 'importing', started_at = COALESCE(started_at, datetime('now')), updated_at = datetime('now')
             WHERE id = ?",
            [$id]
        );

        try {
            foreach (JsonArrayStream::elements($path) as $item) {
                $seen++;
                if ($seen <= $alreadyDone) {
                    continue;
                }
                $batch[] = $item;
                if (count($batch) < $batchSize) {
                    continue;
                }
                $stats = $sync->applyBatch($batch);
                $done += count($batch);
                $inserted += $stats['inserted'];
                $updated += $stats['updated'];
                $skipped += $stats['skipped'];
                $batch = [];
                $this->updateProgress($id, $done, $inserted, $updated, $skipped);
                if ($onProgress !== null) {
                    $onProgress([
                        'type'      => 'progress',
                        'items_done' => $done,
                        'inserted'  => $inserted,
                        'updated'   => $updated,
                        'skipped'   => $skipped,
                    ]);
                }
                if (microtime(true) >= $deadline) {
                    return [
                        'ok' => true, 'done' => false, 'items_done' => $done,
                        'inserted' => $inserted, 'updated' => $updated, 'skipped' => $skipped,
                        'message' => 'Importación parcial: se reanudará en la próxima llamada.',
                    ];
                }
            }

            if ($batch !== []) {
                $stats = $sync->applyBatch($batch);
                $done += count($batch);
                $inserted += $stats['inserted'];
                $updated += $stats['updated'];
                $skipped += $stats['skipped'];
                $this->updateProgress($id, $done, $inserted, $updated, $skipped);
            }

            CveDatabase::query(
                "UPDATE cve_import_files
                 SET status = 'done', items_total = ?, finished_at = datetime('now'), updated_at = datetime('now')
                 WHERE id = ?",
                [$done, $id]
            );
            $this->logImport($filename, $inserted + $updated);

            return [
                'ok' => true, 'done' => true, 'items_done' => $done,
                'inserted' => $inserted, 'updated' => $updated, 'skipped' => $skipped,
                'message' => sprintf(
                    'Feed importado: %s CVEs (%s nuevos, %s actualizados).',
                    number_format($done),
                    number_format($inserted),
                    number_format($updated)
                ),
            ];
        } catch (Throwable $e) {
            CveDatabase::query(
                "UPDATE cve_import_files SET status = 'error', error = ?, updated_at = datetime('now') WHERE id = ?",
                [substr($e->getMessage(), 0, 500), $id]
            );
            return [
                'ok' => false, 'done' => false, 'items_done' => $done,
                'inserted' => $inserted, 'updated' => $updated, 'skipped' => $skipped,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Último feed descargado que aún no se ha importado del todo.
     */
    public function latestPendingFile(): ?string
    {
        $row = CveDatabase::fetchOne(
            "SELECT filename FROM cve_import_files
             WHERE status IN ('downloaded', 'importing', 'error', 'pending')
             ORDER BY id DESC LIMIT 1"
        );
        $name = (string)($row['filename'] ?? '');
        if ($name === '') {
            return null;
        }
        return is_file(self::storageDir() . DIRECTORY_SEPARATOR . $name) ? $name : null;
    }

    public function files(int $limit = 50): array
    {
        $limit = max(1, min(200, $limit));
        return CveDatabase::fetchAll(
            "SELECT filename, source, status, bytes_total, items_done, inserted, updated, skipped,
                    error, started_at, finished_at, updated_at
             FROM cve_import_files ORDER BY id DESC LIMIT " . $limit
        );
    }

    // ============================================================
    // Internos
    // ============================================================

    private function register(
        string $filename,
        string $source,
        string $status,
        int $bytesTotal,
        int $bytesDone,
        int $itemsDone,
        int $inserted,
        int $updated,
        ?string $error
    ): void {
        try {
            CveDatabase::query(
                "INSERT INTO cve_import_files
                    (filename, source, status, bytes_total, bytes_done, items_done, inserted, updated, error, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                 ON CONFLICT(filename) DO UPDATE SET
                    source = excluded.source,
                    status = excluded.status,
                    bytes_total = excluded.bytes_total,
                    bytes_done = excluded.bytes_done,
                    items_done = CASE WHEN excluded.items_done > 0 THEN excluded.items_done ELSE cve_import_files.items_done END,
                    inserted = excluded.inserted,
                    updated = excluded.updated,
                    error = excluded.error,
                    updated_at = datetime('now')",
                [$filename, $source, $status, $bytesTotal, $bytesDone, $itemsDone, $inserted, $updated, $error]
            );
        } catch (Throwable $e) {
            // El registro es best-effort: no debe abortar la descarga/import.
        }
    }

    private function updateProgress(int $id, int $done, int $inserted, int $updated, int $skipped): void
    {
        CveDatabase::query(
            "UPDATE cve_import_files
             SET items_done = ?, inserted = ?, updated = ?, skipped = ?, updated_at = datetime('now')
             WHERE id = ?",
            [$done, $inserted, $updated, $skipped, $id]
        );
    }

    private function logImport(string $filename, int $records): void
    {
        try {
            CveDatabase::query(
                "INSERT INTO cve_sync_log (source, mode, status, records, error, started_at, finished_at)
                 VALUES ('import', ?, 'ok', ?, NULL, datetime('now'), datetime('now'))",
                [substr($filename, 0, 120), $records]
            );
        } catch (Throwable $e) {
            // Best-effort.
        }
    }

    /**
     * Lee el .meta oficial del feed (tamaño comprimido + SHA-256).
     *
     * @return array{gzSize?:int,sha256?:string,lastModifiedDate?:string}
     */
    private function fetchMeta(string $name): array
    {
        if (!function_exists('curl_init')) {
            return [];
        }
        $ch = curl_init(self::BASE_URL . $name . '.meta');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 20,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'EntraID-TI-CVE/1.0',
        ]);
        $body = curl_exec($ch);
        $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($body === false || $http !== 200) {
            return [];
        }
        $meta = [];
        foreach (preg_split('/\r?\n/', (string)$body) as $line) {
            if (str_contains($line, ':')) {
                [$key, $value] = explode(':', $line, 2);
                $meta[trim($key)] = trim($value);
            }
        }
        return [
            'gzSize'           => isset($meta['gzSize']) ? (int)$meta['gzSize'] : 0,
            'sha256'           => isset($meta['sha256']) ? strtolower((string)$meta['sha256']) : '',
            'lastModifiedDate' => isset($meta['lastModifiedDate']) ? (string)$meta['lastModifiedDate'] : '',
        ];
    }

    /**
     * @return array{ok:bool,bytes:int,verified:bool,error?:string}
     */
    private function verifyFile(string $path, array $meta): array
    {
        $bytes = is_file($path) ? (int)filesize($path) : 0;
        if ($bytes <= 0) {
            return ['ok' => false, 'bytes' => 0, 'verified' => false, 'error' => 'Fichero vacío.'];
        }

        // Cabecera gzip obligatoria.
        $fp = @fopen($path, 'rb');
        if ($fp === false) {
            return ['ok' => false, 'bytes' => $bytes, 'verified' => false, 'error' => 'No se pudo leer el fichero.'];
        }
        $magic = (string)fread($fp, 2);
        fclose($fp);
        if ($magic !== "\x1f\x8b") {
            return ['ok' => false, 'bytes' => $bytes, 'verified' => false, 'error' => 'El fichero no es gzip.'];
        }

        $expectedSize = (int)($meta['gzSize'] ?? 0);
        if ($expectedSize > 0 && $bytes !== $expectedSize) {
            return [
                'ok' => false, 'bytes' => $bytes, 'verified' => false,
                'error' => sprintf('Tamaño inesperado: %s de %s bytes.', number_format($bytes), number_format($expectedSize)),
            ];
        }

        $sha = (string)($meta['sha256'] ?? '');
        if ($sha !== '') {
            $actual = hash_file('sha256', $path);
            if (!is_string($actual) || !hash_equals($sha, strtolower($actual))) {
                return ['ok' => false, 'bytes' => $bytes, 'verified' => false, 'error' => 'SHA-256 no coincide con el .meta de NVD.'];
            }
            return ['ok' => true, 'bytes' => $bytes, 'verified' => true];
        }

        return ['ok' => true, 'bytes' => $bytes, 'verified' => false];
    }
}
