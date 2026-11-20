<?php
/**
 * Unit42Feed — descarga y normaliza los ficheros públicos de Unit 42.
 *
 * Fuente: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel
 *
 * El contenido original se guarda TAL CUAL en `u42_articles.content`.
 * El título, las secciones y los IOCs son datos derivados, pensados para
 * mostrar el fichero como un informe y para exportarlos a STIX/MISP/TXT.
 *
 * La sincronización compara el blob SHA de GitHub con el guardado: solo baja
 * los ficheros nuevos o modificados.
 */

declare(strict_types=1);

final class Unit42Feed
{
    public const TREE_API = 'https://api.github.com/repos/PaloAltoNetworks/Unit42-timely-threat-intel/git/trees/main?recursive=1';
    public const RAW_BASE = 'https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/';
    public const TARBALL  = 'https://codeload.github.com/PaloAltoNetworks/Unit42-timely-threat-intel/tar.gz/refs/heads/main';

    /** El mayor fichero del repo ronda los 45 KB; 256 KB deja margen. */
    private const MAX_BYTES = 262144;

    /** Ficheros que no son artículos. */
    private const EXCLUDED = [
        'readme.md', 'license', 'support.md', '.gitignore', 'security.md',
    ];

    // ============================================================
    // HTTP (cURL con respaldo de stream: hay hostings sin extensión curl)
    // ============================================================

    private static function httpGet(string $url, int $timeout = 30): ?string
    {
        $headers = [
            'User-Agent: EntraID-ThreatIntelligence/Unit42',
            'Accept: application/vnd.github+json, */*',
        ];

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => $timeout,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 5,
                CURLOPT_HTTPHEADER     => $headers,
            ]);
            $body = curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($body !== false && $code === 200) {
                return (string)$body;
            }
        }

        $ctx = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'timeout'       => $timeout,
                'follow_location' => 1,
                'max_redirects' => 5,
                'header'        => implode("\r\n", $headers) . "\r\n",
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $body = @file_get_contents($url, false, $ctx);
        return $body === false ? null : (string)$body;
    }

    private static function token(): string
    {
        $envFile = ROOT_PATH . '/.env';
        if (is_file($envFile)) {
            $lines = @file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            foreach ($lines as $line) {
                if (preg_match('/^\s*(?:export\s+)?GITHUB_TOKEN\s*=\s*(.+)$/', $line, $m)) {
                    return trim(trim((string)$m[1]), "\"'");
                }
            }
        }
        return trim((string)(getenv('GITHUB_TOKEN') ?: ''));
    }

    // ============================================================
    // Listado remoto
    // ============================================================

    /**
     * Devuelve los ficheros del repo con path, sha y size.
     *
     * @return array<int,array{path:string,sha:string,size:int}>
     */
    public static function remoteFiles(): array
    {
        $url = self::TREE_API;
        $token = self::token();
        if ($token !== '') {
            $url .= '&token=' . rawurlencode($token); // token personal (no recomendado en URL)
        }

        $json = self::httpGet($url, 30);
        if ($json === null) {
            throw new RuntimeException('No se pudo consultar el árbol de GitHub.');
        }
        $data = json_decode($json, true);
        if (!is_array($data) || empty($data['tree']) || !is_array($data['tree'])) {
            $message = is_array($data) && isset($data['message']) ? (string)$data['message'] : 'respuesta inesperada';
            throw new RuntimeException('GitHub: ' . $message);
        }

        $files = [];
        foreach ($data['tree'] as $entry) {
            if (!is_array($entry) || (string)($entry['type'] ?? '') !== 'blob') {
                continue;
            }
            $path = (string)($entry['path'] ?? '');
            if ($path === '' || str_contains($path, '..')) {
                continue;
            }
            $base = strtolower(basename($path));
            if (in_array($base, self::EXCLUDED, true)) {
                continue;
            }
            if (!preg_match('/\.(?:txt|md)$/i', $path)) {
                continue;
            }
            $size = (int)($entry['size'] ?? 0);
            if ($size > self::MAX_BYTES) {
                continue;
            }
            $files[] = [
                'path' => $path,
                'sha'  => (string)($entry['sha'] ?? ''),
                'size' => $size,
            ];
        }

        usort($files, static fn(array $a, array $b): int => strcmp($a['path'], $b['path']));
        return $files;
    }

    // ============================================================
    // Sincronización
    // ============================================================

    /**
     * Cuenta cuántos ficheros hay nuevos o modificados, SIN descargar nada y
     * SIN escribir en la BD. Se usa antes de pedir la descarga.
     *
     * @param array<int,array{path:string,sha:string,size:int}>|null $files
     */
    public static function check(?array $files = null): array
    {
        $result = [
            'ok' => true, 'total' => 0, 'new' => 0, 'changed' => 0,
            'unchanged' => 0, 'pending' => 0, 'error' => '',
        ];

        try {
            $files = $files ?? self::remoteFiles();
            $known = [];
            foreach (Database::fetchAll("SELECT path, sha FROM u42_articles") as $row) {
                $known[(string)$row['path']] = (string)$row['sha'];
            }

            foreach ($files as $file) {
                $path = (string)($file['path'] ?? '');
                $sha = (string)($file['sha'] ?? '');
                if (!self::needsDownload($path, $sha, $known)) {
                    $result['unchanged']++;
                } elseif (isset($known[$path])) {
                    $result['changed']++;
                } else {
                    $result['new']++;
                }
            }

            $result['total'] = count($files);
            $result['pending'] = $result['new'] + $result['changed'];
        } catch (Throwable $e) {
            $result['ok'] = false;
            $result['error'] = self::friendlyError($e);
        }

        return $result;
    }

    /** Error legible cuando el hosting no permite salir a GitHub. */
    public static function friendlyError(Throwable $e): string
    {
        $message = $e->getMessage();
        if (stripos($message, 'github') !== false || stripos($message, 'descarg') !== false) {
            return $message;
        }
        return 'El servidor no pudo acceder a GitHub. Comprueba la salida HTTPS del hosting. (' . $message . ')';
    }

    /** Progreso de la descarga en curso. */
    private static function setProgress(string $state, int $pending, int $processed): void
    {
        try {
            Database::query(
                "UPDATE u42_sync SET state = ?, pending = ?, processed = ? WHERE id = 1",
                [$state, $pending, $processed]
            );
        } catch (Throwable $ignore) {
            // El progreso es informativo: no debe romper la sincronización.
        }
    }

    /**
     * Descarga solo lo nuevo o modificado y lo guarda. Devuelve el resumen.
     */
    public static function sync(): array
    {
        $summary = [
            'ok' => false, 'total' => 0, 'added' => 0, 'updated' => 0,
            'unchanged' => 0, 'errors' => [],
        ];

        try {
            $files = self::remoteFiles();
            $summary['total'] = count($files);

            $known = [];
            foreach (Database::fetchAll("SELECT path, sha FROM u42_articles") as $row) {
                $known[(string)$row['path']] = (string)$row['sha'];
            }

            $pending = 0;
            foreach ($files as $file) {
                if (self::needsDownload((string)$file['path'], (string)$file['sha'], $known)) {
                    $pending++;
                }
            }
            self::setProgress('running', $pending, 0);

            foreach ($files as $file) {
                $path = $file['path'];
                $sha = $file['sha'];
                $existingSha = $known[$path] ?? '';

                if (!self::needsDownload($path, $sha, $known)) {
                    $summary['unchanged']++;
                    continue; // ya descargado y sin cambios: NO se vuelve a bajar
                }

                $raw = self::httpGet(self::RAW_BASE . rawurlencode($path), 30);
                if ($raw === null || strlen($raw) > self::MAX_BYTES) {
                    $summary['errors'][] = 'No se pudo descargar ' . $path;
                    continue;
                }

                $parsed = self::parseArticle($path, $raw);
                $isNew = $existingSha === '';

                if ($isNew) {
                    Database::insert(
                        "INSERT INTO u42_articles
                         (path, sha, size, title, published_at, kind, content, sections_json, first_seen_at, updated_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
                        [
                            $path,
                            $sha,
                            strlen($raw),
                            $parsed['title'],
                            $parsed['published_at'],
                            $parsed['kind'],
                            $raw, // original, sin tocar
                            json_encode($parsed['sections'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                        ]
                    );
                    $summary['added']++;
                } else {
                    Database::query(
                        "UPDATE u42_articles
                         SET sha = ?, size = ?, title = ?, published_at = ?,
                             content = ?, sections_json = ?, updated_at = datetime('now')
                         WHERE path = ?",
                        [
                            $sha,
                            strlen($raw),
                            $parsed['title'],
                            $parsed['published_at'],
                            $raw,
                            json_encode($parsed['sections'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                            $path,
                        ]
                    );
                    $summary['updated']++;
                }

                $articleId = (int)Database::fetchOne("SELECT id FROM u42_articles WHERE path = ?", [$path])['id'];
                self::saveIocs((int)$articleId, $parsed['sections'], $parsed['title']);

                $done = $summary['added'] + $summary['updated'] + count($summary['errors']);
                self::setProgress('running', $pending, $done);
            }

            Database::query(
                "UPDATE u42_sync
                 SET last_run_at = datetime('now'), files_total = ?, added = ?, updated = ?,
                     unchanged = ?, state = 'done', pending = 0, processed = ?,
                     finished_at = datetime('now'), error = NULL
                 WHERE id = 1",
                [
                    $summary['total'], $summary['added'], $summary['updated'],
                    $summary['unchanged'], $pending,
                ]
            );

            $summary['ok'] = true;
        } catch (Throwable $e) {
            $summary['errors'][] = $e->getMessage();
            self::setProgress('error', (int)($summary['total'] ?? 0), (int)($summary['added'] ?? 0) + (int)($summary['updated'] ?? 0));
            try {
                Database::query("UPDATE u42_sync SET last_run_at = datetime('now'), error = ? WHERE id = 1", [$e->getMessage()]);
            } catch (Throwable $ignore) {
                // nada más que hacer
            }
        }

        return $summary;
    }

    /**
     * Vuelve a parsear el contenido ya guardado, SIN descargar nada.
     * Útil cuando mejora el parser: el original no se toca.
     */
    public static function reparse(): array
    {
        $count = 0;
        foreach (Database::fetchAll("SELECT id, path, content FROM u42_articles") as $row) {
            $parsed = self::parseArticle((string)$row['path'], (string)$row['content']);
            Database::query(
                "UPDATE u42_articles
                 SET title = ?, published_at = ?, sections_json = ?, updated_at = datetime('now')
                 WHERE id = ?",
                [
                    $parsed['title'],
                    $parsed['published_at'],
                    json_encode($parsed['sections'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                    (int)$row['id'],
                ]
            );
            self::saveIocs((int)$row['id'], $parsed['sections'], $parsed['title']);
            $count++;
        }
        return ['reparsed' => $count];
    }

    /** ¿Hay que descargar este fichero? (no si el SHA local coincide). */
    public static function needsDownload(string $path, string $sha, array $known): bool
    {
        return !isset($known[$path]) || (string)$known[$path] !== $sha;
    }

    /** Estado de la última sincronización. */
    public static function status(): array
    {
        $row = Database::fetchOne("SELECT * FROM u42_sync WHERE id = 1");
        $counts = Database::fetchOne(
            "SELECT COUNT(*) AS articles, COALESCE(SUM(size), 0) AS bytes FROM u42_articles"
        ) ?? [];
        $iocs = Database::fetchOne("SELECT COUNT(*) AS c FROM u42_iocs") ?? [];

        return [
            'state'       => (string)($row['state'] ?? 'idle'),
            'pending'     => (int)($row['pending'] ?? 0),
            'processed'   => (int)($row['processed'] ?? 0),
            'started_at'  => (string)($row['started_at'] ?? ''),
            'finished_at' => (string)($row['finished_at'] ?? ''),
            'last_run_at' => (string)($row['last_run_at'] ?? ''),
            'files_total' => (int)($row['files_total'] ?? 0),
            'added'       => (int)($row['added'] ?? 0),
            'updated'     => (int)($row['updated'] ?? 0),
            'error'       => (string)($row['error'] ?? ''),
            'articles'    => (int)($counts['articles'] ?? 0),
            'bytes'       => (int)($counts['bytes'] ?? 0),
            'iocs'        => (int)($iocs['c'] ?? 0),
            'new'         => (int)(Database::fetchOne(
                "SELECT COUNT(*) AS c FROM u42_articles WHERE first_seen_at >= datetime('now', '-7 days')"
            )['c'] ?? 0),
        ];
    }

    // ============================================================
    // Parser (derivado; el original no se modifica)
    // ============================================================

    /**
     * Parsea un fichero de Unit42. Si el formato no encaja, devuelve el texto
     * en una única sección «TEXTO» para que siempre se pueda mostrar.
     *
     * @return array{title:string,published_at:string,kind:string,sections:array<int,array<string,mixed>>}
     */
    public static function parseArticle(string $path, string $content): array
    {
        $lines = preg_split('/\r\n|\r|\n/', $content) ?: [];
        $title = basename($path);
        $published = '';

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            if (preg_match('/^(\d{4}-\d{2}-\d{2})\s*(?:\([^)]*\)\s*)?[-:]\s*(.+)$/', $line, $m)) {
                $published = $m[1];
                $title = trim($m[2]);
            }
            break;
        }

        $sections = [];
        $rawLines = [];
        $currentIndex = -1;

        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '') {
                continue;
            }

            // Cabecera de sección: AUTHORS:, REFERENCES:, NOTES:, DETAILS:, INDICATORS:
            if (preg_match('/^([A-Z][A-Z0-9 \-\/]{2,40}):\s*$/', $trimmed, $m)) {
                $sections[] = ['title' => trim($m[1]), 'items' => []];
                $currentIndex = count($sections) - 1;
                continue;
            }

            // Viñetas con jerarquía: -, --, --- …
            if (preg_match('/^\s*(-{1,4})\s+(.+)$/', $line, $m)) {
                $depth = strlen($m[1]);
                $text = rtrim((string)$m[2]);
                if ($currentIndex >= 0) {
                    $sections[$currentIndex]['items'][] = ['depth' => $depth, 'text' => $text, 'label' => false];
                }
                $rawLines[] = $text;
                continue;
            }

            // Etiqueta dentro de una sección (p. ej. «SHA-256 hash of the DLL:»)
            if ($currentIndex >= 0) {
                $sections[$currentIndex]['items'][] = ['depth' => 0, 'text' => $trimmed, 'label' => true];
            }
            $rawLines[] = $trimmed;
        }

        if ($sections === []) {
            $sections[] = [
                'title' => 'TEXTO',
                'items' => array_map(
                    static fn(string $text): array => ['depth' => 0, 'text' => $text, 'label' => false],
                    $rawLines
                ),
            ];
        }

        return [
            'title'        => $title,
            'published_at' => $published,
            'kind'         => preg_match('/\.md$/i', $path) ? 'md' : 'txt',
            'sections'     => $sections,
        ];
    }

    /** Quita el "defanging" para poder usar el IOC. */
    public static function refang(string $value): string
    {
        $value = trim($value);
        $value = str_ireplace(['[.]', '(.)', '[dot]', ' hxxp'], ['.', '.', '.', ' http'], $value);
        $value = str_ireplace(['hxxps://', 'hxxp://'], ['https://', 'http://'], $value);
        $value = preg_replace('/\s+-\s+.*$/', '', $value) ?? $value; // quita el " - IP:443 (TLS)" posterior
        return trim($value, " \t\n\r\0\x0B\"'`<>");
    }

    /**
     * Extrae IOCs de la sección INDICATORS/IOCs con el vocabulario del
     * exportador STIX. El resto de secciones (NOTES, DETAILS) se ignoran:
     * contienen nombres de ficheros y claves que no son IOCs.
     *
     * @return array<int,array{ioc_type:string,ioc_value:string,description:string}>
     */
    public static function extractIocs(array $sections): array
    {
        $found = [];
        $label = '';
        $fileExtensions = 'exe|dll|pdf|zip|dat|png|jpe?g|gif|ico|py|js|json|ya?ml|log|docx?|xlsx?|pptx?|txt|csv|xml|html?|conf|ini|sh|bat|ps1|wasm|crx|apk|md|sys';

        /* Los ficheros recientes tienen INDICATORS; los antiguos meten los
         * IOCs dentro de cada sección con etiquetas ("SHA256 hash: …"). */
        $hasIndicators = false;
        foreach ($sections as $section) {
            if (preg_match('/INDICATORS|IOCS|IOC/i', (string)($section['title'] ?? ''))) {
                $hasIndicators = true;
                break;
            }
        }

        foreach ($sections as $section) {
            $sectionTitle = strtoupper((string)($section['title'] ?? ''));
            if ($hasIndicators && !preg_match('/INDICATORS|IOCS|IOC/', $sectionTitle)) {
                continue;
            }

            $items = is_array($section['items'] ?? null) ? $section['items'] : [];
            foreach ($items as $item) {
                $text = (string)($item['text'] ?? '');

                if ((bool)($item['label'] ?? false) || preg_match('/:$/', $text)) {
                    $label = $text;
                    continue;
                }

                /* Formato antiguo: "- SHA256 hash: <valor>" */
                if (!$hasIndicators && preg_match('/^([^:]{3,60}):\s*(.+)$/', $text, $m)) {
                    $label = trim($m[1]);
                    $text = trim($m[2]);
                }
                $text = str_ireplace(['[.]', '(.)', '[dot]'], '.', $text);
                $text = str_ireplace(['hxxps://', 'hxxp://'], ['https://', 'http://'], $text);

                $parts = [];

                // URLs primero, para no contar también su dominio.
                if (preg_match_all('~https?://[^\s<>"\']+~i', $text, $m)) {
                    foreach ($m[0] as $url) {
                        $parts[] = ['url', rtrim($url, '.,;')];
                    }
                    $text = preg_replace('~https?://[^\s<>"\']+~i', ' ', $text) ?? $text;
                }

                // Hashes SHA-256 / SHA-1 / MD5 → `file` (el exportador distingue por longitud).
                // Si la etiqueta habla de "key"/"password", no es un hash de fichero.
                $isKeyLine = (bool)preg_match('/key|password|contraseña/i', $label . ' ' . $text);
                if (!$isKeyLine && preg_match_all('/\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/', $text, $m)) {
                    foreach ($m[0] as $hash) {
                        $parts[] = ['file', strtolower($hash)];
                    }
                    $text = preg_replace('/\b[a-fA-F0-9]{32,64}\b/', ' ', $text) ?? $text;
                }

                // IPv4 (ya sin defanging)
                if (preg_match_all('/\b\d{1,3}(?:\.\d{1,3}){3}\b/', $text, $m)) {
                    foreach ($m[0] as $ip) {
                        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                            $parts[] = ['ipv4-addr', $ip];
                        }
                    }
                    $text = preg_replace('/\b\d{1,3}(?:\.\d{1,3}){3}\b/', ' ', $text) ?? $text;
                }

                // Nombres y rutas de ficheros (antes que dominios: "krpt.dll" no es un dominio).
                $filePattern = '#(?:[A-Za-z0-9_\-]+[\\\\/])*[A-Za-z0-9_\-?]+\.(?:' . $fileExtensions . ')\b#i';
                if (preg_match_all($filePattern, $text, $m)) {
                    foreach ($m[0] as $fileName) {
                        $parts[] = ['file', $fileName];
                    }
                    $text = preg_replace($filePattern, ' ', $text) ?? $text;
                }

                // Dominios (ya sin nombres de fichero)
                if (preg_match_all('/\b(?:[a-z0-9\-]+\.)+[a-z]{2,24}\b/i', $text, $m)) {
                    foreach ($m[0] as $domain) {
                        $parts[] = ['domain-name', strtolower($domain)];
                    }
                }

                foreach ($parts as $part) {
                    $value = self::refang((string)$part[1]);
                    if ($value === '') {
                        continue;
                    }
                    $key = $part[0] . '|' . $value;
                    if (isset($found[$key])) {
                        continue;
                    }
                    $found[$key] = [
                        'ioc_type'    => $part[0],
                        'ioc_value'   => $value,
                        'description' => trim($label !== '' ? $label . ' · ' . $text : $text),
                    ];
                }
            }
        }

        return array_values($found);
    }

    private static function saveIocs(int $articleId, array $sections, string $title): void
    {
        Database::query("DELETE FROM u42_iocs WHERE article_id = ?", [$articleId]);
        foreach (self::extractIocs($sections) as $ioc) {
            $description = $ioc['description'];
            if (function_exists('mb_substr')) {
                $description = mb_substr($description, 0, 500);
            } else {
                $description = substr($description, 0, 500);
            }
            Database::query(
                "INSERT OR IGNORE INTO u42_iocs (article_id, ioc_type, ioc_value, description, section, first_seen)
                 VALUES (?, ?, ?, ?, ?, datetime('now'))",
                [
                    $articleId,
                    $ioc['ioc_type'],
                    $ioc['ioc_value'],
                    $description,
                    $title,
                ]
            );
        }
    }

    // ============================================================
    // Consultas locales
    // ============================================================

    public static function countArticles(): int
    {
        return (int)(Database::fetchOne("SELECT COUNT(*) AS c FROM u42_articles")['c'] ?? 0);
    }

    /** @return array<int,array<string,mixed>> */
    public static function articles(array $filters = [], int $limit = 50, int $offset = 0): array
    {
        $userId = (int)($filters['user_id'] ?? 0);
        $where = ['1=1'];
        $params = [];
        $stateJoin = '';
        $stateSelect = '0 AS is_read, 0 AS is_favorite';

        if ($userId > 0) {
            $stateJoin = ' LEFT JOIN u42_article_state s ON s.article_id = a.id AND s.user_id = ?';
            $params[] = $userId; // el parámetro del JOIN va antes que los del WHERE
            $stateSelect = 'COALESCE(s.is_read, 0) AS is_read, COALESCE(s.is_favorite, 0) AS is_favorite';
        }

        $search = trim((string)($filters['q'] ?? ''));
        if ($search !== '') {
            $like = '%' . $search . '%';
            $where[] = '(a.title LIKE ? OR a.path LIKE ?)';
            $params[] = $like;
            $params[] = $like;
        }
        $from = trim((string)($filters['from'] ?? ''));
        if ($from !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) {
            $where[] = 'date(a.published_at) >= ?';
            $params[] = $from;
        }
        $to = trim((string)($filters['to'] ?? ''));
        if ($to !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $to)) {
            $where[] = 'date(a.published_at) <= ?';
            $params[] = $to;
        }
        if ($userId > 0 && !empty($filters['only_unread'])) {
            $where[] = 'COALESCE(s.is_read, 0) = 0';
        }
        if ($userId > 0 && !empty($filters['only_favorites'])) {
            $where[] = 'COALESCE(s.is_favorite, 0) = 1';
        }
        if (!empty($filters['only_iocs'])) {
            $where[] = 'EXISTS (SELECT 1 FROM u42_iocs i WHERE i.article_id = a.id)';
        }

        $sql = "SELECT a.*, $stateSelect FROM u42_articles a $stateJoin
                WHERE " . implode(' AND ', $where) . "
                ORDER BY a.published_at DESC, a.id DESC LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;
        return Database::fetchAll($sql, $params);
    }

    /** Estados de lectura de una lista de artículos para un usuario. */
    public static function statesFor(int $userId, array $ids): array
    {
        if ($userId <= 0 || $ids === []) {
            return [];
        }
        $ids = array_values(array_filter(array_map('intval', $ids)));
        if ($ids === []) {
            return [];
        }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $rows = Database::fetchAll(
            "SELECT article_id, is_read, is_favorite FROM u42_article_state
             WHERE user_id = ? AND article_id IN ($placeholders)",
            array_merge([$userId], $ids)
        );
        $out = [];
        foreach ($rows as $row) {
            $out[(int)$row['article_id']] = $row;
        }
        return $out;
    }

    /**
     * Aplica un cambio de estado a uno o varios artículos (upsert por usuario).
     * Devuelve el número de filas afectadas.
     */
    public static function setArticleState(int $userId, array $ids, array $changes): int
    {
        $ids = array_values(array_filter(array_map('intval', $ids)));
        if ($userId <= 0 || $ids === []) {
            return 0;
        }

        $read = null;
        if (array_key_exists('is_read', $changes)) {
            $read = !empty($changes['is_read']) ? 1 : 0;
        }
        $fav = null;
        if (array_key_exists('is_favorite', $changes)) {
            $fav = !empty($changes['is_favorite']) ? 1 : 0;
        }
        if ($read === null && $fav === null) {
            return 0;
        }

        $changed = 0;
        foreach ($ids as $articleId) {
            $current = Database::fetchOne(
                "SELECT is_read, read_at, is_favorite, favorite_at FROM u42_article_state
                 WHERE user_id = ? AND article_id = ?",
                [$userId, $articleId]
            ) ?: ['is_read' => 0, 'read_at' => null, 'is_favorite' => 0, 'favorite_at' => null];

            $newRead = $read ?? (int)$current['is_read'];
            $newFav = $fav ?? (int)$current['is_favorite'];
            $readAt = $newRead ? ($current['read_at'] ?: gmdate('Y-m-d H:i:s')) : null;
            $favAt = $newFav ? ($current['favorite_at'] ?: gmdate('Y-m-d H:i:s')) : null;

            $stmt = Database::query(
                "INSERT INTO u42_article_state
                 (user_id, article_id, is_read, read_at, is_favorite, favorite_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                 ON CONFLICT(user_id, article_id) DO UPDATE SET
                     is_read = excluded.is_read, read_at = excluded.read_at,
                     is_favorite = excluded.is_favorite, favorite_at = excluded.favorite_at,
                     updated_at = datetime('now')",
                [$userId, $articleId, $newRead, $readAt, $newFav, $favAt]
            );
            $changed += $stmt->rowCount();
        }
        return $changed;
    }

    /** Contadores para la cabecera (no leídos, favoritos, totales). */
    public static function stateCounts(int $userId): array
    {
        $total = (int)(Database::fetchOne("SELECT COUNT(*) AS c FROM u42_articles")['c'] ?? 0);
        $withIocs = (int)(Database::fetchOne(
            "SELECT COUNT(DISTINCT article_id) AS c FROM u42_iocs"
        )['c'] ?? 0);
        if ($userId <= 0) {
            return ['total' => $total, 'unread' => 0, 'favorites' => 0, 'with_iocs' => $withIocs];
        }
        $row = Database::fetchOne(
            "SELECT
                SUM(CASE WHEN COALESCE(s.is_read, 0) = 0 THEN 1 ELSE 0 END) AS unread,
                SUM(CASE WHEN COALESCE(s.is_favorite, 0) = 1 THEN 1 ELSE 0 END) AS favorites
             FROM u42_articles a
             LEFT JOIN u42_article_state s ON s.article_id = a.id AND s.user_id = ?",
            [$userId]
        ) ?: [];
        return [
            'total'     => $total,
            'unread'    => (int)($row['unread'] ?? 0),
            'favorites' => (int)($row['favorites'] ?? 0),
            'with_iocs' => $withIocs,
        ];
    }

    /** @return array<string,mixed>|null */
    public static function article(int $id): ?array
    {
        $row = Database::fetchOne("SELECT * FROM u42_articles WHERE id = ?", [$id]);
        if ($row === null) {
            return null;
        }
        $row['sections'] = json_decode((string)($row['sections_json'] ?? '[]'), true) ?: [];
        return $row;
    }

    /** @return array<int,array<string,mixed>> */
    public static function iocs(int $articleId): array
    {
        return Database::fetchAll(
            "SELECT * FROM u42_iocs WHERE article_id = ? ORDER BY ioc_type, ioc_value",
            [$articleId]
        );
    }

    /** @return array<int,array<string,mixed>> */
    public static function iocCounts(int $articleId): array
    {
        return Database::fetchAll(
            "SELECT ioc_type, COUNT(*) AS c FROM u42_iocs WHERE article_id = ? GROUP BY ioc_type ORDER BY c DESC",
            [$articleId]
        );
    }

    // ============================================================
    // Informes con IA sobre publicaciones seleccionadas
    // ============================================================

    /** Tipos de informe disponibles. */
    public static function reportKinds(): array
    {
        return [
            'resumen'     => ['label' => 'Resumen ejecutivo', 'hint' => 'Qué ha pasado, riesgo y decisión que se pide. Sin inventar datos.'],
            'divulgativa' => ['label' => 'Nota divulgativa', 'hint' => 'Explicación clara del incidente para personal no técnico.'],
            'impacto'     => ['label' => 'Impacto para cliente/sector', 'hint' => 'Qué significa para el sector y el tenant seleccionado.'],
            'indicadores' => ['label' => 'Extracción de IOCs', 'hint' => 'Indicadores del texto narrativo que no cubre la extracción automática.'],
        ];
    }

    /** Prompt efectivo (personalización de Admin → Plantillas o valor por defecto). */
    private static function prompt(string $key): string
    {
        $catalog = llm_prompts_catalog();
        $default = (string)($catalog[$key]['default'] ?? '');
        return llm_prompt($key, $default);
    }

    /** Contexto de las publicaciones seleccionadas para la IA. */
    public static function reportContext(array $ids, int $tenantId = 0, string $kind = 'resumen'): string
    {
        $ids = array_values(array_filter(array_map('intval', $ids)));
        if ($ids === []) {
            return '';
        }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $rows = Database::fetchAll(
            "SELECT * FROM u42_articles WHERE id IN ($placeholders) ORDER BY published_at DESC, id DESC",
            $ids
        );

        $parts = [];
        $index = 0;
        foreach ($rows as $row) {
            $index++;
            $sections = json_decode((string)($row['sections_json'] ?? '[]'), true) ?: [];
            $block = [];
            $block[] = '### PUBLICACIÓN ' . $index . ': ' . (string)($row['title'] ?? '');
            $block[] = 'Fecha: ' . (string)($row['published_at'] ?? 'sin fecha');
            $block[] = 'Fichero: ' . (string)($row['path'] ?? '');

            foreach ($sections as $section) {
                $title = strtoupper((string)($section['title'] ?? ''));
                if ($kind === 'indicadores' && !preg_match('/NOTAS|DETAILS|NOTES|DETALLES/', $title)) {
                    continue;
                }
                $lines = [];
                foreach (($section['items'] ?? []) as $item) {
                    $lines[] = str_repeat('  ', max(0, (int)($item['depth'] ?? 0) - 1))
                        . '- ' . (string)($item['text'] ?? '');
                }
                if ($lines !== []) {
                    $block[] = $title . ":\n" . implode("\n", $lines);
                }
            }

            if ($kind === 'indicadores') {
                $known = self::iocs((int)$row['id']);
                if ($known !== []) {
                    $lines = [];
                    foreach (array_slice($known, 0, 60) as $ioc) {
                        $lines[] = '- [' . $ioc['ioc_type'] . '] ' . $ioc['ioc_value'];
                    }
                    $block[] = "IOCS YA DETECTADOS (no los repitas):\n" . implode("\n", $lines);
                }
            }

            $text = implode("\n", $block);
            $text = function_exists('mb_substr') ? mb_substr($text, 0, 5000) : substr($text, 0, 5000);
            $parts[] = $text;
        }

        $out = "PUBLICACIONES SELECCIONADAS (" . count($parts) . "):\n\n" . implode("\n\n---\n\n", $parts);

        if ($tenantId > 0 && $kind === 'impacto') {
            $tenant = class_exists('TenantManager') ? TenantManager::getById($tenantId) : null;
            if (is_array($tenant)) {
                $ctx = [];
                foreach (['name', 'sector', 'industry', 'country'] as $field) {
                    if (!empty($tenant[$field])) {
                        $ctx[] = $field . ': ' . $tenant[$field];
                    }
                }
                if ($ctx !== []) {
                    $out = "CONTEXTO DEL TENANT: " . implode(' · ', $ctx) . "\n\n" . $out;
                }
            }
        }

        return $out;
    }

    /** Crea un informe en cola para las publicaciones seleccionadas. */
    public static function createReport(int $userId, array $ids, string $kind, int $tenantId = 0, int $profileId = 0): array
    {
        if (!isset(self::reportKinds()[$kind])) {
            return ['success' => false, 'error' => 'Tipo de informe no válido.'];
        }
        $ids = array_values(array_filter(array_map('intval', $ids)));
        if ($ids === []) {
            return ['success' => false, 'error' => 'Selecciona al menos una publicación.'];
        }

        $title = self::reportKinds()[$kind]['label'] . ' · ' . gmdate('Y-m-d H:i');
        $id = Database::insert(
            "INSERT INTO u42_reports (user_id, tenant_id, kind, title, status, article_ids_json, created_at)
             VALUES (?, ?, ?, ?, 'pending', ?, datetime('now'))",
            [$userId, $tenantId, $kind, $title, json_encode($ids)]
        );
        foreach ($ids as $position => $articleId) {
            Database::query(
                "INSERT OR IGNORE INTO u42_report_items (report_id, article_id, position) VALUES (?, ?, ?)",
                [$id, $articleId, $position]
            );
        }
        return ['success' => true, 'id' => (int)$id];
    }

    /** Ejecuta un informe usando la capa única de IA y el cerrojo de trabajos. */
    public static function runReport(int $id): array
    {
        $report = self::report($id);
        if ($report === null) {
            return ['success' => false, 'error' => 'Informe no encontrado.'];
        }
        $kind = (string)($report['kind'] ?? 'resumen');
        $ids = is_array($report['article_ids'] ?? null) ? $report['article_ids'] : [];
        $profileId = (int)($report['profile_id'] ?? 0);

        $owner = 'unit42-report-' . $id;
        if (!llm_job_acquire($owner, 'unit42_report')) {
            $msg = 'Hay otro trabajo de IA en curso. Vuelve a intentarlo en unos minutos.';
            Database::query("UPDATE u42_reports SET status = 'error', error = ? WHERE id = ?", [$msg, $id]);
            return ['success' => false, 'error' => $msg];
        }

        Database::query("UPDATE u42_reports SET status = 'running' WHERE id = ?", [$id]);

        try {
            $user = self::reportContext($ids, (int)($report['tenant_id'] ?? 0), $kind);
            $promptKey = $kind === 'indicadores' ? 'llm.unit42.indicators.system' : 'llm.unit42.' . $kind . '.system';
            $system = self::prompt($promptKey);
            if ($kind !== 'indicadores') {
                $system .= "\n\n" . self::prompt('llm.unit42.format')
                    . "\n\n" . self::prompt('llm.unit42.sources');
            }

            $options = ['max_tokens' => $kind === 'indicadores' ? 1800 : 1600, 'think' => false];
            if ($profileId > 0) {
                $options['profile_id'] = $profileId;
            }

            if ($kind === 'indicadores') {
                $res = llm_run_json('unit42_report', $system, $user, $options);
                $data = is_array($res['data'] ?? null) ? $res['data'] : [];
                $lines = ['# Extracción de IOCs', '', (string)($data['resumen'] ?? 'Sin resumen.'), ''];
                $iocs = is_array($data['iocs'] ?? null) ? $data['iocs'] : [];
                if ($iocs !== []) {
                    $lines[] = '| Tipo | Valor | Contexto |';
                    $lines[] = '|---|---|---|';
                    foreach ($iocs as $ioc) {
                        if (!is_array($ioc)) { continue; }
                        $lines[] = '| ' . (string)($ioc['tipo'] ?? '') . ' | '
                            . (string)($ioc['valor'] ?? '') . ' | '
                            . str_replace('|', '\\|', (string)($ioc['contexto'] ?? '')) . ' |';
                    }
                } else {
                    $lines[] = 'No se extrajeron indicadores nuevos del texto narrativo.';
                }
                $lines[] = '';
                $lines[] = '## Recomendaciones';
                $lines[] = '';
                $lines[] = (string)($data['recomendaciones'] ?? 'Sin recomendaciones.');
                $content = implode("\n", $lines);

                if ($ids !== []) {
                    foreach ($iocs as $ioc) {
                        if (!is_array($ioc)) { continue; }
                        $value = trim((string)($ioc['valor'] ?? ''));
                        $type = trim((string)($ioc['tipo'] ?? ''));
                        if ($value === '' || $type === '') { continue; }
                        Database::query(
                            "INSERT OR IGNORE INTO u42_iocs (article_id, ioc_type, ioc_value, description, source, first_seen)
                             VALUES (?, ?, ?, ?, 'ia', datetime('now'))",
                            [(int)$ids[0], $type, $value, 'Extraído con IA · informe #' . $id
                                . ' · ' . (string)($ioc['contexto'] ?? '')]
                        );
                    }
                }
            } else {
                $res = llm_run('unit42_report', $system, $user, $options);
                $content = trim((string)($res['content'] ?? ''));
            }
            $model = (string)($res['model'] ?? '');

            if (empty($res['success']) || trim($content) === '') {
                $error = (string)($res['error'] ?? 'La IA no devolvió contenido.');
                Database::query(
                    "UPDATE u42_reports SET status = 'error', error = ?, finished_at = datetime('now') WHERE id = ?",
                    [$error, $id]
                );
                return ['success' => false, 'error' => $error];
            }

            Database::query(
                "UPDATE u42_reports
                 SET status = 'done', content_md = ?, model = ?, error = NULL, finished_at = datetime('now')
                 WHERE id = ?",
                [$content, $model, $id]
            );
            return ['success' => true, 'id' => $id, 'content' => $content];
        } catch (Throwable $e) {
            Database::query(
                "UPDATE u42_reports SET status = 'error', error = ?, finished_at = datetime('now') WHERE id = ?",
                [$e->getMessage(), $id]
            );
            return ['success' => false, 'error' => $e->getMessage()];
        } finally {
            llm_job_release($owner);
        }
    }

    /** @return array<int,array<string,mixed>> */
    public static function reports(int $userId): array
    {
        return Database::fetchAll(
            "SELECT * FROM u42_reports WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 100",
            [$userId]
        );
    }

    /** @return array<string,mixed>|null */
    public static function report(int $id): ?array
    {
        $row = Database::fetchOne("SELECT * FROM u42_reports WHERE id = ?", [$id]);
        if ($row === null) {
            return null;
        }
        $row['article_ids'] = json_decode((string)($row['article_ids_json'] ?? '[]'), true) ?: [];
        $row['articles'] = [];
        if ($row['article_ids'] !== []) {
            $placeholders = implode(',', array_fill(0, count($row['article_ids']), '?'));
            $row['articles'] = Database::fetchAll(
                "SELECT id, title, published_at, path FROM u42_articles WHERE id IN ($placeholders) ORDER BY published_at DESC",
                $row['article_ids']
            );
        }
        return $row;
    }

    public static function reportStatus(int $id): array
    {
        $row = Database::fetchOne("SELECT id, status, error, created_at, finished_at FROM u42_reports WHERE id = ?", [$id]);
        return $row ?? ['id' => $id, 'status' => 'missing', 'error' => 'Informe no encontrado.'];
    }


    /** HTML limpio para copiar/exportar el informe a Word (estilos en línea). */
    public static function reportWordHtml(array $report): string
    {
        $esc = static fn(mixed $v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $lines = preg_split('/\r\n|\r|\n/', (string)($report['content_md'] ?? '')) ?: [];
        $out = ['<div style="font-family:Segoe UI,Arial,sans-serif;color:#111827;font-size:11pt;line-height:1.45;">'];
        $out[] = '<p style="margin:0 0 2pt;font-size:8pt;letter-spacing:1pt;color:#6b7280;font-weight:700;">'
            . 'INFORME UNIT 42 · ' . $esc((string)($report['title'] ?? '')) . '</p>';

        $inList = false;
        $inTable = false;
        $tableRows = [];
        $flushTable = static function () use (&$out, &$tableRows, &$inTable): void {
            if ($tableRows === []) { return; }
            $out[] = '<table style="width:100%;border-collapse:collapse;margin:10pt 0;font-size:9pt;">';
            foreach ($tableRows as $index => $cells) {
                if ($index === 1 && preg_match('/^\-+$/', implode('', $cells))) { continue; }
                $out[] = '<tr>';
                foreach ($cells as $cell) {
                    $out[] = ($index === 0)
                        ? '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5pt;text-align:left;">' . $cell . '</th>'
                        : '<td style="border:1px solid #d1d5db;padding:5pt;vertical-align:top;">' . $cell . '</td>';
                }
                $out[] = '</tr>';
            }
            $out[] = '</table>';
            $tableRows = [];
            $inTable = false;
        };

        foreach ($lines as $line) {
            $trimmed = trim($line);
            if (str_starts_with($trimmed, '|')) {
                if ($inList) { $out[] = '</ul>'; $inList = false; }
                $inTable = true;
                $cells = array_map(static fn(string $c): string => $esc(trim($c)),
                    array_filter(explode('|', $trimmed), static fn(string $c): bool => trim($c) !== ''));
                $tableRows[] = array_values($cells);
                continue;
            }
            if ($inTable) { $flushTable(); }

            if (preg_match('/^(#{1,3})\s+(.*)$/', $trimmed, $m)) {
                if ($inList) { $out[] = '</ul>'; $inList = false; }
                $level = strlen($m[1]);
                $size = $level === 1 ? '15pt' : ($level === 2 ? '12pt' : '11pt');
                $out[] = '<h' . $level . ' style="font-size:' . $size . ';font-weight:700;margin:14pt 0 5pt;color:#111827;">'
                    . $esc((string)$m[2]) . '</h' . $level . '>';
                continue;
            }
            if (preg_match('/^[-*]\s+(.*)$/', $trimmed, $m)) {
                if (!$inList) { $out[] = '<ul style="margin:5pt 0 8pt 16pt;padding:0;list-style:disc;">'; $inList = true; }
                $out[] = '<li style="margin:3pt 0;">' . $esc((string)$m[1]) . '</li>';
                continue;
            }
            if ($inList) { $out[] = '</ul>'; $inList = false; }
            if ($trimmed === '') { continue; }
            $out[] = '<p style="margin:0 0 7pt;">' . $esc($trimmed) . '</p>';
        }
        if ($inList) { $out[] = '</ul>'; }
        $flushTable();

        $articles = is_array($report['articles'] ?? null) ? $report['articles'] : [];
        if ($articles !== []) {
            $out[] = '<p style="margin:14pt 0 4pt;font-size:8pt;color:#6b7280;font-weight:700;">FUENTES CONSULTADAS</p>';
            $out[] = '<ul style="margin:0 0 0 16pt;padding:0;list-style:disc;">';
            foreach ($articles as $article) {
                $out[] = '<li style="margin:2pt 0;font-size:9pt;color:#4b5563;">'
                    . $esc((string)($article['published_at'] ?? '')) . ' · ' . $esc((string)($article['title'] ?? ''))
                    . '</li>';
            }
            $out[] = '</ul>';
        }
        $out[] = '</div>';
        return implode("\n", $out);
    }

}
