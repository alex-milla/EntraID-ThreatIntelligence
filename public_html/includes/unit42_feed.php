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
            }

            Database::query(
                "UPDATE u42_sync
                 SET last_run_at = datetime('now'), files_total = ?, added = ?, updated = ?, error = NULL
                 WHERE id = 1",
                [$summary['total'], $summary['added'], $summary['updated']]
            );

            $summary['ok'] = true;
        } catch (Throwable $e) {
            $summary['errors'][] = $e->getMessage();
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
    public static function articles(string $search = '', int $limit = 100, int $offset = 0): array
    {
        $where = '1=1';
        $params = [];
        if ($search !== '') {
            $where .= ' AND (title LIKE ? OR path LIKE ?)';
            $like = '%' . $search . '%';
            $params[] = $like;
            $params[] = $like;
        }
        $sql = "SELECT * FROM u42_articles WHERE $where ORDER BY published_at DESC, id DESC LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;
        return Database::fetchAll($sql, $params);
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
}
