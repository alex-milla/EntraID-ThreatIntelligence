<?php
/**
 * CveSync — sincronización del catálogo público de CVEs (NVD API 2.0).
 *
 * Fase 2: carga inicial (full/recent), índice de productos y matching local
 * contra el inventario de software. KEV/EPSS llegan en la Fase 4.
 */

declare(strict_types=1);

class CveSync
{
    private ?CveClient $client;
    private ?CveClient $resolvedClient = null;
    private ?array $watchlistMap = null;
    private float $minCvss = 0.0;

    public function __construct(?CveClient $client = null)
    {
        $this->client = $client;
    }

    private function client(): CveClient
    {
        if ($this->client !== null) {
            return $this->client;
        }
        if ($this->resolvedClient === null) {
            $this->resolvedClient = CveClient::fromSettings();
        }
        return $this->resolvedClient;
    }

    // ============================================================
    // Estado / control
    // ============================================================

    public function state(): ?array
    {
        return CveDatabase::fetchOne("SELECT * FROM cve_sync_state WHERE id = 1") ?: null;
    }

    public function counts(): array
    {
        $row = CveDatabase::fetchOne(
            "SELECT COUNT(*) AS total,
                    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high
             FROM cve_catalog"
        ) ?: [];
        return [
            'catalog'  => (int)($row['total'] ?? 0),
            'critical' => (int)($row['critical'] ?? 0),
            'high'     => (int)($row['high'] ?? 0),
            'products' => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_product")['c'] ?? 0),
            'matches'  => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_watchlist_match")['c'] ?? 0),
            'software' => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM software_watchlist")['c'] ?? 0),
            'groups'   => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM software_groups")['c'] ?? 0),
        ];
    }

    public function status(): array
    {
        $state = $this->publicState($this->state());
        $running = $state && in_array((string)$state['status'], ['queued', 'running'], true);
        return [
            'success' => true,
            'state'   => $state,
            'counts'  => $running ? [] : $this->counts(),
        ];
    }

    /**
     * Estado ligero para el badge global y el polling de la página CVE.
     * No ejecuta COUNT(*): solo lee cve_sync_state.
     */
    public function activeStatus(): array
    {
        $state = $this->publicState($this->state());
        $active = $state !== null && in_array((string)$state['status'], ['queued', 'running'], true);
        return [
            'success' => true,
            'active'  => $active,
            'state'   => $state,
        ];
    }

    /**
     * Elimina secretos internos (token del worker, base_url) antes de enviar
     * el estado al navegador.
     */
    public function publicState(?array $state): ?array
    {
        if ($state === null) {
            return null;
        }
        unset($state['token'], $state['base_url']);
        return $state;
    }

    /**
     * Inicia una sincronización global. Solo un job a la vez.
     */
    public function start(?string $mode = null): array
    {
        $cfg = CveClient::config();
        if (!CveClient::isSafeUrl((string)($cfg['nvd_url'] ?? ''))) {
            return ['success' => false, 'error' => 'La URL de NVD no es válida. Revísala en Admin → APIs.'];
        }
        $mode = strtolower(trim((string)($mode ?? ($cfg['scope'] ?? 'full'))));
        if (!in_array($mode, ['full', 'recent'], true)) {
            return [
                'success' => false,
                'error'   => 'El modo «solo KEV + EPSS» se habilitará en la Fase 4. Usa Full o Reciente.',
            ];
        }

        $state = $this->state();
        $resume = false;
        $cursor = 0;
        $total = 0;
        $processed = 0;
        $inserted = 0;
        $updatedCount = 0;
        $windowStart = null;
        $windowEnd = null;

        if ($state && in_array((string)$state['status'], ['queued', 'running'], true)) {
            $lastUpdate = $this->dbTime($state['updated_at'] ?? null);
            if ($lastUpdate > 0 && (time() - $lastUpdate) < (int)CVE_SYNC_STALE) {
                return ['success' => false, 'error' => 'Ya hay una sincronización en curso.'];
            }
            // Reanudar el mismo modo/fase en vez de empezar de cero.
            if ((string)($state['mode'] ?? '') === $mode && (string)($state['phase'] ?? '') === 'nvd') {
                $resume = true;
                $cursor = (int)($state['cursor'] ?? 0);
                $total = (int)($state['total'] ?? 0);
                $processed = (int)($state['processed'] ?? 0);
                $inserted = (int)($state['inserted'] ?? 0);
                $updatedCount = (int)($state['updated'] ?? 0);
                $windowStart = $state['window_start'] ?? null;
                $windowEnd = $state['window_end'] ?? null;
            }
        }

        if (!$resume && $mode === 'recent') {
            $years = max(1, min(10, (int)($cfg['recent_years'] ?? 3)));
            $startTs = time() - ($years * 365 * 86400);
            $endTs = min($startTs + (119 * 86400), time());
            $windowStart = gmdate('Y-m-d\TH:i:s\Z', $startTs);
            $windowEnd = gmdate('Y-m-d\TH:i:s\Z', $endTs);
        }

        $token = bin2hex(random_bytes(32));
        $baseUrl = $this->baseUrl();
        $pageSize = max(1, min(2000, (int)($cfg['nvd_page_size'] ?? CVE_NVD_PAGE_SIZE)));

        // Guardar el tamaño de página elegido para este job.
        setting_set('cve_job_page_size', (string)$pageSize);

        CveDatabase::query(
            "UPDATE cve_sync_state
             SET status = 'queued', mode = ?, phase = 'nvd', cursor = ?, total = ?,
                 processed = ?, inserted = ?, updated = ?, token = ?, base_url = ?,
                 message = ?, window_start = ?, window_end = ?, started_at = datetime('now'),
                 finished_at = NULL, updated_at = datetime('now')
             WHERE id = 1",
            [
                $mode,
                $cursor,
                $total,
                $processed,
                $inserted,
                $updatedCount,
                $token,
                $baseUrl,
                $resume ? 'Reanudando la descarga de NVD…' : 'Preparando la descarga de NVD…',
                $windowStart,
                $windowEnd,
            ]
        );

        $workerStarted = false;
        if ($baseUrl !== '') {
            $workerStarted = background_request(
                rtrim($baseUrl, '/') . '/cve-worker.php?token=' . rawurlencode($token)
            );
        }
        if (!$workerStarted) {
            CveDatabase::query(
                "UPDATE cve_sync_state
                 SET message = ?, updated_at = datetime('now')
                 WHERE id = 1 AND token = ?",
                ['No se pudo lanzar el worker en segundo plano; pulsa «Continuar» para procesar tramos.', $token]
            );
        }

        return [
            'success'        => true,
            'state'          => $this->publicState($this->state()),
            'worker_started' => $workerStarted,
            'message'        => $workerStarted
                ? 'Sincronización iniciada en segundo plano.'
                : 'No se pudo lanzar el worker. Usa «Continuar» para procesar tramos manualmente.',
        ];
    }

    public function cancel(): array
    {
        CveDatabase::query(
            "UPDATE cve_sync_state
             SET status = 'cancelled', token = '', message = 'Cancelado por el usuario.',
                 finished_at = datetime('now'), updated_at = datetime('now')
             WHERE id = 1 AND status IN ('queued', 'running')"
        );
        return ['success' => true, 'state' => $this->publicState($this->state())];
    }

    /**
     * Procesa un tramo del job. Devuelve done/token/base_url para el worker.
     */
    public function runChunk(string $token): array
    {
        $state = $this->state();
        if (!$state || !hash_equals((string)($state['token'] ?? ''), $token)) {
            return ['done' => true, 'error' => 'Token de sincronización inválido.'];
        }
        if (in_array((string)$state['status'], ['cancelled', 'error'], true)) {
            return ['done' => true, 'state' => $state];
        }
        if ((string)$state['status'] === 'idle' && (string)$state['phase'] === 'done') {
            return ['done' => true, 'state' => $state];
        }

        CveDatabase::query(
            "UPDATE cve_sync_state
             SET status = 'running', started_at = COALESCE(started_at, datetime('now')),
                 updated_at = datetime('now')
             WHERE id = 1 AND token = ?",
            [$token]
        );

        $state = $this->state();
        if (!$state || !hash_equals((string)($state['token'] ?? ''), $token)) {
            return ['done' => true, 'error' => 'La sincronización fue reemplazada por otra ejecución.'];
        }

        $cfg = CveClient::config();
        $pageSize = max(1, min(2000, (int)($cfg['nvd_page_size'] ?? CVE_NVD_PAGE_SIZE)));
        $this->minCvss = max(0.0, min(10.0, (float)($cfg['min_cvss'] ?? 0)));
        $jobPageSize = (int)(setting_get('cve_job_page_size', (string)$pageSize));
        if ($jobPageSize >= 1 && $jobPageSize <= 2000) {
            $pageSize = $jobPageSize;
        }

        $this->watchlistMap = $this->watchlistCpeMap();
        if (empty($this->watchlistMap)) {
            // No hay inventario con CPE: no puede haber matches vigentes.
            if ((string)$state['status'] === 'running' && (int)$state['processed'] === 0) {
                $fresh = $this->state();
                if ($fresh && hash_equals((string)($fresh['token'] ?? ''), $token)) {
                    CveDatabase::query("DELETE FROM cve_watchlist_match");
                }
            }
        }

        $deadline = microtime(true) + (float)CVE_SYNC_BUDGET;
        $delay = $this->client()->hasApiKey() ? 0.6 : 6.0;

        try {
            while (microtime(true) < $deadline) {
                $state = $this->state();
                if (!$state) {
                    return ['done' => true, 'error' => 'Estado de sincronización no disponible.'];
                }
                if (!hash_equals((string)($state['token'] ?? ''), $token)) {
                    return ['done' => true, 'error' => 'La sincronización fue reemplazada por otra ejecución.'];
                }
                if ((string)$state['status'] === 'cancelled') {
                    return ['done' => true, 'state' => $state];
                }
                if ((string)$state['phase'] === 'done') {
                    $this->finish((int)$state['processed'], $token);
                    return ['done' => true, 'state' => $this->state()];
                }

                if (microtime(true) + $delay >= $deadline) {
                    break;
                }
                usleep((int)($delay * 1000000));

                $pubStart = ($state['mode'] === 'recent') ? ($state['window_start'] ?? null) : null;
                $pubEnd = ($state['mode'] === 'recent') ? ($state['window_end'] ?? null) : null;

                $page = $this->client()->nvdPage(
                    (int)$state['cursor'],
                    $pageSize,
                    $pubStart !== null ? (string)$pubStart : null,
                    $pubEnd !== null ? (string)$pubEnd : null
                );

                $vulns = $page['vulnerabilities'];
                $pageCount = count($vulns);

                $pageStats = CveDatabase::transaction(function (PDO $db) use ($vulns): array {
                    return $this->processPage($db, $vulns);
                });

                $cursor = (int)$state['cursor'] + $pageCount;
                $total = (int)$page['total'];
                $processed = (int)$state['processed'] + $pageCount;
                $inserted = (int)$state['inserted'] + (int)$pageStats['inserted'];
                $updated = (int)$state['updated'] + (int)$pageStats['updated'];
                $phase = (string)$state['phase'];
                $windowStart = $state['window_start'] ?? null;
                $windowEnd = $state['window_end'] ?? null;
                $done = false;

                if ($pageCount === 0 || ($total > 0 && $cursor >= $total) || ($total === 0 && $pageCount === 0)) {
                    if ((string)$state['mode'] === 'recent') {
                        $next = $this->nextWindow($windowEnd !== null ? (string)$windowEnd : null);
                        if ($next !== null) {
                            $windowStart = $next['start'];
                            $windowEnd = $next['end'];
                            $cursor = 0;
                            $total = 0;
                        } else {
                            $phase = 'done';
                            $done = true;
                        }
                    } else {
                        $phase = 'done';
                        $done = true;
                    }
                }

                $message = $state['mode'] === 'recent'
                    ? sprintf('NVD (ventana %s → %s): %s CVEs procesados', (string)$windowStart, (string)$windowEnd, number_format($processed))
                    : sprintf('NVD: %s CVEs procesados', number_format($processed));

                $this->updateState([
                    'phase'        => $phase,
                    'cursor'       => $cursor,
                    'total'        => $total,
                    'processed'    => $processed,
                    'inserted'     => $inserted,
                    'updated'      => $updated,
                    'window_start' => $windowStart,
                    'window_end'   => $windowEnd,
                    'message'      => $message,
                ], $token);

                if ($done) {
                    $this->finish($processed, $token);
                    return ['done' => true, 'state' => $this->state()];
                }
            }

            $state = $this->state();
            return [
                'done'      => false,
                'state'     => $state,
                'token'     => $token,
                'base_url'  => (string)($state['base_url'] ?? ''),
            ];
        } catch (Throwable $e) {
            $message = substr($e->getMessage(), 0, 1000);
            CveDatabase::query(
                "UPDATE cve_sync_state
                 SET status = 'error', message = ?, finished_at = datetime('now'), updated_at = datetime('now')
                 WHERE id = 1 AND token = ?",
                [$message, $token]
            );
            return ['done' => true, 'error' => $message, 'state' => $this->state()];
        }
    }

    // ============================================================
    // Procesamiento de una página
    // ============================================================

    private function processPage(PDO $db, array $vulns): array
    {
        $stmts = $this->prepareStatements($db);
        $inserted = 0;
        $updated = 0;
        $skipped = 0;

        foreach ($vulns as $v) {
            $cve = $v['cve'] ?? null;
            if (!is_array($cve)) {
                $skipped++;
                continue;
            }
            $result = $this->upsertCve($db, $cve, $stmts);
            if ($result === 'inserted') {
                $inserted++;
            } elseif ($result === 'updated') {
                $updated++;
            } else {
                $skipped++;
            }
        }

        return ['inserted' => $inserted, 'updated' => $updated, 'skipped' => $skipped];
    }

    private function prepareStatements(PDO $db): array
    {
        return [
            'exists' => $db->prepare("SELECT 1 FROM cve_catalog WHERE cve_id = ?"),
            'upsert' => $db->prepare(
                "INSERT INTO cve_catalog
                 (cve_id, description, description_lang, published_at, last_modified_at, vuln_status,
                  source_identifier, severity, cvss_v3_score, cvss_v3_vector, cvss_v2_score,
                  cwe_ids, references_json, products_json, nvd_url, fetched_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                 ON CONFLICT(cve_id) DO UPDATE SET
                    description = excluded.description,
                    description_lang = excluded.description_lang,
                    published_at = excluded.published_at,
                    last_modified_at = excluded.last_modified_at,
                    vuln_status = excluded.vuln_status,
                    source_identifier = excluded.source_identifier,
                    severity = excluded.severity,
                    cvss_v3_score = excluded.cvss_v3_score,
                    cvss_v3_vector = excluded.cvss_v3_vector,
                    cvss_v2_score = excluded.cvss_v2_score,
                    cwe_ids = excluded.cwe_ids,
                    references_json = excluded.references_json,
                    products_json = excluded.products_json,
                    nvd_url = excluded.nvd_url,
                    fetched_at = datetime('now'),
                    updated_at = datetime('now')"
            ),
            'del_products' => $db->prepare("DELETE FROM cve_product WHERE cve_id = ?"),
            'ins_product'  => $db->prepare("INSERT OR IGNORE INTO cve_product (cve_id, vendor, product) VALUES (?, ?, ?)"),
            'sel_matches'  => $db->prepare("SELECT watchlist_id FROM cve_watchlist_match WHERE cve_id = ?"),
            'del_match'    => $db->prepare("DELETE FROM cve_watchlist_match WHERE cve_id = ? AND watchlist_id = ?"),
            'upsert_match' => $db->prepare(
                "INSERT INTO cve_watchlist_match
                 (watchlist_id, cve_id, matched_cpe, matched_by, version_match, affected_versions, first_seen_at, last_seen_at)
                 VALUES (?, ?, ?, 'cpe', ?, ?, datetime('now'), datetime('now'))
                 ON CONFLICT(watchlist_id, cve_id) DO UPDATE SET
                    matched_cpe = excluded.matched_cpe,
                    matched_by = excluded.matched_by,
                    version_match = excluded.version_match,
                    affected_versions = excluded.affected_versions,
                    last_seen_at = datetime('now')"
            ),
        ];
    }

    private function upsertCve(PDO $db, array $cve, array $stmts): string
    {
        $parsed = $this->parseCve($cve);
        if ($parsed === null) {
            return 'skipped';
        }
        if ($this->minCvss > 0) {
            $score = $parsed['cvss_v3_score'] ?? $parsed['cvss_v2_score'];
            if ($score !== null && (float)$score < $this->minCvss) {
                return 'skipped';
            }
        }

        $id = $parsed['cve_id'];
        $stmts['exists']->execute([$id]);
        $isUpdate = $stmts['exists']->fetchColumn() !== false;
        $stmts['exists']->closeCursor();

        $stmts['upsert']->execute([
            $id,
            $parsed['description'],
            $parsed['description_lang'],
            $parsed['published_at'],
            $parsed['last_modified_at'],
            $parsed['vuln_status'],
            $parsed['source_identifier'],
            $parsed['severity'],
            $parsed['cvss_v3_score'],
            $parsed['cvss_v3_vector'],
            $parsed['cvss_v2_score'],
            $parsed['cwe_ids'],
            $parsed['references_json'],
            $parsed['products_json'],
            $parsed['nvd_url'],
        ]);

        $stmts['del_products']->execute([$id]);
        foreach ($parsed['products'] as $product) {
            $stmts['ins_product']->execute([$id, $product['vendor'], $product['product']]);
        }

        if (!empty($this->watchlistMap)) {
            $this->matchWatchlist($id, $parsed['cpe_matches'], $stmts);
        }

        return $isUpdate ? 'updated' : 'inserted';
    }

    private function parseCve(array $cve): ?array
    {
        $id = strtoupper(trim((string)($cve['id'] ?? '')));
        if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $id)) {
            return null;
        }
        if (strtolower((string)($cve['vulnStatus'] ?? '')) === 'rejected') {
            return null;
        }

        $description = '';
        $descriptionLang = 'en';
        foreach (($cve['descriptions'] ?? []) as $desc) {
            if (is_array($desc) && ($desc['lang'] ?? '') === 'es') {
                $description = (string)($desc['value'] ?? '');
                $descriptionLang = 'es';
                break;
            }
        }
        if ($description === '') {
            foreach (($cve['descriptions'] ?? []) as $desc) {
                if (is_array($desc) && ($desc['lang'] ?? '') === 'en') {
                    $description = (string)($desc['value'] ?? '');
                    $descriptionLang = 'en';
                    break;
                }
            }
        }

        $metrics = is_array($cve['metrics'] ?? null) ? $cve['metrics'] : [];
        $v31 = $this->pickMetric($metrics['cvssMetricV31'] ?? []);
        $v30 = $this->pickMetric($metrics['cvssMetricV30'] ?? []);
        $v2  = $this->pickMetric($metrics['cvssMetricV2'] ?? []);
        $v3 = $v31 ?? $v30;

        $cvssV3Score = null;
        $cvssV3Vector = null;
        $cvssV2Score = null;
        $severity = '';

        if ($v3 !== null) {
            $data = is_array($v3['cvssData'] ?? null) ? $v3['cvssData'] : [];
            $cvssV3Score = isset($data['baseScore']) ? (float)$data['baseScore'] : null;
            $cvssV3Vector = isset($data['vectorString']) ? (string)$data['vectorString'] : null;
            $severity = (string)($data['baseSeverity'] ?? $v3['baseSeverity'] ?? '');
        }
        if ($v2 !== null) {
            $data2 = is_array($v2['cvssData'] ?? null) ? $v2['cvssData'] : [];
            $cvssV2Score = isset($data2['baseScore']) ? (float)$data2['baseScore'] : null;
            if ($severity === '') {
                $severity = (string)($data2['baseSeverity'] ?? $v2['baseSeverity'] ?? '');
            }
        }

        $severity = $severity !== '' ? ucfirst(strtolower($severity)) : null;
        $scoreForSeverity = $cvssV3Score ?? $cvssV2Score;
        if ($severity === null && $scoreForSeverity !== null) {
            $severity = $scoreForSeverity >= 9.0 ? 'Critical' : ($scoreForSeverity >= 7.0 ? 'High' : ($scoreForSeverity >= 4.0 ? 'Medium' : 'Low'));
        }

        $cwes = [];
        foreach (($cve['weaknesses'] ?? []) as $weakness) {
            foreach (($weakness['description'] ?? []) as $desc) {
                $value = (string)($desc['value'] ?? '');
                if (preg_match('/^CWE-\d+$/', $value)) {
                    $cwes[$value] = true;
                }
            }
        }

        $references = [];
        foreach (($cve['references'] ?? []) as $ref) {
            $url = trim((string)($ref['url'] ?? ''));
            if ($url !== '' && filter_var($url, FILTER_VALIDATE_URL)) {
                $references[$url] = true;
                if (count($references) >= 5) {
                    break;
                }
            }
        }

        $cpeMatches = [];
        foreach (($cve['configurations'] ?? []) as $config) {
            foreach (($config['nodes'] ?? []) as $node) {
                if (is_array($node)) {
                    $this->collectCpeMatches($node, $cpeMatches);
                }
            }
        }
        $cpeMatches = array_values(array_filter(
            $cpeMatches,
            static fn(array $match): bool => !empty($match['vulnerable'])
        ));
        $cpeMatches = array_slice($cpeMatches, 0, 200);

        $products = [];
        foreach ($cpeMatches as $match) {
            $parsedCpe = $this->parseCpe((string)($match['criteria'] ?? ''));
            if ($parsedCpe === null) {
                continue;
            }
            $key = $parsedCpe['vendor'] . ':' . $parsedCpe['product'];
            $products[$key] = ['vendor' => $parsedCpe['vendor'], 'product' => $parsedCpe['product']];
        }

        return [
            'cve_id'            => $id,
            'description'       => $description,
            'description_lang'  => $descriptionLang,
            'published_at'      => isset($cve['published']) ? (string)$cve['published'] : null,
            'last_modified_at'  => isset($cve['lastModified']) ? (string)$cve['lastModified'] : null,
            'vuln_status'       => isset($cve['vulnStatus']) ? (string)$cve['vulnStatus'] : null,
            'source_identifier' => isset($cve['sourceIdentifier']) ? (string)$cve['sourceIdentifier'] : null,
            'severity'          => $severity,
            'cvss_v3_score'     => $cvssV3Score,
            'cvss_v3_vector'    => $cvssV3Vector,
            'cvss_v2_score'     => $cvssV2Score,
            'cwe_ids'           => json_encode(array_keys($cwes), JSON_UNESCAPED_SLASHES),
            'references_json'   => json_encode(array_keys($references), JSON_UNESCAPED_SLASHES),
            'products_json'     => json_encode(array_values($products), JSON_UNESCAPED_SLASHES),
            'nvd_url'           => 'https://nvd.nist.gov/vuln/detail/' . $id,
            'cpe_matches'       => $cpeMatches,
            'products'          => array_values($products),
        ];
    }

    private function pickMetric(array $metrics): ?array
    {
        if (empty($metrics)) {
            return null;
        }
        foreach ($metrics as $metric) {
            if (is_array($metric) && ($metric['type'] ?? '') === 'Primary') {
                return $metric;
            }
        }
        return is_array($metrics[0] ?? null) ? $metrics[0] : null;
    }

    private function collectCpeMatches(array $node, array &$out, int $depth = 0): void
    {
        if ($depth > 10 || count($out) >= 200) {
            return;
        }
        foreach (($node['cpeMatch'] ?? []) as $match) {
            if (is_array($match)) {
                $out[] = $match;
            }
        }
        foreach (($node['children'] ?? []) as $child) {
            if (is_array($child)) {
                $this->collectCpeMatches($child, $out, $depth + 1);
            }
        }
    }

    // ============================================================
    // Matching contra el inventario
    // ============================================================

    private function watchlistCpeMap(): array
    {
        $rows = CveDatabase::fetchAll(
            "SELECT w.id, w.name, w.version, c.cpe_name
             FROM software_watchlist w
             JOIN software_cpe c ON c.watchlist_id = w.id
             WHERE w.is_active = 1"
        );

        $map = [];
        foreach ($rows as $row) {
            $cpe = $this->parseCpe((string)($row['cpe_name'] ?? ''));
            if ($cpe === null) {
                continue;
            }
            $key = $cpe['vendor'] . ':' . $cpe['product'];
            $map[$key][] = [
                'watchlist_id' => (int)$row['id'],
                'name'         => (string)$row['name'],
                'version'      => (string)($row['version'] ?? ''),
                'cpe'          => (string)$row['cpe_name'],
            ];
        }
        return $map;
    }

    private function matchWatchlist(string $cveId, array $cpeMatches, array $stmts): int
    {
        if (empty($this->watchlistMap) || empty($cpeMatches)) {
            return 0;
        }

        $byWatchlist = [];
        $priority = ['unknown' => 0, 'all' => 1, 'range' => 2, 'exact' => 3];

        foreach ($cpeMatches as $match) {
            $parsed = $this->parseCpe((string)($match['criteria'] ?? ''));
            if ($parsed === null) {
                continue;
            }
            $key = $parsed['vendor'] . ':' . $parsed['product'];
            if (!isset($this->watchlistMap[$key])) {
                continue;
            }
            foreach ($this->watchlistMap[$key] as $watch) {
                $versionMatch = $this->versionMatch($watch['version'], $match, $parsed);
                if ($versionMatch === false) {
                    continue;
                }
                $wid = (int)$watch['watchlist_id'];
                if (!isset($byWatchlist[$wid])) {
                    $byWatchlist[$wid] = [
                        'version_match' => $versionMatch,
                        'matched_cpe'   => (string)($match['criteria'] ?? ''),
                        'affected'      => [],
                    ];
                } elseif (($priority[$versionMatch] ?? 0) > ($priority[$byWatchlist[$wid]['version_match']] ?? 0)) {
                    $byWatchlist[$wid]['version_match'] = $versionMatch;
                }
                $criteria = (string)($match['criteria'] ?? '');
                if ($criteria !== '') {
                    $byWatchlist[$wid]['affected'][$criteria] = true;
                }
            }
        }

        if (empty($byWatchlist)) {
            // No borramos matches antiguos aquí: la reconciliación completa
            // se hace en la Fase 3. En una carga inicial no hay stale.
            return 0;
        }

        $stmts['sel_matches']->execute([$cveId]);
        $existing = array_map('intval', $stmts['sel_matches']->fetchAll(PDO::FETCH_COLUMN));
        $stmts['sel_matches']->closeCursor();

        foreach ($existing as $watchedId) {
            if (!isset($byWatchlist[$watchedId])) {
                $stmts['del_match']->execute([$cveId, $watchedId]);
            }
        }

        foreach ($byWatchlist as $watchedId => $data) {
            $affected = array_slice(array_keys($data['affected']), 0, 20);
            $stmts['upsert_match']->execute([
                $watchedId,
                $cveId,
                $data['matched_cpe'],
                $data['version_match'],
                json_encode($affected, JSON_UNESCAPED_SLASHES),
            ]);
        }

        return count($byWatchlist);
    }

    private function versionMatch(string $watchVersion, array $match, array $parsed): string|false
    {
        if ($watchVersion === '') {
            return 'all';
        }

        $cpeVersion = (string)($parsed['version'] ?? '*');
        if ($cpeVersion !== '' && $cpeVersion !== '*' && $cpeVersion !== '-') {
            return version_compare($watchVersion, $cpeVersion, '==') ? 'exact' : false;
        }

        $startInc = $match['versionStartIncluding'] ?? null;
        $startExc = $match['versionStartExcluding'] ?? null;
        $endInc   = $match['versionEndIncluding'] ?? null;
        $endExc   = $match['versionEndExcluding'] ?? null;

        if ($startInc !== null || $startExc !== null || $endInc !== null || $endExc !== null) {
            if ($startInc !== null && version_compare($watchVersion, (string)$startInc, '<')) {
                return false;
            }
            if ($startExc !== null && version_compare($watchVersion, (string)$startExc, '<=')) {
                return false;
            }
            if ($endInc !== null && version_compare($watchVersion, (string)$endInc, '>')) {
                return false;
            }
            if ($endExc !== null && version_compare($watchVersion, (string)$endExc, '>=')) {
                return false;
            }
            return 'range';
        }

        return 'all';
    }

    private function parseCpe(string $cpe): ?array
    {
        $cpe = trim($cpe);
        if (!str_starts_with($cpe, 'cpe:2.3:')) {
            return null;
        }
        $parts = explode(':', $cpe);
        if (count($parts) < 5) {
            return null;
        }
        $part = strtolower($parts[2]);
        if (!in_array($part, ['a', 'o'], true)) {
            return null;
        }
        $vendor = strtolower($parts[3]);
        $product = strtolower($parts[4]);
        if ($vendor === '' || $product === '' || $vendor === '*' || $product === '*' || $vendor === '-' || $product === '-') {
            return null;
        }
        return [
            'part'    => $part,
            'vendor'  => $vendor,
            'product' => $product,
            'version' => $parts[5] ?? '*',
        ];
    }

    // ============================================================
    // Estado auxiliar
    // ============================================================

    private function nextWindow(?string $currentEnd): ?array
    {
        if ($currentEnd === null || $currentEnd === '') {
            return null;
        }
        $end = strtotime($currentEnd);
        if ($end === false) {
            return null;
        }
        $now = time();
        if ($end >= $now) {
            return null;
        }
        $nextStart = $end;
        $nextEnd = min($nextStart + (119 * 86400), $now);
        if ($nextEnd <= $nextStart) {
            return null;
        }
        return [
            'start' => gmdate('Y-m-d\TH:i:s\Z', $nextStart),
            'end'   => gmdate('Y-m-d\TH:i:s\Z', $nextEnd),
        ];
    }

    private function finish(int $processed, ?string $token = null): void
    {
        $sql = "UPDATE cve_sync_state
             SET status = 'idle', phase = 'done', token = '', base_url = '',
                 message = ?, finished_at = datetime('now'), last_success_at = datetime('now'),
                 updated_at = datetime('now')
             WHERE id = 1";
        $params = [sprintf('Catálogo actualizado: %s CVEs procesados.', number_format($processed))];
        if ($token !== null) {
            $sql .= " AND token = ?";
            $params[] = $token;
        }
        CveDatabase::query($sql, $params);
    }

    private function updateState(array $fields, ?string $token = null): void
    {
        $allowed = [
            'status', 'phase', 'cursor', 'total', 'processed', 'inserted', 'updated',
            'window_start', 'window_end', 'message', 'started_at', 'finished_at', 'last_success_at',
        ];
        $sets = [];
        $params = [];
        foreach ($fields as $key => $value) {
            if (!in_array($key, $allowed, true)) {
                continue;
            }
            $sets[] = $key . ' = ?';
            $params[] = $value;
        }
        if (empty($sets)) {
            return;
        }
        $sets[] = "updated_at = datetime('now')";
        $sql = "UPDATE cve_sync_state SET " . implode(', ', $sets) . " WHERE id = 1";
        if ($token !== null) {
            $sql .= " AND token = ?";
            $params[] = $token;
        }
        CveDatabase::query($sql, $params);
    }

    private function dbTime(?string $value): int
    {
        if ($value === null || $value === '') {
            return 0;
        }
        $ts = str_contains($value, 'T') || str_ends_with($value, 'Z')
            ? strtotime($value)
            : strtotime($value . ' UTC');
        return $ts === false ? 0 : $ts;
    }

    private function baseUrl(): string
    {
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https');

        $base = rtrim(base_url(''), '/');
        if (preg_match('#^https?://#i', $base)) {
            // Si la petición actual es HTTPS pero APP_URL está en HTTP, el
            // worker debe llamarse por HTTPS para no recibir un 301.
            if ($isHttps && str_starts_with(strtolower($base), 'http://')) {
                $base = 'https://' . substr($base, 7);
            }
            return $base;
        }

        $scheme = $isHttps ? 'https' : 'http';
        $host = (string)($_SERVER['HTTP_HOST'] ?? '');
        return $host !== '' ? $scheme . '://' . $host : '';
    }
}
