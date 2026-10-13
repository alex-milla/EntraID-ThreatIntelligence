<?php
/**
 * Módulo: Threat Intelligence
 * Extrae informes TI, IOCs, CVEs e intel profiles desde Graph.
 * Permiso requerido: ThreatIntelligence.Read.All
 */

declare(strict_types=1);

class Module_ThreatIntelligence extends BaseModule
{
    public function key(): string { return 'threat_intelligence'; }
    public function name(): string { return 'Threat Intelligence'; }
    public function description(): string { return 'Informes TI, IOCs, CVEs e intel profiles'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return ['ThreatIntelligence.Read.All'];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Threat Intel',
            'url'   => base_url('modules/threat_intelligence'),
            'icon'  => 'file-text',
            'group' => 'Inteligencia',
        ];
    }

    // ============================================================
    // Sincronización
    // ============================================================

    public function sync(int $tenantId): array
    {
        $client = $this->getGraphClient($tenantId);
        $recordCount = 0;
        $errors = [];

        try {
            // 1. Artículos recientes (hasta 90 días: lo que expone la API)
            $recent = $this->fetchRecentArticles($client);

            foreach ($recent as $article) {
                try {
                    // 2. Obtener artículo completo
                    $full = $client->graphGet('security/threatIntelligence/articles/' . $article['id']);

                    // 3. Guardar artículo
                    Database::query(
                        "INSERT OR REPLACE INTO ti_articles
                         (tenant_id, article_id, title, created_date, last_updated, summary, body, tags, is_featured, fetched_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                        [
                            $tenantId,
                            $article['id'],
                            $full['title'] ?? $article['title'],
                            $full['createdDateTime'] ?? null,
                            $full['lastUpdatedDateTime'] ?? null,
                            $full['summary']['content'] ?? null,
                            $full['body']['content'] ?? null,
                            json_encode($full['tags'] ?? []),
                            !empty($full['isFeatured']) ? 1 : 0,
                        ]
                    );
                    $recordCount++;

                    // 4. Obtener y guardar IOCs del artículo
                    $iocCount = $this->syncArticleIocs($client, $tenantId, $article['id']);
                    $recordCount += $iocCount;

                } catch (Throwable $e) {
                    $errors[] = "Artículo {$article['id']}: " . $e->getMessage();
                }
            }

            // 2.b) Intel profiles (threat actors y tools)
            $recordCount += $this->syncIntelProfiles($client, $tenantId);

            $this->logSync($tenantId, 'full', empty($errors) ? 'success' : 'partial', $recordCount, implode('; ', $errors) ?: null);

            return [
                'success' => empty($errors),
                'records' => $recordCount,
                'errors'  => $errors,
            ];

        } catch (Throwable $e) {
            $this->logSync($tenantId, 'full', 'error', $recordCount, $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Sincroniza los IOCs de un artículo específico.
     */
    private function syncArticleIocs(GraphClient $client, int $tenantId, string $articleId): int
    {
        try {
            $iocs = $client->graphGet("security/threatIntelligence/articles/{$articleId}/indicators");
            $articleDbId = Database::fetchOne(
                "SELECT id FROM ti_articles WHERE tenant_id = ? AND article_id = ?",
                [$tenantId, $articleId]
            )['id'] ?? null;

            $count = 0;
            foreach ($iocs['value'] ?? [] as $ioc) {
                $artifact = $ioc['artifact'] ?? [];
                $value    = $this->extractIocValue($artifact);
                $iocType  = $this->mapIocType($artifact, $value);

                Database::query(
                    "INSERT OR REPLACE INTO ti_iocs
                     (tenant_id, article_id, ioc_id, ioc_type, ioc_value, source, description, severity, first_seen, last_seen, fetched_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                    [
                        $tenantId,
                        $articleDbId,
                        $ioc['id'],
                        $iocType,
                        $value,
                        $ioc['source'] ?? null,
                        $ioc['description'] ?? null,
                        $ioc['severity'] ?? null,
                        $ioc['firstSeenDateTime'] ?? null,
                        $ioc['lastSeenDateTime'] ?? null,
                    ]
                );
                $count++;
            }
            return $count;

        } catch (Throwable $e) {
            // Artículo sin IOCs o error: no es crítico
            return 0;
        }
    }

    /**
     * Extrae el valor del IOC desde el artefacto (robusto ante distintas formas
     * de la estructura que devuelve Microsoft Graph).
     */
    private function extractIocValue(array $artifact): string
    {
        // 1) Claves conocidas (escalares)
        $knownKeys = ['ipV4Address', 'ipAddress', 'ipv6Address', 'domainName', 'domain', 'hostname',
                      'url', 'emailAddress', 'registryKey', 'macAddress', 'value'];
        foreach ($knownKeys as $k) {
            if (isset($artifact[$k]) && is_scalar($artifact[$k]) && (string)$artifact[$k] !== '') {
                return (string)$artifact[$k];
            }
        }
        // 2) Objetos típicos (fileHash / userAccount)
        foreach (['fileHash', 'userAccount'] as $k) {
            if (isset($artifact[$k])) {
                $v = $artifact[$k];
                if (is_array($v)) {
                    foreach (['value', 'hashValue', 'sha256', 'sha1', 'md5', 'name'] as $kk) {
                        if (isset($v[$kk]) && is_scalar($v[$kk]) && (string)$v[$kk] !== '') {
                            return (string)$v[$kk];
                        }
                    }
                    $first = reset($v);
                    if (is_scalar($first) && (string)$first !== '') {
                        return (string)$first;
                    }
                } elseif (is_scalar($v) && (string)$v !== '') {
                    return (string)$v;
                }
            }
        }
        // 3) Recursivo: primera hoja escalar (ignorando @odata.type)
        return $this->firstScalar($artifact) ?? 'unknown';
    }

    private function firstScalar(array $arr): ?string
    {
        foreach ($arr as $k => $v) {
            if ($k === '@odata.type') {
                continue;
            }
            if (is_scalar($v) && (string)$v !== '') {
                return (string)$v;
            }
            if (is_array($v)) {
                $r = $this->firstScalar($v);
                if ($r !== null) {
                    return $r;
                }
            }
        }
        return null;
    }

    /**
     * Mapea el artefacto a un tipo STIX-like. Usa @odata.type, claves conocidas
     * y, como último recurso, el propio valor.
     */
    private function mapIocType(array $artifact, string $value = ''): string
    {
        // 1) @odata.type
        $odata = strtolower((string)($artifact['@odata.type'] ?? ''));
        $odataMap = [
            'ipv4address' => 'ipv4-addr', 'ipaddress' => 'ipv4-addr', 'ipv6address' => 'ipv6-addr',
            'hostname' => 'domain-name', 'domainname' => 'domain-name', 'domain' => 'domain-name',
            'urlinfo' => 'url', 'url' => 'url',
            'filehash' => 'file', 'file' => 'file',
            'emailaddress' => 'email-addr', 'email' => 'email-addr',
            'useraccount' => 'user-account', 'registrykey' => 'windows-registry-key', 'macaddress' => 'mac-addr',
        ];
        foreach ($odataMap as $needle => $type) {
            if ($odata !== '' && str_contains($odata, $needle)) {
                return $type;
            }
        }

        // 2) Claves conocidas
        $keyMap = [
            'ipV4Address' => 'ipv4-addr', 'ipAddress' => 'ipv4-addr', 'ipv6Address' => 'ipv6-addr',
            'domainName' => 'domain-name', 'domain' => 'domain-name', 'hostname' => 'domain-name',
            'url' => 'url', 'fileHash' => 'file', 'emailAddress' => 'email-addr',
            'userAccount' => 'user-account', 'registryKey' => 'windows-registry-key', 'macAddress' => 'mac-addr',
        ];
        foreach ($keyMap as $k => $type) {
            if (isset($artifact[$k])) {
                return $type;
            }
        }

        // 3) Por el valor
        return $this->classifyByValue($value);
    }

    private function classifyByValue(string $v): string
    {
        $v = trim($v);
        if ($v === '' || $v === 'unknown') {
            return 'unknown';
        }
        if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return 'ipv4-addr';
        }
        if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return 'ipv6-addr';
        }
        if (filter_var($v, FILTER_VALIDATE_EMAIL)) {
            return 'email-addr';
        }
        if (preg_match('#^https?://#i', $v)) {
            return 'url';
        }
        if (preg_match('/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i', $v)) {
            return 'file';
        }
        if (preg_match('/^([a-z0-9\-]+\.)+[a-z]{2,}$/i', $v)) {
            return 'domain-name';
        }
        return 'unknown';
    }

    // ============================================================
    // Consultas para la UI
    // ============================================================

    /**
     * Obtiene artículos de un tenant con paginación y filtro por fechas.
     */
    public function getArticles(int $tenantId, int $page = 1, int $perPage = 20, array $filters = []): array
    {
        $where = ['a.tenant_id = ?'];
        $params = [$tenantId];
        if (!empty($filters['from'])) {
            $where[] = "substr(COALESCE(a.last_updated, a.created_date), 1, 10) >= ?";
            $params[] = $filters['from'];
        }
        if (!empty($filters['to'])) {
            $where[] = "substr(COALESCE(a.last_updated, a.created_date), 1, 10) <= ?";
            $params[] = $filters['to'];
        }
        if (!empty($filters['q'])) {
            $like = '%' . $filters['q'] . '%';
            $where[] = "(a.title LIKE ? OR a.summary LIKE ? OR a.body LIKE ? OR a.tags LIKE ?)";
            array_push($params, $like, $like, $like, $like);
        }
        if (!empty($filters['tag'])) {
            $where[] = 'a.tags LIKE ?';
            $params[] = '%' . $filters['tag'] . '%';
        }
        if (!empty($filters['sector']) && isset(SECTORS[$filters['sector']])) {
            $or = [];
            foreach (SECTORS[$filters['sector']] as $kw) {
                $like = '%' . $kw . '%';
                $or[] = 'a.title LIKE ?';
                $params[] = $like;
                $or[] = 'a.summary LIKE ?';
                $params[] = $like;
                $or[] = 'a.body LIKE ?';
                $params[] = $like;
                $or[] = 'a.tags LIKE ?';
                $params[] = $like;
            }
            if (!empty($or)) {
                $where[] = '(' . implode(' OR ', $or) . ')';
            }
        }
        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM ti_articles a WHERE $whereClause",
            $params
        )['cnt'];

        $params[] = $perPage;
        $params[] = $offset;

        $articles = Database::fetchAll(
            "SELECT a.*, COUNT(i.id) as ioc_count
             FROM ti_articles a
             LEFT JOIN ti_iocs i ON a.id = i.article_id AND i.tenant_id = a.tenant_id
             WHERE $whereClause
             GROUP BY a.id
             ORDER BY a.last_updated DESC
             LIMIT ? OFFSET ?",
            $params
        );

        return [
            'data'      => $articles,
            'total'     => $total,
            'page'      => $page,
            'perPage'   => $perPage,
            'totalPages'=> (int)ceil($total / max(1, $perPage)),
        ];
    }

    /**
     * Etiquetas distintas de los artículos del tenant (tag => nº de artículos).
     */
    public function getArticleTags(int $tenantId, int $limit = 200): array
    {
        $rows = Database::fetchAll(
            "SELECT tags FROM ti_articles WHERE tenant_id = ? AND tags IS NOT NULL AND tags != ''",
            [$tenantId]
        );
        $set = [];
        foreach ($rows as $r) {
            $tags = safe_json_decode($r['tags'], []);
            if (!is_array($tags)) {
                continue;
            }
            foreach ($tags as $t) {
                $val = is_array($t) ? ($t['value'] ?? $t['name'] ?? '') : $t;
                $val = trim((string)$val);
                if ($val !== '') {
                    $set[$val] = ($set[$val] ?? 0) + 1;
                }
            }
        }
        arsort($set);
        return array_slice($set, 0, $limit, true);
    }

    /**
     * Rango de fechas por defecto: últimas 24 h (ayer → hoy).
     * Con inputs de solo fecha, "24 h" equivale a la jornada actual.
     */
    private function defaultDateRange(): array
    {
        $to = gmdate('Y-m-d');
        return ['from' => gmdate('Y-m-d', strtotime($to) - 86400), 'to' => $to];
    }

    /**
     * Rango de fechas activo (por defecto últimas 24 h; máximo 90 días).
     */
    private function resolveDateRange(): array
    {
        $def  = $this->defaultDateRange();
        $to   = $_GET['to'] ?? $def['to'];
        $from = $_GET['from'] ?? $def['from'];
        $min  = gmdate('Y-m-d', strtotime($to) - 90 * 86400);
        if ($from < $min) {
            $from = $min; // límite de 90 días
        }
        if ($from > $to) {
            $from = $to;
        }
        return ['from' => $from, 'to' => $to];
    }

    /**
     * Artículo anterior (más reciente) o siguiente (más antiguo) dentro del tenant y rango.
     */
    private function adjacentArticle(string $dir, array $article): ?int
    {
        $tenantId = (int)$article['tenant_id'];
        $key = $article['last_updated'] ?? $article['created_date'];
        $range = $this->resolveDateRange();

        $params = [$tenantId, $key];
        $rangeSql = '';
        $rangeSql .= " AND substr(COALESCE(last_updated, created_date), 1, 10) >= ?";
        $params[] = $range['from'];
        $rangeSql .= " AND substr(COALESCE(last_updated, created_date), 1, 10) <= ?";
        $params[] = $range['to'];

        $q = trim((string)($_GET['q'] ?? ''));
        if ($q !== '') {
            $like = '%' . $q . '%';
            $rangeSql .= " AND (title LIKE ? OR summary LIKE ? OR body LIKE ? OR tags LIKE ?)";
            array_push($params, $like, $like, $like, $like);
        }
        $tag = trim((string)($_GET['tag'] ?? ''));
        if ($tag !== '') {
            $rangeSql .= " AND tags LIKE ?";
            $params[] = '%' . $tag . '%';
        }
        $sector = trim((string)($_GET['sector'] ?? ''));
        if ($sector !== '' && isset(SECTORS[$sector])) {
            $or = [];
            foreach (SECTORS[$sector] as $kw) {
                $like = '%' . $kw . '%';
                $or[] = 'title LIKE ?';
                $params[] = $like;
                $or[] = 'summary LIKE ?';
                $params[] = $like;
                $or[] = 'body LIKE ?';
                $params[] = $like;
                $or[] = 'tags LIKE ?';
                $params[] = $like;
            }
            if (!empty($or)) {
                $rangeSql .= ' AND (' . implode(' OR ', $or) . ')';
            }
        }

        if ($dir === 'prev') {
            $row = Database::fetchOne(
                "SELECT id FROM ti_articles
                 WHERE tenant_id = ? AND COALESCE(last_updated, created_date) > ? $rangeSql
                 ORDER BY COALESCE(last_updated, created_date) ASC LIMIT 1",
                $params
            );
        } else {
            $row = Database::fetchOne(
                "SELECT id FROM ti_articles
                 WHERE tenant_id = ? AND COALESCE(last_updated, created_date) < ? $rangeSql
                 ORDER BY COALESCE(last_updated, created_date) DESC LIMIT 1",
                $params
            );
        }
        return $row ? (int)$row['id'] : null;
    }

    /**
     * Obtiene IOCs de un tenant con filtros.
     */
    public function getIocs(int $tenantId, array $filters = [], int $page = 1, int $perPage = 50): array
    {
        $where = ['tenant_id = ?'];
        $params = [$tenantId];

        if (!empty($filters['type'])) {
            $where[] = 'ioc_type = ?';
            $params[] = $filters['type'];
        }
        if (!empty($filters['search'])) {
            $where[] = 'ioc_value LIKE ?';
            $params[] = '%' . $filters['search'] . '%';
        }
        if (!empty($filters['from'])) {
            $where[] = 'date(COALESCE(last_seen, first_seen, fetched_at)) >= ?';
            $params[] = $filters['from'];
        }
        if (!empty($filters['to'])) {
            $where[] = 'date(COALESCE(last_seen, first_seen, fetched_at)) <= ?';
            $params[] = $filters['to'];
        }

        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $orderBy = (($filters['sort'] ?? '') === 'value')
            ? 'ioc_value ASC'
            : 'COALESCE(last_seen, first_seen, fetched_at) DESC';

        $total = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM ti_iocs WHERE $whereClause",
            $params
        )['cnt'];

        $params[] = $perPage;
        $params[] = $offset;

        $iocs = Database::fetchAll(
            "SELECT * FROM ti_iocs WHERE $whereClause ORDER BY $orderBy LIMIT ? OFFSET ?",
            $params
        );

        return [
            'data'      => $iocs,
            'total'     => $total,
            'page'      => $page,
            'perPage'   => $perPage,
            'totalPages'=> (int)ceil($total / $perPage),
        ];
    }

    /**
     * Obtiene estadísticas de IOCs por tipo.
     */
    public function getIocStats(int $tenantId): array
    {
        return Database::fetchAll(
            "SELECT ioc_type, COUNT(*) as cnt FROM ti_iocs WHERE tenant_id = ? GROUP BY ioc_type ORDER BY cnt DESC",
            [$tenantId]
        );
    }

    // ============================================================
    // Intel profiles (threat actors y tools)
    // ============================================================

    /**
     * Sincroniza los intel profiles (threat actors y tools) del tenant.
     */
    private function syncIntelProfiles(GraphClient $client, int $tenantId): int
    {
        try {
            $profiles = $client->graphGetAll('security/threatIntelligence/intelProfiles');
        } catch (Throwable $e) {
            return 0;
        }
        $count = 0;
        foreach ($profiles as $p) {
            if (empty($p['id'])) { continue; }
            try {
                Database::query(
                    "INSERT OR REPLACE INTO ti_intel_profiles
                     (tenant_id, profile_id, kind, title, summary, description, tradecraft, aliases, targets, countries, first_active, raw_data, fetched_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                    [
                        $tenantId,
                        $p['id'],
                        $p['kind'] ?? null,
                        $p['title'] ?? 'Sin título',
                        $p['summary']['content'] ?? null,
                        $p['description']['content'] ?? null,
                        $p['tradecraft']['content'] ?? null,
                        json_encode($p['aliases'] ?? []),
                        json_encode($p['targets'] ?? []),
                        json_encode($p['countriesOrRegionsOfOrigin'] ?? []),
                        $p['firstActiveDateTime'] ?? null,
                        json_encode($p),
                    ]
                );
                $count++;
            } catch (Throwable $e) { /* noop */ }
        }
        return $count;
    }

    /**
     * Cosecha los indicadores de cada intel profile (con topes prudentes).
     */
    public function syncProfileIndicators(GraphClient $client, int $tenantId, int $perProfile = 1000, int $totalCap = 50000): array
    {
        $profiles = Database::fetchAll("SELECT id, profile_id FROM ti_intel_profiles WHERE tenant_id = ?", [$tenantId]);
        $total = 0;
        $errors = 0;

        foreach ($profiles as $p) {
            if ($total >= $totalCap) { break; }
            try {
                $iocs = $client->graphGetAll("security/threatIntelligence/intelProfiles/{$p['profile_id']}/indicators");
            } catch (Throwable $e) { $errors++; continue; }

            $n = 0;
            foreach ($iocs as $ioc) {
                if ($n >= $perProfile || $total >= $totalCap) { break; }
                $artifact = $ioc['artifact'] ?? [];
                $value = $this->extractIocValue($artifact);
                $iocType = $this->mapIocType($artifact, $value);
                try {
                    Database::query(
                        "INSERT OR REPLACE INTO ti_iocs
                         (tenant_id, profile_id, article_id, ioc_id, ioc_type, ioc_value, source, description, severity, first_seen, last_seen, fetched_at)
                         VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                        [
                            $tenantId,
                            (int)$p['id'],
                            $ioc['id'] ?? md5($iocType . '|' . $value),
                            $iocType,
                            $value,
                            $ioc['source'] ?? null,
                            $ioc['description'] ?? null,
                            $ioc['severity'] ?? null,
                            $ioc['firstSeenDateTime'] ?? null,
                            $ioc['lastSeenDateTime'] ?? null,
                        ]
                    );
                    $n++;
                    $total++;
                } catch (Throwable $e) { /* noop */ }
            }
        }

        $this->logSync($tenantId, 'profile_indicators', $errors === 0 ? 'success' : 'partial', $total, $errors ? ($errors . ' perfiles con error') : null);
        return ['success' => true, 'profiles' => count($profiles), 'indicators' => $total, 'errors' => $errors];
    }

    /**
     * Lista de intel profiles con filtros.
     */
    public function getProfiles(int $tenantId, array $filters = [], int $page = 1, int $perPage = 50): array
    {
        $where = ['tenant_id = ?'];
        $params = [$tenantId];
        if (!empty($filters['kind'])) {
            $where[] = 'kind = ?';
            $params[] = $filters['kind'];
        }
        if (!empty($filters['search'])) {
            $where[] = '(title LIKE ? OR summary LIKE ?)';
            $params[] = '%' . $filters['search'] . '%';
            $params[] = '%' . $filters['search'] . '%';
        }
        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne("SELECT COUNT(*) as cnt FROM ti_intel_profiles WHERE $whereClause", $params)['cnt'];
        $params[] = $perPage;
        $params[] = $offset;
        $rows = Database::fetchAll("SELECT * FROM ti_intel_profiles WHERE $whereClause ORDER BY title LIMIT ? OFFSET ?", $params);

        return ['data' => $rows, 'total' => $total, 'page' => $page, 'perPage' => $perPage, 'totalPages' => (int)ceil($total / $perPage)];
    }

    /** Conteo de perfiles por tipo. */
    public function getProfileCounts(int $tenantId): array
    {
        $out = ['actor' => 0, 'tool' => 0, 'other' => 0, 'total' => 0];
        foreach (Database::fetchAll("SELECT kind, COUNT(*) cnt FROM ti_intel_profiles WHERE tenant_id = ? GROUP BY kind", [$tenantId]) as $r) {
            $k = strtolower((string)$r['kind']);
            if (isset($out[$k]) && $k !== 'total') { $out[$k] += (int)$r['cnt']; } else { $out['other'] += (int)$r['cnt']; }
            $out['total'] += (int)$r['cnt'];
        }
        return $out;
    }

    public function profilesPage(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $filters = [
            'kind'   => trim((string)($_GET['kind'] ?? '')),
            'search' => trim((string)($_GET['search'] ?? '')),
        ];
        $page = max(1, (int)($_GET['page'] ?? 1));
        $data = $selectedTenant ? $this->getProfiles($selectedTenant, $filters, $page, 50) : ['data' => [], 'total' => 0, 'page' => 1, 'perPage' => 50, 'totalPages' => 1];
        $counts = $selectedTenant ? $this->getProfileCounts($selectedTenant) : ['actor' => 0, 'tool' => 0, 'other' => 0, 'total' => 0];

        echo $this->page('profiles', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'filters'        => $filters,
            'profiles'       => $data,
            'counts'         => $counts,
        ]);
    }

    public function showProfilePage(array $params = []): void
    {
        $id = (int)($params['id'] ?? 0);
        $profile = Database::fetchOne("SELECT * FROM ti_intel_profiles WHERE id = ?", [$id]);
        if (!$profile) {
            http_response_code(404);
            require VIEWS_PATH . '/errors/404.php';
            return;
        }
        $indicators = Database::fetchAll("SELECT * FROM ti_iocs WHERE profile_id = ? ORDER BY ioc_type, ioc_value LIMIT 3000", [$id]);
        $tenant = TenantManager::getById((int)$profile['tenant_id']);

        $scope = in_array((string)($profile['kind'] ?? ''), ['actor', 'tool'], true) ? (string)$profile['kind'] : 'actor';

        echo $this->page('profile', [
            'module'     => $this,
            'profile'    => $profile,
            'indicators' => $indicators,
            'tenant'     => $tenant,
            'actions'           => llm_actions_list(true, $scope),
            'actionsEditorList' => llm_actions_list(false, $scope),
            'actionScope'       => $scope,
            'profiles'          => llm_profile_list(),
            'defaultProfileId'  => (llm_profile_default()['id'] ?? null),
        ]);
    }

    public function triggerSyncIndicators(array $params = []): void
    {
        Csrf::validateOrFail();
        $tenantId = (int)($params['tenantId'] ?? 0);
        $missing = $this->missingPermissions($tenantId);
        if (!empty($missing)) {
            json_response(['success' => false, 'skipped' => true, 'error' => 'El tenant no tiene los permisos: ' . implode(', ', $missing)]);
        }
        try {
            $client = $this->getGraphClient($tenantId);
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()]);
            return;
        }
        json_response($this->syncProfileIndicators($client, $tenantId));
    }

    // ============================================================
    // Sincronización por pasos (con progreso)
    // ============================================================

    /** Lista de artículos de TI de los últimos 90 días (con paginación). */
    private function fetchRecentArticles(GraphClient $client): array
    {
        $all = $client->graphGetAll('security/threatIntelligence/articles', [
            '$select' => 'id,title,createdDateTime,lastUpdatedDateTime',
        ]);
        $since = time() - (90 * 86400);
        return array_values(array_filter($all, function ($a) use ($since) {
            $date = $a['lastUpdatedDateTime'] ?? $a['createdDateTime'] ?? null;
            return $date && strtotime($date) >= $since;
        }));
    }

    /** Paso de artículos: procesa [cursor, cursor+batch) omitiendo los que no cambiaron. */
    public function syncStepArticles(GraphClient $client, int $tenantId, int $cursor, int $batch): array
    {
        $recent = $this->fetchRecentArticles($client);
        $total = count($recent);
        $end = min($cursor + $batch, $total);
        $added = 0;
        $skipped = 0;

        for ($k = $cursor; $k < $end; $k++) {
            $aid = (string)($recent[$k]['id'] ?? '');
            if ($aid === '') { continue; }
            $lastUpd = (string)($recent[$k]['lastUpdatedDateTime'] ?? '');

            $existing = Database::fetchOne("SELECT last_updated FROM ti_articles WHERE tenant_id = ? AND article_id = ?", [$tenantId, $aid]);
            if ($existing && (string)($existing['last_updated'] ?? '') === $lastUpd && $lastUpd !== '') {
                $skipped++;
                continue;
            }

            try {
                $full = $client->graphGet('security/threatIntelligence/articles/' . $aid);
                Database::query(
                    "INSERT OR REPLACE INTO ti_articles
                     (tenant_id, article_id, title, created_date, last_updated, summary, body, tags, is_featured, fetched_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                    [
                        $tenantId,
                        $aid,
                        $full['title'] ?? ($recent[$k]['title'] ?? 'Sin título'),
                        $full['createdDateTime'] ?? null,
                        $full['lastUpdatedDateTime'] ?? null,
                        $full['summary']['content'] ?? null,
                        $full['body']['content'] ?? null,
                        json_encode($full['tags'] ?? []),
                        !empty($full['isFeatured']) ? 1 : 0,
                    ]
                );
                $this->syncArticleIocs($client, $tenantId, $aid);
                $added++;
            } catch (Throwable $e) { /* skip */ }
        }

        return ['success' => true, 'phase' => 'articles', 'processed' => $end, 'total' => $total, 'cursor' => $end, 'done' => $end >= $total, 'added' => $added, 'skipped' => $skipped];
    }

    /** Paso de perfiles (threat actors / tools): upsert en una sola llamada. */
    public function syncStepProfiles(GraphClient $client, int $tenantId, int $cursor, int $batch): array
    {
        $count = $this->syncIntelProfiles($client, $tenantId);
        return ['success' => true, 'phase' => 'profiles', 'processed' => $count, 'total' => $count, 'cursor' => $count, 'done' => true, 'added' => $count, 'skipped' => 0];
    }

    /** Paso de indicadores por perfil: procesa [cursor, cursor+batch) omitiendo los recientes (<24 h). */
    public function syncStepProfileIndicators(GraphClient $client, int $tenantId, int $cursor, int $batch, int $perProfile = 1000): array
    {
        $profiles = Database::fetchAll("SELECT id, profile_id, indicators_synced_at FROM ti_intel_profiles WHERE tenant_id = ? ORDER BY id", [$tenantId]);
        $total = count($profiles);
        $end = min($cursor + $batch, $total);
        $added = 0;
        $skipped = 0;

        for ($k = $cursor; $k < $end; $k++) {
            $p = $profiles[$k];
            $synced = (string)($p['indicators_synced_at'] ?? '');
            if ($synced !== '' && ($ts = strtotime($synced)) !== false && (time() - $ts) < 86400) {
                $skipped++;
                continue;
            }

            try {
                $iocs = $client->graphGetAll("security/threatIntelligence/intelProfiles/{$p['profile_id']}/indicators");
            } catch (Throwable $e) { $skipped++; continue; }

            $n = 0;
            foreach ($iocs as $ioc) {
                if ($n >= $perProfile) { break; }
                $artifact = $ioc['artifact'] ?? [];
                $value = $this->extractIocValue($artifact);
                $iocType = $this->mapIocType($artifact, $value);
                try {
                    Database::query(
                        "INSERT OR REPLACE INTO ti_iocs
                         (tenant_id, profile_id, article_id, ioc_id, ioc_type, ioc_value, source, description, severity, first_seen, last_seen, fetched_at)
                         VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                        [
                            $tenantId,
                            (int)$p['id'],
                            $ioc['id'] ?? md5($iocType . '|' . $value),
                            $iocType,
                            $value,
                            $ioc['source'] ?? null,
                            $ioc['description'] ?? null,
                            $ioc['severity'] ?? null,
                            $ioc['firstSeenDateTime'] ?? null,
                            $ioc['lastSeenDateTime'] ?? null,
                        ]
                    );
                    $n++;
                } catch (Throwable $e) { /* skip */ }
            }
            Database::query("UPDATE ti_intel_profiles SET indicators_synced_at = datetime('now') WHERE id = ?", [(int)$p['id']]);
            $added++;
        }

        if ($end >= $total) {
            setting_set('ti_last_sync_' . $tenantId, gmdate('c'));
        }

        return ['success' => true, 'phase' => 'profile_indicators', 'processed' => $end, 'total' => $total, 'cursor' => $end, 'done' => $end >= $total, 'added' => $added, 'skipped' => $skipped];
    }

    /** Endpoint de sincronización por pasos (articles / profiles / profile_indicators). */
    public function syncRun(array $params = []): void
    {
        Csrf::validateOrFail();
        $tenantId = (int)($params['tenantId'] ?? 0);
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $phase = (string)($input['phase'] ?? 'articles');
        $cursor = max(0, (int)($input['cursor'] ?? 0));
        $batch = max(1, min(25, (int)($input['batch'] ?? 8)));

        $missing = $this->missingPermissions($tenantId);
        if (!empty($missing)) {
            json_response(['success' => false, 'skipped' => true, 'error' => 'El tenant no tiene los permisos: ' . implode(', ', $missing)]);
        }

        try {
            $client = $this->getGraphClient($tenantId);
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()]);
            return;
        }

        try {
            $res = match ($phase) {
                'profiles'           => $this->syncStepProfiles($client, $tenantId, $cursor, $batch),
                'profile_indicators' => $this->syncStepProfileIndicators($client, $tenantId, $cursor, $batch),
                default              => $this->syncStepArticles($client, $tenantId, $cursor, $batch),
            };
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()]);
            return;
        }

        json_response($res);
    }

    // ============================================================
    // Rutas del módulo
    // ============================================================

    public function routes(): array
    {
        return [
            ['method' => 'GET', 'pattern' => '',                    'handler' => [$this, 'index']],
            ['method' => 'GET', 'pattern' => 'articles',            'handler' => [$this, 'listArticles']],
            ['method' => 'GET', 'pattern' => 'article/{id}',        'handler' => [$this, 'showArticlePage']],
            ['method' => 'GET', 'pattern' => 'article/{id}/data',   'handler' => [$this, 'showArticle']],
            ['method' => 'GET', 'pattern' => 'iocs',                'handler' => [$this, 'iocsPage']],
            ['method' => 'GET', 'pattern' => 'iocs/data',           'handler' => [$this, 'listIocs']],
            ['method' => 'GET', 'pattern' => 'stats',               'handler' => [$this, 'getStats']],
            ['method' => 'GET', 'pattern' => 'profiles',            'handler' => [$this, 'profilesPage']],
            ['method' => 'GET', 'pattern' => 'profile/{id}',        'handler' => [$this, 'showProfilePage']],
            ['method' => 'POST','pattern' => 'sync/{tenantId}',    'handler' => [$this, 'triggerSync']],
            ['method' => 'POST','pattern' => 'sync-run/{tenantId}', 'handler' => [$this, 'syncRun']],
            ['method' => 'POST','pattern' => 'sync-indicators/{tenantId}', 'handler' => [$this, 'triggerSyncIndicators']],
        ];
    }

    /**
     * Página de detalle de un artículo: cuerpo, IOCs, export y análisis IA.
     */
    public function showArticlePage(array $params = []): void
    {
        $id = (int)($params['id'] ?? 0);
        $article = Database::fetchOne("SELECT * FROM ti_articles WHERE id = ?", [$id]);
        if (!$article) {
            http_response_code(404);
            require VIEWS_PATH . '/errors/404.php';
            return;
        }
        $iocs = Database::fetchAll(
            "SELECT * FROM ti_iocs WHERE article_id = ? ORDER BY ioc_type, ioc_value",
            [$id]
        );
        $tenant = TenantManager::getById((int)$article['tenant_id']);
        $range = $this->resolveDateRange();
        $prevId = $this->adjacentArticle('prev', $article);
        $nextId = $this->adjacentArticle('next', $article);

        echo $this->page('article', [
            'module'   => $this,
            'article'  => $article,
            'iocs'     => $iocs,
            'tenant'   => $tenant,
            'prevId'   => $prevId,
            'nextId'   => $nextId,
            'dateFrom' => $range['from'],
            'dateTo'   => $range['to'],
            'q'        => trim((string)($_GET['q'] ?? '')),
            'tag'      => trim((string)($_GET['tag'] ?? '')),
            'sector'   => trim((string)($_GET['sector'] ?? '')),
            'profiles' => llm_profile_list(),
            'defaultProfileId' => (llm_profile_default()['id'] ?? null),
            'actions'           => llm_actions_list(true, 'article'),
            'actionsEditorList' => llm_actions_list(false, 'article'),
            'actionScope'       => 'article',
        ]);
    }

    /**
     * Página con la lista de IOCs (filtros + paginación).
     */
    public function iocsPage(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $def = $this->defaultDateRange();
        $filters = [
            'type'   => $_GET['type'] ?? '',
            'search' => $_GET['search'] ?? '',
            'from'   => $_GET['from'] ?? $def['from'],
            'to'     => $_GET['to'] ?? $def['to'],
            'sort'   => $_GET['sort'] ?? '',
        ];
        $page = max(1, (int)($_GET['page'] ?? 1));
        $data = $selectedTenant
            ? $this->getIocs($selectedTenant, $filters, $page, 50)
            : ['data' => [], 'total' => 0, 'page' => 1, 'perPage' => 50, 'totalPages' => 1];
        $types = $selectedTenant ? $this->getIocStats($selectedTenant) : [];

        echo $this->page('iocs', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'filters'        => $filters,
            'iocs'           => $data,
            'types'          => $types,
            'profileCounts'  => $selectedTenant ? $this->getProfileCounts($selectedTenant) : ['actor' => 0, 'tool' => 0, 'other' => 0, 'total' => 0],
            'dateDefaultFrom' => $def['from'],
            'dateDefaultTo'   => $def['to'],
            'actions'           => llm_actions_list(true, 'indicator'),
            'actionsEditorList' => llm_actions_list(false, 'indicator'),
            'actionScope'       => 'indicator',
            'profiles'          => llm_profile_list(),
            'defaultProfileId'  => (llm_profile_default()['id'] ?? null),
        ]);
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $range = $this->resolveDateRange();
        $def = $this->defaultDateRange();
        $q = trim((string)($_GET['q'] ?? ''));
        $tag = trim((string)($_GET['tag'] ?? ''));
        $sector = trim((string)($_GET['sector'] ?? ''));
        $filters = array_merge($range, ['q' => $q, 'tag' => $tag, 'sector' => $sector]);
        $stats = $selectedTenant ? $this->getIocStats($selectedTenant) : [];
        $articles = $selectedTenant ? $this->getArticles($selectedTenant, 1, 50, $filters) : ['data' => []];
        $tagOptions = $selectedTenant ? $this->getArticleTags($selectedTenant) : [];
        $mySector = $selectedTenant ? $this->tenantSectorKey($selectedTenant) : null;

        echo $this->page('index', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'stats'          => $stats,
            'articles'       => $articles,
            'dateFrom'       => $range['from'],
            'dateTo'         => $range['to'],
            'dateDefaultFrom' => $def['from'],
            'dateDefaultTo'   => $def['to'],
            'q'              => $q,
            'tag'            => $tag,
            'tagOptions'     => $tagOptions,
            'sectors'        => array_keys(SECTORS),
            'sector'         => $sector,
            'mySector'       => $mySector,
            'profileCounts'  => $selectedTenant ? $this->getProfileCounts($selectedTenant) : ['actor' => 0, 'tool' => 0, 'other' => 0, 'total' => 0],
        ]);
    }

    /**
     * Sector del tenant a partir del campo industry (Graph /organization).
     */
    private function tenantSectorKey(int $tenantId): ?string
    {
        $tenant = TenantManager::getById($tenantId);
        $ind = strtolower((string)($tenant['industry'] ?? ''));
        if ($ind === '') {
            return null;
        }
        foreach (SECTOR_INDUSTRY_MAP as $needle => $sector) {
            if (str_contains($ind, $needle)) {
                return $sector;
            }
        }
        return null;
    }

    public function listArticles(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        $page = (int)($_GET['page'] ?? 1);
        json_response($this->getArticles($tenantId, $page));
    }

    public function showArticle(array $params = []): void
    {
        $id = (int)($params['id'] ?? 0);
        $article = Database::fetchOne("SELECT * FROM ti_articles WHERE id = ?", [$id]);
        $iocs = Database::fetchAll("SELECT * FROM ti_iocs WHERE article_id = ?", [$id]);
        json_response(['article' => $article, 'iocs' => $iocs]);
    }

    public function listIocs(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        $page = (int)($_GET['page'] ?? 1);
        $filters = [
            'type'   => $_GET['type'] ?? '',
            'search' => $_GET['search'] ?? '',
            'from'   => $_GET['from'] ?? '',
            'to'     => $_GET['to'] ?? '',
            'sort'   => $_GET['sort'] ?? '',
        ];
        json_response($this->getIocs($tenantId, $filters, $page));
    }

    public function getStats(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        json_response(['stats' => $this->getIocStats($tenantId)]);
    }

    public function triggerSync(array $params = []): void
    {
        Csrf::validateOrFail();
        $tenantId = (int)($params['tenantId'] ?? 0);
        $missing = $this->missingPermissions($tenantId);
        if (!empty($missing)) {
            json_response(['success' => false, 'skipped' => true, 'error' => 'El tenant no tiene los permisos: ' . implode(', ', $missing)]);
        }
        json_response($this->sync($tenantId));
    }
}
