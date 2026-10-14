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
                        "INSERT INTO ti_articles
                         (tenant_id, article_id, title, created_date, last_updated, summary, body, tags, is_featured, fetched_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                         ON CONFLICT(tenant_id, article_id) DO UPDATE SET
                            title = excluded.title,
                            created_date = excluded.created_date,
                            last_updated = excluded.last_updated,
                            summary = excluded.summary,
                            body = excluded.body,
                            tags = excluded.tags,
                            is_featured = excluded.is_featured,
                            fetched_at = datetime('now')",
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
    public function getArticles(int $tenantId, int $page = 1, int $perPage = 20, array $filters = [], ?int $userId = null): array
    {
        // La recencia se decide por la FECHA DE PUBLICACIÓN (created_date), no por
        // la última modificación: así un artículo antiguo re-actualizado no
        // aparece como si fuera de las últimas 24 h.
        $dateExpr = 'COALESCE(a.created_date, a.last_updated)';

        $where = ['a.tenant_id = ?'];
        $params = [$tenantId];
        if (!empty($filters['from'])) {
            $where[] = "substr($dateExpr, 1, 10) >= ?";
            $params[] = $filters['from'];
        }
        if (!empty($filters['to'])) {
            $where[] = "substr($dateExpr, 1, 10) <= ?";
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

        // Estado leído/favorito del usuario actual (opcional).
        $stateJoin = '';
        $joinParams = [];
        $stateSelect = '0 as is_read, 0 as is_favorite';
        if ($userId !== null && $userId > 0) {
            $stateJoin = ' LEFT JOIN ti_article_state s ON s.article_id = a.id AND s.user_id = ?';
            $joinParams[] = $userId;
            $stateSelect = 'COALESCE(s.is_read, 0) as is_read, COALESCE(s.is_favorite, 0) as is_favorite';
            if (!empty($filters['only_unread'])) {
                $where[] = 'COALESCE(s.is_read, 0) = 0';
            }
            if (!empty($filters['only_favorites'])) {
                $where[] = 'COALESCE(s.is_favorite, 0) = 1';
            }
        }

        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM ti_articles a $stateJoin WHERE $whereClause",
            array_merge($joinParams, $params)
        )['cnt'];

        $params[] = $perPage;
        $params[] = $offset;

        $articles = Database::fetchAll(
            "SELECT a.*, $stateSelect, COUNT(i.id) as ioc_count
             FROM ti_articles a
             $stateJoin
             LEFT JOIN ti_iocs i ON a.id = i.article_id AND i.tenant_id = a.tenant_id
             WHERE $whereClause
             GROUP BY a.id
             ORDER BY $dateExpr DESC
             LIMIT ? OFFSET ?",
            array_merge($joinParams, $params)
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
     * Nº de artículos sin leer y favoritos del usuario para un tenant.
     */
    public function getArticleStateCounts(int $tenantId, ?int $userId): array
    {
        if ($userId === null || $userId <= 0) {
            return ['unread' => 0, 'favorites' => 0];
        }
        $row = Database::fetchOne(
            "SELECT
                SUM(CASE WHEN COALESCE(s.is_read, 0) = 0 THEN 1 ELSE 0 END) AS unread,
                SUM(CASE WHEN COALESCE(s.is_favorite, 0) = 1 THEN 1 ELSE 0 END) AS favorites
             FROM ti_articles a
             LEFT JOIN ti_article_state s ON s.article_id = a.id AND s.user_id = ?
             WHERE a.tenant_id = ?",
            [$userId, $tenantId]
        );
        return [
            'unread'    => (int)($row['unread'] ?? 0),
            'favorites' => (int)($row['favorites'] ?? 0),
        ];
    }

    /**
     * Marca/desmarca un artículo como leído y/o favorito para el usuario actual.
     * Es un merge: lo que no se envía se conserva.
     */
    public function setArticleState(array $params = []): void
    {
        Csrf::validateOrFail();
        $id = (int)($params['id'] ?? 0);
        $article = Database::fetchOne("SELECT id FROM ti_articles WHERE id = ?", [$id]);
        if (!$article) {
            json_response(['success' => false, 'error' => 'Artículo no encontrado']);
        }
        $userId = (int)(Auth::id() ?? 0);
        if ($userId <= 0) {
            json_response(['success' => false, 'error' => 'Sesión no válida']);
        }

        $input = json_decode(file_get_contents('php://input'), true);
        if (!is_array($input)) { $input = $_POST; }

        $current = Database::fetchOne(
            "SELECT is_read, read_at, is_favorite, favorite_at FROM ti_article_state WHERE user_id = ? AND article_id = ?",
            [$userId, $id]
        ) ?: ['is_read' => 0, 'read_at' => null, 'is_favorite' => 0, 'favorite_at' => null];

        $isRead = array_key_exists('is_read', $input)
            ? (!empty($input['is_read']) ? 1 : 0)
            : (int)$current['is_read'];
        $isFav = array_key_exists('is_favorite', $input)
            ? (!empty($input['is_favorite']) ? 1 : 0)
            : (int)$current['is_favorite'];

        $readAt = $isRead ? ($current['read_at'] ?: gmdate('Y-m-d H:i:s')) : null;
        $favAt  = $isFav  ? ($current['favorite_at'] ?: gmdate('Y-m-d H:i:s')) : null;

        Database::query(
            "INSERT INTO ti_article_state (user_id, article_id, is_read, read_at, is_favorite, favorite_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(user_id, article_id) DO UPDATE SET
                is_read = excluded.is_read,
                read_at = excluded.read_at,
                is_favorite = excluded.is_favorite,
                favorite_at = excluded.favorite_at,
                updated_at = datetime('now')",
            [$userId, $id, $isRead, $readAt, $isFav, $favAt]
        );

        json_response([
            'success'     => true,
            'is_read'     => $isRead,
            'is_favorite' => $isFav,
        ]);
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
     * Rango por defecto de la pestaña Indicators: últimos TI_INDICATORS_FULL_DAYS
     * días (90 por defecto).
     */
    private function defaultIocDateRange(): array
    {
        $days = max(1, (int)TI_INDICATORS_FULL_DAYS);
        $to = gmdate('Y-m-d');
        return ['from' => gmdate('Y-m-d', strtotime($to) - $days * 86400), 'to' => $to];
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
    private function adjacentArticle(string $dir, array $article, ?int $userId = null): ?int
    {
        $tenantId = (int)$article['tenant_id'];
        // Clave de orden = fecha de publicación (coherente con la lista y el filtro).
        $dateExpr = 'COALESCE(created_date, last_updated)';
        $key = $article['created_date'] ?? $article['last_updated'] ?? null;
        $range = $this->resolveDateRange();

        $onlyUnread = !empty($_GET['only_unread']);
        $onlyFav    = !empty($_GET['only_favorites']);
        $stateJoin = '';
        $joinParams = [];
        if ($userId !== null && $userId > 0 && ($onlyUnread || $onlyFav)) {
            $stateJoin = ' LEFT JOIN ti_article_state s ON s.article_id = ti_articles.id AND s.user_id = ?';
            $joinParams[] = $userId;
        }

        $params = array_merge($joinParams, [$tenantId, $key]);
        $rangeSql = '';
        $rangeSql .= " AND substr($dateExpr, 1, 10) >= ?";
        $params[] = $range['from'];
        $rangeSql .= " AND substr($dateExpr, 1, 10) <= ?";
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
        if ($userId !== null && $userId > 0 && $onlyUnread) {
            $rangeSql .= ' AND COALESCE(s.is_read, 0) = 0';
        }
        if ($userId !== null && $userId > 0 && $onlyFav) {
            $rangeSql .= ' AND COALESCE(s.is_favorite, 0) = 1';
        }

        $cmp = ($dir === 'prev') ? '>' : '<';
        $ord = ($dir === 'prev') ? 'ASC' : 'DESC';
        $row = Database::fetchOne(
            "SELECT ti_articles.id FROM ti_articles
             $stateJoin
             WHERE tenant_id = ? AND $dateExpr $cmp ? $rangeSql
             ORDER BY $dateExpr $ord LIMIT 1",
            $params
        );
        return $row ? (int)$row['id'] : null;
    }

    /**
     * Obtiene IOCs de un tenant con filtros. Los resultados van SIN DUPLICADOS:
     * se agrupa por tipo+valor (un indicador puede venir de varios perfiles).
     * La búsqueda abarca valor, descripción y fuente.
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
            $like = '%' . $filters['search'] . '%';
            $where[] = '(ioc_value LIKE ? OR description LIKE ? OR source LIKE ?)';
            array_push($params, $like, $like, $like);
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
            : 'COALESCE(MAX(last_seen), MAX(first_seen), MAX(fetched_at)) DESC';

        // Total de valores únicos (sin duplicados).
        $total = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM (SELECT 1 FROM ti_iocs WHERE $whereClause GROUP BY ioc_type, ioc_value)",
            $params
        )['cnt'];

        $params[] = $perPage;
        $params[] = $offset;

        $iocs = Database::fetchAll(
            "SELECT MIN(id) AS id, ioc_type, ioc_value,
                    MAX(severity) AS severity, MIN(first_seen) AS first_seen,
                    MAX(last_seen) AS last_seen, MAX(description) AS description,
                    MAX(source) AS source, MAX(article_id) AS article_id,
                    MAX(profile_id) AS profile_id, COUNT(*) AS occurrences
             FROM ti_iocs WHERE $whereClause
             GROUP BY ioc_type, ioc_value
             ORDER BY $orderBy
             LIMIT ? OFFSET ?",
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
     * Obtiene estadísticas de IOCs por tipo (valores únicos, sin duplicados).
     */
    public function getIocStats(int $tenantId): array
    {
        return Database::fetchAll(
            "SELECT ioc_type, COUNT(DISTINCT ioc_value) as cnt FROM ti_iocs WHERE tenant_id = ? GROUP BY ioc_type ORDER BY cnt DESC",
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
                $facets = ti_parse_targets(is_array($p['targets'] ?? null) ? $p['targets'] : []);
                Database::query(
                    "INSERT INTO ti_intel_profiles
                     (tenant_id, profile_id, kind, title, summary, description, tradecraft, aliases, targets, industries, regions, countries, first_active, raw_data, fetched_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                     ON CONFLICT(tenant_id, profile_id) DO UPDATE SET
                        kind = excluded.kind,
                        title = excluded.title,
                        summary = excluded.summary,
                        description = excluded.description,
                        tradecraft = excluded.tradecraft,
                        aliases = excluded.aliases,
                        targets = excluded.targets,
                        industries = excluded.industries,
                        regions = excluded.regions,
                        countries = excluded.countries,
                        first_active = excluded.first_active,
                        raw_data = excluded.raw_data,
                        fetched_at = datetime('now')",
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
                        json_encode($facets['industries'], JSON_UNESCAPED_UNICODE),
                        json_encode($facets['regions'], JSON_UNESCAPED_UNICODE),
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
        // Facetas: industria / región (varias por grupo, OR dentro de cada grupo)
        foreach (['industry' => 'industries', 'region' => 'regions'] as $fk => $col) {
            $vals = array_values(array_filter((array)($filters[$fk] ?? []), fn($v) => $v !== '' && $v !== null));
            if ($vals) {
                $or = [];
                foreach ($vals as $v) {
                    $or[] = $col . ' LIKE ?';
                    $params[] = '%"' . $v . '"%';
                }
                $where[] = '(' . implode(' OR ', $or) . ')';
            }
        }
        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne("SELECT COUNT(*) as cnt FROM ti_intel_profiles WHERE $whereClause", $params)['cnt'];
        $params[] = $perPage;
        $params[] = $offset;
        $rows = Database::fetchAll("SELECT * FROM ti_intel_profiles WHERE $whereClause ORDER BY title LIMIT ? OFFSET ?", $params);

        return ['data' => $rows, 'total' => $total, 'page' => $page, 'perPage' => $perPage, 'totalPages' => (int)ceil($total / $perPage)];
    }

    /**
     * Rellena industries/regions de perfiles antiguos a partir de sus targets.
     * Solo toca filas aún sin procesar (columnas NULL).
     */
    private function backfillProfileFacets(int $tenantId): void
    {
        $rows = Database::fetchAll(
            "SELECT id, targets FROM ti_intel_profiles WHERE tenant_id = ? AND (industries IS NULL OR regions IS NULL)",
            [$tenantId]
        );
        foreach ($rows as $r) {
            $targets = safe_json_decode((string)($r['targets'] ?? ''), []);
            $facets = ti_parse_targets(is_array($targets) ? $targets : []);
            Database::query(
                "UPDATE ti_intel_profiles SET industries = ?, regions = ? WHERE id = ?",
                [json_encode($facets['industries'], JSON_UNESCAPED_UNICODE), json_encode($facets['regions'], JSON_UNESCAPED_UNICODE), (int)$r['id']]
            );
        }
    }

    /** Facetas de intel profiles: industrias y regiones con su nº de perfiles. */
    public function getProfileFacets(int $tenantId): array
    {
        $rows = Database::fetchAll("SELECT industries, regions FROM ti_intel_profiles WHERE tenant_id = ?", [$tenantId]);
        $ind = [];
        $reg = [];
        foreach ($rows as $r) {
            foreach ((array)safe_json_decode((string)($r['industries'] ?? ''), []) as $v) {
                $v = trim((string)$v);
                if ($v !== '') { $ind[$v] = ($ind[$v] ?? 0) + 1; }
            }
            foreach ((array)safe_json_decode((string)($r['regions'] ?? ''), []) as $v) {
                $v = trim((string)$v);
                if ($v !== '') { $reg[$v] = ($reg[$v] ?? 0) + 1; }
            }
        }

        // Vocabulario canónico COMPLETO (con 0 donde no haya resultados), más
        // los valores extra presentes. Orden: primero lo más afectado, luego el
        // resto en el orden de la taxonomía (paridad con MDTI).
        $build = function (array $counts, array $canonical): array {
            $all = [];
            foreach ($canonical as $name) { $all[$name] = (int)($counts[$name] ?? 0); }
            foreach ($counts as $name => $cnt) {
                if (!array_key_exists($name, $all)) { $all[$name] = (int)$cnt; }
            }
            $canonIdx = array_flip($canonical);
            uksort($all, function ($a, $b) use ($all, $canonIdx) {
                if ($all[$a] !== $all[$b]) { return $all[$b] <=> $all[$a]; }
                return ($canonIdx[$a] ?? PHP_INT_MAX) <=> ($canonIdx[$b] ?? PHP_INT_MAX);
            });
            return $all;
        };

        return [
            'industries' => $build($ind, TI_TARGET_INDUSTRIES),
            'regions'    => $build($reg, TI_TARGET_REGIONS),
        ];
    }

    /**
     * Re-clasifica (una sola vez) industrias/regiones de los perfiles ya
     * guardados con la taxonomía canónica MDTI. Idempotente vía settings.
     */
    private function ensureTargetsTaxonomyOnce(): void
    {
        try {
            if ((string)setting_get('ti_targets_taxonomy_v2', '') === '1') {
                return;
            }
            $rows = Database::fetchAll("SELECT id, targets FROM ti_intel_profiles");
            foreach ($rows as $r) {
                $targets = safe_json_decode((string)($r['targets'] ?? ''), []);
                $facets  = ti_parse_targets(is_array($targets) ? $targets : []);
                Database::query(
                    "UPDATE ti_intel_profiles SET industries = ?, regions = ? WHERE id = ?",
                    [json_encode($facets['industries'], JSON_UNESCAPED_UNICODE), json_encode($facets['regions'], JSON_UNESCAPED_UNICODE), (int)$r['id']]
                );
            }
            setting_set('ti_targets_taxonomy_v2', '1');
        } catch (Throwable $e) {
            // No es crítico: se reintentará en la siguiente carga.
        }
    }

    /**
     * Estadística de sectores afectados dentro de un rango de fechas.
     * Cuenta los artículos por sector (palabras clave de SECTORS) del rango,
     * tenant y filtros q/tag. NO aplica el filtro `sector`. Un artículo puede
     * contarse en varios sectores.
     *
     * @return array{total:int,sectors:array<int,array{sector:string,count:int,pct:int}>}
     */
    public function getSectorStats(int $tenantId, array $filters = []): array
    {
        $dateExpr = 'COALESCE(created_date, last_updated)';
        $where = ['tenant_id = ?'];
        $params = [$tenantId];
        if (!empty($filters['from'])) {
            $where[] = "substr($dateExpr, 1, 10) >= ?";
            $params[] = $filters['from'];
        }
        if (!empty($filters['to'])) {
            $where[] = "substr($dateExpr, 1, 10) <= ?";
            $params[] = $filters['to'];
        }
        if (!empty($filters['q'])) {
            $like = '%' . $filters['q'] . '%';
            $where[] = "(title LIKE ? OR summary LIKE ? OR body LIKE ? OR tags LIKE ?)";
            array_push($params, $like, $like, $like, $like);
        }
        if (!empty($filters['tag'])) {
            $where[] = 'tags LIKE ?';
            $params[] = '%' . $filters['tag'] . '%';
        }
        $whereClause = implode(' AND ', $where);

        $total = (int)(Database::fetchOne("SELECT COUNT(*) AS c FROM ti_articles WHERE $whereClause", $params)['c'] ?? 0);

        $sectorKeys = array_keys(SECTORS);
        $counts = array_fill_keys($sectorKeys, 0);

        if ($total > 0) {
            $selects = [];
            $selParams = [];
            $i = 0;
            foreach (SECTORS as $keywords) {
                $or = [];
                foreach ($keywords as $kw) {
                    $like = '%' . $kw . '%';
                    $or[] = 'title LIKE ?';   $selParams[] = $like;
                    $or[] = 'summary LIKE ?'; $selParams[] = $like;
                    $or[] = 'body LIKE ?';    $selParams[] = $like;
                    $or[] = 'tags LIKE ?';    $selParams[] = $like;
                }
                $selects[] = 'SUM(CASE WHEN (' . implode(' OR ', $or) . ') THEN 1 ELSE 0 END) AS sector_' . $i;
                $i++;
            }
            $row = Database::fetchOne(
                'SELECT ' . implode(', ', $selects) . " FROM ti_articles WHERE $whereClause",
                array_merge($selParams, $params)
            ) ?? [];
            foreach ($sectorKeys as $idx => $name) {
                $counts[$name] = (int)($row['sector_' . $idx] ?? 0);
            }
        }

        $out = [];
        foreach ($counts as $name => $c) {
            $out[] = [
                'sector' => $name,
                'count'  => $c,
                'pct'    => $total > 0 ? (int)round($c * 100 / $total) : 0,
            ];
        }
        usort($out, fn($a, $b) => ($b['count'] <=> $a['count']) ?: strcmp($a['sector'], $b['sector']));

        return ['total' => $total, 'sectors' => $out];
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
        if ($selectedTenant) {
            $this->ensureTargetsTaxonomyOnce();
            $this->backfillProfileFacets($selectedTenant);
        }
        $norm = function ($v) { return array_values(array_filter(array_map('strval', (array)$v), fn($x) => trim($x) !== '')); };
        $filters = [
            'kind'     => trim((string)($_GET['kind'] ?? '')),
            'search'   => trim((string)($_GET['search'] ?? $_GET['q'] ?? '')),
            'industry' => $norm($_GET['industry'] ?? []),
            'region'   => $norm($_GET['region'] ?? []),
        ];
        $page = max(1, (int)($_GET['page'] ?? 1));
        $data = $selectedTenant ? $this->getProfiles($selectedTenant, $filters, $page, 50) : ['data' => [], 'total' => 0, 'page' => 1, 'perPage' => 50, 'totalPages' => 1];
        $counts = $selectedTenant ? $this->getProfileCounts($selectedTenant) : ['actor' => 0, 'tool' => 0, 'other' => 0, 'total' => 0];
        $facets = $selectedTenant ? $this->getProfileFacets($selectedTenant) : ['industries' => [], 'regions' => []];

        echo $this->page('profiles', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'filters'        => $filters,
            'profiles'       => $data,
            'counts'         => $counts,
            'facets'         => $facets,
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
        // Backfill de facetas si el perfil es antiguo (aún sin industries/regions).
        if ($profile['industries'] === null || $profile['regions'] === null) {
            $targets = safe_json_decode((string)($profile['targets'] ?? ''), []);
            $facets  = ti_parse_targets(is_array($targets) ? $targets : []);
            $profile['industries'] = json_encode($facets['industries'], JSON_UNESCAPED_UNICODE);
            $profile['regions']    = json_encode($facets['regions'], JSON_UNESCAPED_UNICODE);
            Database::query(
                "UPDATE ti_intel_profiles SET industries = ?, regions = ? WHERE id = ?",
                [$profile['industries'], $profile['regions'], $id]
            );
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
        release_session_lock();
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
                    "INSERT INTO ti_articles
                     (tenant_id, article_id, title, created_date, last_updated, summary, body, tags, is_featured, fetched_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                     ON CONFLICT(tenant_id, article_id) DO UPDATE SET
                        title = excluded.title,
                        created_date = excluded.created_date,
                        last_updated = excluded.last_updated,
                        summary = excluded.summary,
                        body = excluded.body,
                        tags = excluded.tags,
                        is_featured = excluded.is_featured,
                        fetched_at = datetime('now')",
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

    /**
     * Carga INICIAL de indicadores: recorre todos los intel profiles y guarda
     * los indicadores con actividad en los últimos TI_INDICATORS_FULL_DAYS días,
     * hasta un máximo total de TI_INDICATORS_FULL_LIMIT. Por pasos (con progreso).
     */
    public function syncIndicatorsFull(GraphClient $client, int $tenantId, int $cursor = 0, int $batch = 8): array
    {
        $limit  = max(1, (int)TI_INDICATORS_FULL_LIMIT);
        $days   = max(1, (int)TI_INDICATORS_FULL_DAYS);
        $cutoff = time() - $days * 86400;

        $profiles = Database::fetchAll("SELECT id, profile_id FROM ti_intel_profiles WHERE tenant_id = ? ORDER BY id", [$tenantId]);
        $total = count($profiles);
        $end = min($cursor + $batch, $total);

        // Indicadores ya almacenados (para respetar el tope global de la carga).
        $stored = (int)(Database::fetchOne("SELECT COUNT(*) c FROM ti_iocs WHERE tenant_id = ?", [$tenantId])['c'] ?? 0);

        $added = 0;
        $skipped = 0;
        $limitReached = false;

        for ($k = $cursor; $k < $end; $k++) {
            if ($stored + $added >= $limit) { $limitReached = true; break; }
            $p = $profiles[$k];
            try {
                $iocs = $client->graphGetAll("security/threatIntelligence/intelProfiles/{$p['profile_id']}/indicators");
            } catch (Throwable $e) { $skipped++; continue; }

            foreach ($iocs as $ioc) {
                if ($stored + $added >= $limit) { $limitReached = true; break; }
                // Solo indicadores con actividad en la ventana (si tienen fecha).
                $date = $ioc['lastSeenDateTime'] ?? $ioc['firstSeenDateTime'] ?? null;
                if ($date !== null) {
                    $ts = strtotime((string)$date);
                    if ($ts !== false && $ts < $cutoff) { $skipped++; continue; }
                }
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
                    $added++;
                } catch (Throwable $e) { /* skip */ }
            }
        }

        if ($end >= $total) {
            setting_set('ti_last_sync_' . $tenantId, gmdate('c'));
        }

        return [
            'success'      => true,
            'phase'        => 'indicators_full',
            'processed'    => $end,
            'total'        => $total,
            'cursor'       => $end,
            'done'         => ($end >= $total) || $limitReached,
            'added'        => $added,
            'skipped'      => $skipped,
            'stored'       => $stored + $added,
            'limit'        => $limit,
            'limitReached' => $limitReached,
        ];
    }

    /** Endpoint de la carga inicial de indicadores (por pasos, con progreso). */
    public function syncIndicatorsFullEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        release_session_lock();
        $tenantId = (int)($params['tenantId'] ?? 0);
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
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
            json_response($this->syncIndicatorsFull($client, $tenantId, $cursor, $batch));
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()]);
        }
    }

    /** Endpoint de sincronización por pasos (articles / profiles / profile_indicators). */
    public function syncRun(array $params = []): void
    {
        Csrf::validateOrFail();
        release_session_lock();
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
            ['method' => 'POST','pattern' => 'article/{id}/state',  'handler' => [$this, 'setArticleState']],
            ['method' => 'POST','pattern' => 'sync/{tenantId}',    'handler' => [$this, 'triggerSync']],
            ['method' => 'POST','pattern' => 'sync-run/{tenantId}', 'handler' => [$this, 'syncRun']],
            ['method' => 'POST','pattern' => 'sync-indicators/{tenantId}', 'handler' => [$this, 'triggerSyncIndicators']],
            ['method' => 'POST','pattern' => 'sync-indicators-full/{tenantId}', 'handler' => [$this, 'syncIndicatorsFullEndpoint']],
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
        $userId = (int)(Auth::id() ?? 0);
        $prevId = $this->adjacentArticle('prev', $article, $userId ?: null);
        $nextId = $this->adjacentArticle('next', $article, $userId ?: null);

        $state = $userId > 0
            ? Database::fetchOne("SELECT is_read, is_favorite, read_at, favorite_at FROM ti_article_state WHERE user_id = ? AND article_id = ?", [$userId, $id])
            : null;

        // Traducción cacheada: válida si el artículo no cambió desde que se tradujo
        // y tiene menos de 90 días (caducidad acordada).
        $translationHtml = null;
        $hasTranslation = false;
        $cached = Database::fetchOne("SELECT content, source_updated, created_at FROM ti_article_translations WHERE article_id = ? AND lang = 'es'", [$id]);
        if ($cached) {
            $fresh  = (string)($cached['source_updated'] ?? '') === (string)($article['last_updated'] ?? '');
            $ts     = strtotime((string)$cached['created_at']);
            $notOld = ($ts !== false) && (time() - $ts) < 90 * 86400;
            if ($fresh && $notOld && trim((string)$cached['content']) !== '') {
                $hasTranslation  = true;
                $translationHtml = render_markdown((string)$cached['content']);
            }
        }

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
            'articleState'    => $state,
            'hasTranslation'  => $hasTranslation,
            'translationHtml' => $translationHtml,
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
        $def = $this->defaultIocDateRange();
        $filters = [
            'type'   => $_GET['type'] ?? '',
            'search' => trim((string)($_GET['search'] ?? $_GET['q'] ?? '')),
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
        $onlyUnread = !empty($_GET['only_unread']) ? 1 : 0;
        $onlyFavorites = !empty($_GET['only_favorites']) ? 1 : 0;
        $userId = (int)(Auth::id() ?? 0);
        $filters = array_merge($range, [
            'q' => $q, 'tag' => $tag, 'sector' => $sector,
            'only_unread' => $onlyUnread, 'only_favorites' => $onlyFavorites,
        ]);
        $stats = $selectedTenant ? $this->getIocStats($selectedTenant) : [];
        $articles = $selectedTenant ? $this->getArticles($selectedTenant, 1, 50, $filters, $userId ?: null) : ['data' => []];
        $tagOptions = $selectedTenant ? $this->getArticleTags($selectedTenant) : [];
        $mySector = $selectedTenant ? $this->tenantSectorKey($selectedTenant) : null;
        $stateCounts = $selectedTenant ? $this->getArticleStateCounts($selectedTenant, $userId ?: null) : ['unread' => 0, 'favorites' => 0];
        $sectorStats = $selectedTenant
            ? $this->getSectorStats($selectedTenant, ['from' => $range['from'], 'to' => $range['to'], 'q' => $q, 'tag' => $tag])
            : ['total' => 0, 'sectors' => []];

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
            'onlyUnread'     => $onlyUnread,
            'onlyFavorites'  => $onlyFavorites,
            'stateCounts'    => $stateCounts,
            'sectorStats'    => $sectorStats,
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
        $userId = (int)(Auth::id() ?? 0);
        json_response($this->getArticles($tenantId, $page, 20, [], $userId ?: null));
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
        release_session_lock();
        $tenantId = (int)($params['tenantId'] ?? 0);
        $missing = $this->missingPermissions($tenantId);
        if (!empty($missing)) {
            json_response(['success' => false, 'skipped' => true, 'error' => 'El tenant no tiene los permisos: ' . implode(', ', $missing)]);
        }
        json_response($this->sync($tenantId));
    }
}
