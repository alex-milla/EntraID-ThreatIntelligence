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
            // 1. Obtener artículos recientes (últimos 30 días)
            $articles = $client->graphGet('security/threatIntelligence/articles', [
                '$select' => 'id,title,createdDateTime,lastUpdatedDateTime',
            ]);

            $since = time() - (30 * 86400);
            $recent = array_filter($articles['value'] ?? [], function ($a) use ($since) {
                $date = $a['lastUpdatedDateTime'] ?? $a['createdDateTime'] ?? null;
                return $date && strtotime($date) >= $since;
            });

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
                $iocType = $this->mapIocType($artifact);

                Database::query(
                    "INSERT OR REPLACE INTO ti_iocs
                     (tenant_id, article_id, ioc_id, ioc_type, ioc_value, source, description, severity, first_seen, last_seen, fetched_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                    [
                        $tenantId,
                        $articleDbId,
                        $ioc['id'],
                        $iocType,
                        $this->extractIocValue($artifact),
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
     * Mapea el tipo de artefacto a tipo STIX-like.
     */
    private function mapIocType(array $artifact): string
    {
        return match (true) {
            isset($artifact['ipV4Address'], $artifact['ipV6Address']) => 'ipv4-addr',
            isset($artifact['domainName'])                           => 'domain-name',
            isset($artifact['url'])                                  => 'url',
            isset($artifact['fileHash'])                             => 'file',
            isset($artifact['emailAddress'])                         => 'email-addr',
            isset($artifact['userAccount'])                          => 'user-account',
            isset($artifact['registryKey'])                          => 'windows-registry-key',
            isset($artifact['macAddress'])                           => 'mac-addr',
            default                                                  => 'unknown',
        };
    }

    /**
     * Extrae el valor del IOC desde el artefacto.
     */
    private function extractIocValue(array $artifact): string
    {
        return $artifact['ipV4Address']
            ?? $artifact['ipV6Address']
            ?? $artifact['domainName']
            ?? $artifact['url']
            ?? ($artifact['fileHash']['value'] ?? null)
            ?? $artifact['emailAddress']
            ?? ($artifact['userAccount']['value'] ?? null)
            ?? $artifact['registryKey']
            ?? $artifact['macAddress']
            ?? 'unknown';
    }

    // ============================================================
    // Consultas para la UI
    // ============================================================

    /**
     * Obtiene artículos de un tenant con paginación.
     */
    public function getArticles(int $tenantId, int $page = 1, int $perPage = 20): array
    {
        $offset = ($page - 1) * $perPage;
        $total = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM ti_articles WHERE tenant_id = ?",
            [$tenantId]
        )['cnt'];

        $articles = Database::fetchAll(
            "SELECT a.*, COUNT(i.id) as ioc_count
             FROM ti_articles a
             LEFT JOIN ti_iocs i ON a.id = i.article_id AND i.tenant_id = a.tenant_id
             WHERE a.tenant_id = ?
             GROUP BY a.id
             ORDER BY a.last_updated DESC
             LIMIT ? OFFSET ?",
            [$tenantId, $perPage, $offset]
        );

        return [
            'data'      => $articles,
            'total'     => $total,
            'page'      => $page,
            'perPage'   => $perPage,
            'totalPages'=> (int)ceil($total / $perPage),
        ];
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

        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM ti_iocs WHERE $whereClause",
            $params
        )['cnt'];

        $params[] = $perPage;
        $params[] = $offset;

        $iocs = Database::fetchAll(
            "SELECT * FROM ti_iocs WHERE $whereClause ORDER BY fetched_at DESC LIMIT ? OFFSET ?",
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
    // Rutas del módulo
    // ============================================================

    public function routes(): array
    {
        return [
            ['method' => 'GET', 'pattern' => '',                    'handler' => [$this, 'index']],
            ['method' => 'GET', 'pattern' => 'articles',            'handler' => [$this, 'listArticles']],
            ['method' => 'GET', 'pattern' => 'article/{id}',        'handler' => [$this, 'showArticle']],
            ['method' => 'GET', 'pattern' => 'iocs',                'handler' => [$this, 'listIocs']],
            ['method' => 'GET', 'pattern' => 'stats',               'handler' => [$this, 'getStats']],
            ['method' => 'POST','pattern' => 'sync/{tenantId}',    'handler' => [$this, 'triggerSync']],
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $stats = $selectedTenant ? $this->getIocStats($selectedTenant) : [];
        $articles = $selectedTenant ? $this->getArticles($selectedTenant, 1, 10) : ['data' => []];

        echo $this->render('index', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'stats'          => $stats,
            'articles'       => $articles,
        ]);
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
        json_response($this->sync($tenantId));
    }
}
