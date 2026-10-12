<?php
/**
 * Módulo: Advanced Hunting (KQL)
 * Ejecuta consultas KQL programáticas contra Defender XDR.
 * Permiso: ThreatHunting.Read.All
 * Nota: los datos raw solo cubren 30 días; se almacenan agregados para histórico.
 */

declare(strict_types=1);

class Module_Hunting extends BaseModule
{
    public function key(): string { return 'hunting'; }
    public function name(): string { return 'Advanced Hunting'; }
    public function description(): string { return 'Consultas programáticas KQL'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return ['ThreatHunting.Read.All'];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Hunting (KQL)',
            'url'   => base_url('modules/hunting'),
            'icon'  => 'search',
            'group' => 'Inteligencia',
        ];
    }

    /**
     * Consultas predefinidas para reportes periódicos.
     */
    public function getPresetQueries(): array
    {
        return [
            'top_alerts' => [
                'name'  => 'Top alertas por volumen',
                'query' => "AlertInfo
                    | where Timestamp >= ago(30d)
                    | summarize AlertCount = count() by Title, Severity
                    | top 20 by AlertCount",
            ],
            'device_exposure' => [
                'name'  => 'Equipos con mayor exposición',
                'query' => "DeviceInfo
                    | summarize arg_max(Timestamp, *) by DeviceId
                    | join kind=inner (
                        AlertInfo
                        | where Timestamp >= ago(7d)
                        | summarize AlertCount = count() by DeviceId
                    ) on DeviceId
                    | project DeviceName, OSPlatform, AlertCount
                    | top 20 by AlertCount",
            ],
            'identity_anomalies' => [
                'name'  => 'Anomalías de identidad',
                'query' => "IdentityLogonEvents
                    | where Timestamp >= ago(7d)
                    | where ActionType == 'LogonFailed'
                    | summarize FailedAttempts = count() by AccountUpn, IPAddress
                    | where FailedAttempts > 5
                    | top 20 by FailedAttempts",
            ],
            'email_threats' => [
                'name'  => 'Amenazas en email',
                'query' => "EmailEvents
                    | where Timestamp >= ago(7d)
                    | where ThreatTypes != ''
                    | summarize Count = count() by ThreatTypes, SenderFromAddress
                    | top 20 by Count",
            ],
            'process_anomalies' => [
                'name'  => 'Procesos sospechosos',
                'query' => "DeviceProcessEvents
                    | where Timestamp >= ago(7d)
                    | where ProcessCommandLine has_any ('powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32')
                    | summarize Count = count() by FileName, ProcessCommandLine, DeviceName
                    | top 20 by Count",
            ],
        ];
    }

    /**
     * Ejecuta una consulta KQL personalizada.
     */
    public function runQuery(int $tenantId, string $query, ?string $queryName = null, ?string $periodStart = null, ?string $periodEnd = null): array
    {
        $client = $this->getGraphClient($tenantId);
        $queryHash = md5($query);

        try {
            $result = $client->graphPost('security/runHuntingQuery', ['Query' => $query]);
            $results = $result['results'] ?? [];

            // Almacenar para histórico (composición de reportes mensuales/anuales)
            Database::insert(
                "INSERT INTO hunting_results (tenant_id, query_hash, query_text, query_name, results, row_count, period_start, period_end)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    $tenantId,
                    $queryHash,
                    $query,
                    $queryName ?? 'Custom query',
                    json_encode($results),
                    count($results),
                    $periodStart,
                    $periodEnd,
                ]
            );

            return ['success' => true, 'results' => $results, 'rowCount' => count($results)];

        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Sincroniza ejecutando todas las consultas predefinidas (para reportes periódicos).
     */
    public function sync(int $tenantId): array
    {
        $presets = $this->getPresetQueries();
        $totalRecords = 0;
        $errors = [];

        foreach ($presets as $key => $preset) {
            $result = $this->runQuery(
                $tenantId,
                $preset['query'],
                $preset['name'],
                gmdate('Y-m-d\T00:00:00\Z', time() - (30 * 86400)),
                gmdate('Y-m-d\T00:00:00\Z')
            );

            if ($result['success']) {
                $totalRecords += $result['rowCount'];
            } else {
                $errors[] = "{$preset['name']}: " . $result['error'];
            }
        }

        $this->logSync($tenantId, 'hunting', empty($errors) ? 'success' : 'partial', $totalRecords, implode('; ', $errors) ?: null);

        return ['success' => empty($errors), 'records' => $totalRecords, 'errors' => $errors];
    }

    /**
     * Obtiene resultados históricos de hunting almacenados.
     */
    public function getHistory(int $tenantId, ?string $queryHash = null, int $page = 1, int $perPage = 20): array
    {
        $where = ['tenant_id = ?'];
        $params = [$tenantId];

        if ($queryHash) {
            $where[] = 'query_hash = ?';
            $params[] = $queryHash;
        }

        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne("SELECT COUNT(*) as cnt FROM hunting_results WHERE $whereClause", $params)['cnt'];
        $params[] = $perPage;
        $params[] = $offset;

        $rows = Database::fetchAll(
            "SELECT id, query_hash, query_name, row_count, executed_at, period_start, period_end
             FROM hunting_results WHERE $whereClause ORDER BY executed_at DESC LIMIT ? OFFSET ?",
            $params
        );

        return ['data' => $rows, 'total' => $total, 'page' => $page, 'perPage' => $perPage, 'totalPages' => (int)ceil($total / $perPage)];
    }

    /**
     * Obtiene el resultado de una ejecución específica.
     */
    public function getResult(int $id): array
    {
        $row = Database::fetchOne("SELECT * FROM hunting_results WHERE id = ?", [$id]);
        if (!$row) return ['success' => false, 'error' => 'No encontrado'];
        $row['results'] = safe_json_decode($row['results'], []);
        return ['success' => true, 'data' => $row];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                       'handler' => [$this, 'index']],
            ['method' => 'POST', 'pattern' => 'run',                    'handler' => [$this, 'runCustomQuery']],
            ['method' => 'GET',  'pattern' => 'presets',                'handler' => [$this, 'listPresets']],
            ['method' => 'GET',  'pattern' => 'history',                'handler' => [$this, 'listHistory']],
            ['method' => 'GET',  'pattern' => 'result/{id}',            'handler' => [$this, 'showResult']],
            ['method' => 'POST', 'pattern' => 'sync/{tenantId}',        'handler' => [$this, 'triggerSync']],
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        echo $this->render('index', [
            'module' => $this, 'tenants' => $tenants,
            'selectedTenant' => $selectedTenant,
            'presets' => $this->getPresetQueries(),
        ]);
    }

    public function runCustomQuery(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $tenantId = (int)($input['tenant_id'] ?? 0);
        $query = $input['query'] ?? '';
        $queryName = $input['query_name'] ?? null;

        if (empty($query)) json_response(['success' => false, 'error' => 'Query vacío'], 400);

        json_response($this->runQuery($tenantId, $query, $queryName));
    }

    public function listPresets(array $params = []): void
    {
        json_response(['presets' => $this->getPresetQueries()]);
    }

    public function listHistory(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        json_response($this->getHistory($tenantId, $_GET['hash'] ?? null, (int)($_GET['page'] ?? 1)));
    }

    public function showResult(array $params = []): void
    {
        json_response($this->getResult((int)($params['id'] ?? 0)));
    }

    public function triggerSync(array $params = []): void
    {
        Csrf::validateOrFail();
        json_response($this->sync((int)($params['tenantId'] ?? 0)));
    }
}
