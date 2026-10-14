<?php
/**
 * Módulo: Graph Connector
 * Gestión de conexión con Microsoft Graph. No sincroniza datos,
 * proporciona la infraestructura de conexión para otros módulos.
 */

declare(strict_types=1);

class Module_GraphConnector extends BaseModule
{
    public function key(): string { return 'graph_connector'; }
    public function name(): string { return 'Graph Connector'; }
    public function description(): string { return 'Conexión y gestión de tenants de Microsoft Graph'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        // Este módulo no requiere permisos específicos, solo conectividad
        return [];
    }

    public function isSyncable(): bool
    {
        // No sincroniza datos, solo gestiona la conexión
        return false;
    }

    public function sync(int $tenantId): array
    {
        return ['success' => true, 'records' => 0, 'message' => 'Módulo de infraestructura, no requiere sincronización'];
    }

    public function getNavItem(): ?array
    {
        // Se muestra como enlace dentro de "Administración" en el sidebar (solo admin).
        return null;
    }

    /**
     * Prueba la conexión con un tenant específico.
     */
    public function testTenantConnection(int $tenantId): array
    {
        try {
            $client = $this->getGraphClient($tenantId);
            return $client->testConnection();
        } catch (Throwable $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    /**
     * Obtiene información del tenant desde Graph (organización).
     */
    public function getOrganizationInfo(int $tenantId): array
    {
        try {
            $client = $this->getGraphClient($tenantId);
            $org = $client->graphGet('organization');
            $value = $org['value'][0] ?? [];

            $industry = isset($value['industry']) && $value['industry'] !== '' ? (string)$value['industry'] : null;
            $country  = isset($value['countryLetterCode']) && $value['countryLetterCode'] !== '' ? (string)$value['countryLetterCode'] : null;

            // Persistir el sector/país detectados en el tenant
            TenantManager::updateOrgInfo($tenantId, $industry, $country);

            return [
                'success' => true,
                'data' => [
                    'displayName'     => $value['displayName'] ?? 'N/A',
                    'id'              => $value['id'] ?? 'N/A',
                    'industry'        => $industry,
                    'country'         => $country,
                    'tenantType'      => $value['tenantType'] ?? null,
                    'verifiedDomains' => array_column($value['verifiedDomains'] ?? [], 'name'),
                    'createdDateTime' => $value['createdDateTime'] ?? null,
                ],
            ];
        } catch (Throwable $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                          'handler' => [$this, 'index']],
            ['method' => 'POST', 'pattern' => 'test/{id}',                 'handler' => [$this, 'testConnection']],
            ['method' => 'GET',  'pattern' => 'org/{id}',                  'handler' => [$this, 'showOrganization']],
            ['method' => 'POST', 'pattern' => 'sync-all/{id}',            'handler' => [$this, 'syncAllModules']],
            ['method' => 'POST', 'pattern' => 'diagnose/{id}',            'handler' => [$this, 'diagnoseEndpoint']],
        ];
    }

    public function index(array $params = []): void
    {
        Auth::requireAdmin();
        $tenants = TenantManager::getAll();
        $data = ['module' => $this, 'tenants' => $tenants];
        echo $this->page('index', $data);
    }

    public function testConnection(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();
        release_session_lock();
        $tenantId = (int)($params['id'] ?? 0);
        $result = $this->testTenantConnection($tenantId);
        json_response($result);
    }

    public function showOrganization(array $params = []): void
    {
        Auth::requireAdmin();
        release_session_lock();
        $tenantId = (int)($params['id'] ?? 0);
        $result = $this->getOrganizationInfo($tenantId);
        json_response($result);
    }

    public function syncAllModules(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();
        release_session_lock();
        $tenantId = (int)($params['id'] ?? 0);
        $results = ModuleManager::syncAll($tenantId);
        json_response(['success' => true, 'results' => $results]);
    }

    /**
     * Diagnóstico de conexión + permisos reales del tenant.
     * Comprueba un endpoint representativo por permiso (Graph y Defender).
     */
    public function diagnose(int $tenantId): array
    {
        $tenant = TenantManager::getById($tenantId);
        if (!$tenant) {
            return ['success' => false, 'error' => 'Tenant no encontrado'];
        }

        try {
            $client = $this->getGraphClient($tenantId);
        } catch (Throwable $e) {
            return ['success' => false, 'error' => 'No se pudo preparar el cliente: ' . $e->getMessage()];
        }

        $token = $client->testConnection();

        // permiso => [scope, método, endpoint, params]
        $probes = [
            ['Organization.Read.All',       'Graph', 'GET', 'organization',                              []],
            ['ThreatIntelligence.Read.All', 'Graph', 'GET', 'security/threatIntelligence/articles',      ['$top' => 1]],
            ['SecurityIncident.Read.All',   'Graph', 'GET', 'security/incidents',                        ['$top' => 1]],
            ['SecurityAlert.Read.All',      'Graph', 'GET', 'security/alerts_v2',                        ['$top' => 1]],
            ['SecurityEvents.Read.All',     'Graph', 'GET', 'security/secureScores',                     ['$top' => 1]],
            ['Machine.Read.All',            'MDE',   'GET', 'api/machines',                              ['$top' => 1]],
            ['Vulnerability.Read.All',      'MDE',   'GET', 'api/vulnerabilities/machinesVulnerabilities', ['$top' => 1]],
            ['Software.Read.All',           'MDE',   'GET', 'api/software',                              ['$top' => 1]],
        ];

        $checks = [];
        foreach ($probes as [$perm, $scope, $method, $path, $params]) {
            if (empty($token['success'])) {
                $checks[] = ['permission' => $perm, 'scope' => $scope, 'ok' => false, 'http' => 0, 'message' => 'Sin token', 'count' => null];
                continue;
            }
            $res = $client->probe($method, $path, $params, $scope === 'MDE');
            $checks[] = [
                'permission' => $perm,
                'scope'      => $scope,
                'ok'         => (bool)$res['ok'],
                'http'       => (int)$res['http'],
                'message'    => (string)$res['message'],
                'count'      => $res['count'] ?? null,
            ];
        }

        $lastSync = Database::fetchOne(
            "SELECT module_key, status, records_processed, error_message, completed_at
             FROM sync_log WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
            [$tenantId]
        );

        $okCount = count(array_filter($checks, fn($c) => $c['ok']));

        return [
            'success'  => true,
            'tenant'   => ['id' => $tenantId, 'name' => $tenant['name']],
            'token'    => $token,
            'checks'   => $checks,
            'summary'  => ['ok' => $okCount, 'total' => count($checks), 'missing' => count($checks) - $okCount],
            'last_sync'=> $lastSync,
        ];
    }

    public function diagnoseEndpoint(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();
        release_session_lock();
        json_response($this->diagnose((int)($params['id'] ?? 0)));
    }
}
