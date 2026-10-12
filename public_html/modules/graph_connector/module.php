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
        return [
            'label' => 'Conexión Graph',
            'url'   => base_url('modules/graph_connector'),
            'icon'  => 'plug',
            'group' => 'Configuración',
        ];
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
            return [
                'success' => true,
                'data' => [
                    'displayName'      => $value['displayName'] ?? 'N/A',
                    'id'               => $value['id'] ?? 'N/A',
                    'verifiedDomains'  => array_column($value['verifiedDomains'] ?? [], 'name'),
                    'createdDateTime'  => $value['createdDateTime'] ?? null,
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
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getAll();
        $data = ['module' => $this, 'tenants' => $tenants];
        echo $this->page('index', $data);
    }

    public function testConnection(array $params = []): void
    {
        Csrf::validateOrFail();
        $tenantId = (int)($params['id'] ?? 0);
        $result = $this->testTenantConnection($tenantId);
        json_response($result);
    }

    public function showOrganization(array $params = []): void
    {
        $tenantId = (int)($params['id'] ?? 0);
        $result = $this->getOrganizationInfo($tenantId);
        json_response($result);
    }

    public function syncAllModules(array $params = []): void
    {
        Csrf::validateOrFail();
        $tenantId = (int)($params['id'] ?? 0);
        $results = ModuleManager::syncAll($tenantId);
        json_response(['success' => true, 'results' => $results]);
    }
}
