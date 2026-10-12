<?php
/**
 * Módulo: Vulnerabilidades (TVM)
 * Extrae inventario de equipos y vulnerabilidades de Defender for Endpoint.
 * Permisos: Machine.Read.All, Vulnerability.Read.All
 * Audience: https://api.securitycenter.microsoft.com/.default
 */

declare(strict_types=1);

class Module_Vulnerabilities extends BaseModule
{
    public function key(): string { return 'vulnerabilities'; }
    public function name(): string { return 'Vulnerabilidades'; }
    public function description(): string { return 'Vulnerabilidades de equipos y software (TVM)'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return ['Machine.Read.All', 'Vulnerability.Read.All'];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Vulnerabilidades',
            'url'   => base_url('modules/vulnerabilities'),
            'icon'  => 'bug',
            'group' => 'Seguridad',
        ];
    }

    public function sync(int $tenantId): array
    {
        $client = $this->getGraphClient($tenantId);
        $recordCount = 0;
        $errors = [];

        try {
            // 1. Sincronizar inventario de equipos
            $machines = $client->mdeGetAll('api/machines', ['$top' => 10000]);

            foreach ($machines as $machine) {
                try {
                    Database::insert(
                        "INSERT OR REPLACE INTO machines
                         (tenant_id, machine_id, computer_dns_name, os_platform, os_version, health_status,
                          risk_score, exposure_level, last_seen, last_ip_address, machine_tags, rbac_group_id, aad_device_id, raw_data, fetched_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                        [
                            $tenantId,
                            $machine['id'],
                            $machine['computerDnsName'] ?? null,
                            $machine['osPlatform'] ?? null,
                            $machine['osVersion'] ?? null,
                            $machine['healthStatus'] ?? null,
                            $machine['riskScore'] ?? null,
                            $machine['exposureLevel'] ?? null,
                            $machine['lastSeen'] ?? null,
                            $machine['lastIpAddress'] ?? null,
                            json_encode($machine['machineTags'] ?? []),
                            $machine['rbacGroupId'] ?? null,
                            $machine['aadDeviceId'] ?? null,
                            json_encode($machine),
                        ]
                    );
                    $recordCount++;
                } catch (Throwable $e) {
                    $errors[] = "Máquina {$machine['id']}: " . $e->getMessage();
                }
            }

            // 2. Sincronizar vulnerabilidades por equipo
            $vulns = $client->mdeGetAll('api/vulnerabilities/machinesVulnerabilities', ['$top' => 10000]);

            foreach ($vulns as $vuln) {
                try {
                    $machineDbId = Database::fetchOne(
                        "SELECT id FROM machines WHERE tenant_id = ? AND machine_id = ?",
                        [$tenantId, $vuln['machineId']]
                    )['id'] ?? null;

                    Database::insert(
                        "INSERT OR REPLACE INTO vulnerabilities
                         (tenant_id, machine_id, cve_id, product_name, product_vendor, product_version,
                          severity, cvss_v3, fixing_kb_id, published_on, updated_on, public_exploit, exploit_verified, epss, exposed_machines, raw_data, fetched_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                        [
                            $tenantId,
                            $machineDbId,
                            $vuln['cveId'],
                            $vuln['productName'] ?? null,
                            $vuln['productVendor'] ?? null,
                            $vuln['productVersion'] ?? null,
                            $vuln['severity'] ?? null,
                            $vuln['cvssV3'] ?? null,
                            $vuln['fixingKbId'] ?? null,
                            $vuln['publishedOn'] ?? null,
                            $vuln['updatedOn'] ?? null,
                            !empty($vuln['publicExploit']) ? 1 : 0,
                            !empty($vuln['exploitVerified']) ? 1 : 0,
                            $vuln['epss'] ?? null,
                            $vuln['exposedMachines'] ?? null,
                            json_encode($vuln),
                        ]
                    );
                    $recordCount++;
                } catch (Throwable $e) {
                    $errors[] = "CVE {$vuln['cveId']}: " . $e->getMessage();
                }
            }

            $this->logSync($tenantId, 'vulnerabilities', empty($errors) ? 'success' : 'partial', $recordCount, implode('; ', $errors) ?: null);

            return ['success' => empty($errors), 'records' => $recordCount, 'errors' => $errors];

        } catch (Throwable $e) {
            $this->logSync($tenantId, 'vulnerabilities', 'error', $recordCount, $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Obtiene vulnerabilidades con filtros.
     */
    public function getVulnerabilities(int $tenantId, array $filters = [], int $page = 1, int $perPage = 50): array
    {
        $where = ['v.tenant_id = ?'];
        $params = [$tenantId];

        if (!empty($filters['severity'])) {
            $where[] = 'v.severity = ?';
            $params[] = $filters['severity'];
        }
        if (!empty($filters['cve'])) {
            $where[] = 'v.cve_id LIKE ?';
            $params[] = '%' . $filters['cve'] . '%';
        }
        if (!empty($filters['exploited'])) {
            $where[] = 'v.public_exploit = 1';
        }
        if (!empty($filters['machine'])) {
            $where[] = 'm.computer_dns_name LIKE ?';
            $params[] = '%' . $filters['machine'] . '%';
        }

        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM vulnerabilities v LEFT JOIN machines m ON v.machine_id = m.id WHERE $whereClause",
            $params
        )['cnt'];

        $params[] = $perPage;
        $params[] = $offset;

        $vulns = Database::fetchAll(
            "SELECT v.*, m.computer_dns_name, m.os_platform
             FROM vulnerabilities v
             LEFT JOIN machines m ON v.machine_id = m.id AND v.tenant_id = m.tenant_id
             WHERE $whereClause
             ORDER BY v.cvss_v3 DESC, v.severity DESC
             LIMIT ? OFFSET ?",
            $params
        );

        return ['data' => $vulns, 'total' => $total, 'page' => $page, 'perPage' => $perPage, 'totalPages' => (int)ceil($total / $perPage)];
    }

    /**
     * Obtiene equipos con filtros.
     */
    public function getMachines(int $tenantId, array $filters = [], int $page = 1, int $perPage = 50): array
    {
        $where = ['tenant_id = ?'];
        $params = [$tenantId];

        if (!empty($filters['health'])) {
            $where[] = 'health_status = ?';
            $params[] = $filters['health'];
        }
        if (!empty($filters['exposure'])) {
            $where[] = 'exposure_level = ?';
            $params[] = $filters['exposure'];
        }
        if (!empty($filters['search'])) {
            $where[] = 'computer_dns_name LIKE ?';
            $params[] = '%' . $filters['search'] . '%';
        }

        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne("SELECT COUNT(*) as cnt FROM machines WHERE $whereClause", $params)['cnt'];
        $params[] = $perPage;
        $params[] = $offset;

        $machines = Database::fetchAll(
            "SELECT m.*, COUNT(v.id) as vuln_count,
                    SUM(CASE WHEN v.severity = 'Critical' THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN v.severity = 'High' THEN 1 ELSE 0 END) as high_count
             FROM machines m
             LEFT JOIN vulnerabilities v ON m.id = v.machine_id AND m.tenant_id = v.tenant_id
             WHERE $whereClause
             GROUP BY m.id
             ORDER BY critical_count DESC, high_count DESC
             LIMIT ? OFFSET ?",
            $params
        );

        return ['data' => $machines, 'total' => $total, 'page' => $page, 'perPage' => $perPage, 'totalPages' => (int)ceil($total / $perPage)];
    }

    /**
     * Estadísticas de vulnerabilidades.
     */
    public function getVulnStats(int $tenantId): array
    {
        $bySeverity = Database::fetchAll(
            "SELECT severity, COUNT(*) as cnt, COUNT(DISTINCT machine_id) as machines_affected
             FROM vulnerabilities WHERE tenant_id = ? GROUP BY severity ORDER BY
             CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END",
            [$tenantId]
        );

        $topCves = Database::fetchAll(
            "SELECT cve_id, COUNT(DISTINCT machine_id) as affected_machines, MAX(cvss_v3) as max_cvss, public_exploit
             FROM vulnerabilities WHERE tenant_id = ? GROUP BY cve_id ORDER BY affected_machines DESC LIMIT 10",
            [$tenantId]
        );

        $exploited = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM vulnerabilities WHERE tenant_id = ? AND public_exploit = 1",
            [$tenantId]
        )['cnt'];

        return [
            'bySeverity' => $bySeverity,
            'topCves'    => $topCves,
            'exploited'  => $exploited,
        ];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                       'handler' => [$this, 'index']],
            ['method' => 'GET',  'pattern' => 'list',                   'handler' => [$this, 'listVulns']],
            ['method' => 'GET',  'pattern' => 'machines',               'handler' => [$this, 'listMachines']],
            ['method' => 'GET',  'pattern' => 'stats',                  'handler' => [$this, 'getStats']],
            ['method' => 'POST', 'pattern' => 'sync/{tenantId}',        'handler' => [$this, 'triggerSync']],
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        echo $this->render('index', ['module' => $this, 'tenants' => $tenants, 'selectedTenant' => $selectedTenant]);
    }

    public function listVulns(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        $filters = [
            'severity'  => $_GET['severity'] ?? '',
            'cve'       => $_GET['cve'] ?? '',
            'exploited' => !empty($_GET['exploited']),
            'machine'   => $_GET['machine'] ?? '',
        ];
        json_response($this->getVulnerabilities($tenantId, $filters, (int)($_GET['page'] ?? 1)));
    }

    public function listMachines(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        $filters = [
            'health'   => $_GET['health'] ?? '',
            'exposure' => $_GET['exposure'] ?? '',
            'search'   => $_GET['search'] ?? '',
        ];
        json_response($this->getMachines($tenantId, $filters, (int)($_GET['page'] ?? 1)));
    }

    public function getStats(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        json_response(['stats' => $this->getVulnStats($tenantId)]);
    }

    public function triggerSync(array $params = []): void
    {
        Csrf::validateOrFail();
        json_response($this->sync((int)($params['tenantId'] ?? 0)));
    }
}
