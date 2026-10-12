<?php
/**
 * Módulo: Incidentes y Alertas
 * Extrae incidentes y alertas de Defender XDR.
 * Permisos: SecurityIncident.Read.All, SecurityAlert.Read.All
 */

declare(strict_types=1);

class Module_Incidents extends BaseModule
{
    public function key(): string { return 'incidents'; }
    public function name(): string { return 'Incidentes y Alertas'; }
    public function description(): string { return 'Incidentes y alertas de Defender XDR'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return ['SecurityIncident.Read.All', 'SecurityAlert.Read.All'];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Incidentes',
            'url'   => base_url('modules/incidents'),
            'icon'  => 'alert-triangle',
            'group' => 'Seguridad',
        ];
    }

    public function sync(int $tenantId): array
    {
        $client = $this->getGraphClient($tenantId);
        $recordCount = 0;
        $errors = [];

        try {
            // Sincronizar incidentes de los últimos 30 días
            $since = gmdate('Y-m-d\T00:00:00\Z', time() - (30 * 86400));
            $incidents = $client->graphGetAll('security/incidents', [
                '$filter' => "createdDateTime ge $since",
                '$expand' => 'alerts',
                '$count'  => 'true',
            ]);

            foreach ($incidents as $incident) {
                try {
                    $incidentDbId = Database::insert(
                        "INSERT OR REPLACE INTO incidents
                         (tenant_id, incident_id, display_name, severity, status, classification, determination,
                          assigned_to, created_date, last_update_date, recommended_actions, custom_tags, raw_data, fetched_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                        [
                            $tenantId,
                            $incident['id'],
                            $incident['displayName'] ?? 'Sin título',
                            $incident['severity'] ?? null,
                            $incident['status'] ?? null,
                            $incident['classification'] ?? null,
                            $incident['determination'] ?? null,
                            $incident['assignedTo'] ?? null,
                            $incident['createdDateTime'] ?? null,
                            $incident['lastUpdateDateTime'] ?? null,
                            $incident['recommendedActions'] ?? null,
                            json_encode($incident['customTags'] ?? []),
                            json_encode($incident),
                        ]
                    );
                    $recordCount++;

                    // Guardar alertas asociadas
                    foreach ($incident['alerts'] ?? [] as $alert) {
                        Database::insert(
                            "INSERT OR REPLACE INTO alerts
                             (tenant_id, alert_id, incident_id, title, threat_display_name, threat_family_name,
                              category, severity, status, service_source, detection_source, mitre_techniques,
                              first_activity, last_activity, raw_data, fetched_at)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                            [
                                $tenantId,
                                $alert['id'],
                                $incidentDbId,
                                $alert['title'] ?? 'Sin título',
                                $alert['threatDisplayName'] ?? null,
                                $alert['threatFamilyName'] ?? null,
                                $alert['category'] ?? null,
                                $alert['severity'] ?? null,
                                $alert['status'] ?? null,
                                $alert['serviceSource'] ?? null,
                                $alert['detectionSource'] ?? null,
                                json_encode($alert['mitreTechniques'] ?? []),
                                $alert['firstActivityDateTime'] ?? null,
                                $alert['lastActivityDateTime'] ?? null,
                                json_encode($alert),
                            ]
                        );
                        $recordCount++;
                    }

                } catch (Throwable $e) {
                    $errors[] = "Incidente {$incident['id']}: " . $e->getMessage();
                }
            }

            $this->logSync($tenantId, 'incidents', empty($errors) ? 'success' : 'partial', $recordCount, implode('; ', $errors) ?: null);

            return [
                'success' => empty($errors),
                'records' => $recordCount,
                'errors'  => $errors,
            ];

        } catch (Throwable $e) {
            $this->logSync($tenantId, 'incidents', 'error', $recordCount, $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Obtiene incidentes con filtros y paginación.
     */
    public function getIncidents(int $tenantId, array $filters = [], int $page = 1, int $perPage = 20): array
    {
        // OJO: la consulta hace JOIN con alerts, que también tiene tenant_id,
        // severity, status y created_date → hay que cualificar con "i."
        $where = ['i.tenant_id = ?'];
        $params = [$tenantId];

        if (!empty($filters['severity'])) {
            $where[] = 'i.severity = ?';
            $params[] = $filters['severity'];
        }
        if (!empty($filters['status'])) {
            $where[] = 'i.status = ?';
            $params[] = $filters['status'];
        }
        if (!empty($filters['date_from'])) {
            $where[] = 'i.created_date >= ?';
            $params[] = $filters['date_from'];
        }
        if (!empty($filters['date_to'])) {
            $where[] = 'i.created_date <= ?';
            $params[] = $filters['date_to'];
        }

        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne("SELECT COUNT(*) as cnt FROM incidents i WHERE $whereClause", $params)['cnt'];

        $params[] = $perPage;
        $params[] = $offset;

        $incidents = Database::fetchAll(
            "SELECT i.*, COUNT(a.id) as alert_count
             FROM incidents i
             LEFT JOIN alerts a ON i.id = a.incident_id AND a.tenant_id = i.tenant_id
             WHERE $whereClause
             GROUP BY i.id
             ORDER BY i.created_date DESC
             LIMIT ? OFFSET ?",
            $params
        );

        return [
            'data' => $incidents, 'total' => $total, 'page' => $page,
            'perPage' => $perPage, 'totalPages' => (int)ceil($total / $perPage),
        ];
    }

    /**
     * Obtiene alertas con filtros.
     */
    public function getAlerts(int $tenantId, array $filters = [], int $page = 1, int $perPage = 50): array
    {
        $where = ['tenant_id = ?'];
        $params = [$tenantId];

        if (!empty($filters['severity'])) {
            $where[] = 'severity = ?';
            $params[] = $filters['severity'];
        }
        if (!empty($filters['service'])) {
            $where[] = 'service_source = ?';
            $params[] = $filters['service'];
        }

        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne("SELECT COUNT(*) as cnt FROM alerts WHERE $whereClause", $params)['cnt'];
        $params[] = $perPage;
        $params[] = $offset;

        $alerts = Database::fetchAll(
            "SELECT * FROM alerts WHERE $whereClause ORDER BY last_activity DESC LIMIT ? OFFSET ?",
            $params
        );

        return ['data' => $alerts, 'total' => $total, 'page' => $page, 'perPage' => $perPage, 'totalPages' => (int)ceil($total / $perPage)];
    }

    /**
     * Estadísticas de incidentes por severidad.
     */
    public function getSeverityStats(int $tenantId, string $period = '30d'): array
    {
        $days = match ($period) {
            '7d'  => 7,
            '90d' => 90,
            '365d'=> 365,
            default => 30,
        };
        $since = gmdate('Y-m-d', time() - ($days * 86400));

        return Database::fetchAll(
            "SELECT severity, status, COUNT(*) as cnt
             FROM incidents
             WHERE tenant_id = ? AND created_date >= ?
             GROUP BY severity, status
             ORDER BY cnt DESC",
            [$tenantId, $since]
        );
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                       'handler' => [$this, 'index']],
            ['method' => 'GET',  'pattern' => 'list',                   'handler' => [$this, 'listIncidents']],
            ['method' => 'GET',  'pattern' => 'alerts',                 'handler' => [$this, 'listAlerts']],
            ['method' => 'GET',  'pattern' => 'stats',                  'handler' => [$this, 'getStats']],
            ['method' => 'GET',  'pattern' => 'incident/{id}',          'handler' => [$this, 'showIncident']],
            ['method' => 'POST', 'pattern' => 'sync/{tenantId}',        'handler' => [$this, 'triggerSync']],
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));

        echo $this->page('index', [
            'module' => $this, 'tenants' => $tenants,
            'selectedTenant' => $selectedTenant,
        ]);
    }

    public function listIncidents(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        $filters = [
            'severity'  => $_GET['severity'] ?? '',
            'status'    => $_GET['status'] ?? '',
            'date_from' => $_GET['from'] ?? '',
            'date_to'   => $_GET['to'] ?? '',
        ];
        json_response($this->getIncidents($tenantId, $filters, (int)($_GET['page'] ?? 1)));
    }

    public function listAlerts(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        $filters = [
            'severity' => $_GET['severity'] ?? '',
            'service'  => $_GET['service'] ?? '',
        ];
        json_response($this->getAlerts($tenantId, $filters, (int)($_GET['page'] ?? 1)));
    }

    public function getStats(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        $period = $_GET['period'] ?? '30d';
        json_response(['stats' => $this->getSeverityStats($tenantId, $period)]);
    }

    public function showIncident(array $params = []): void
    {
        $id = (int)($params['id'] ?? 0);
        $incident = Database::fetchOne("SELECT * FROM incidents WHERE id = ?", [$id]);
        $alerts = Database::fetchAll("SELECT * FROM alerts WHERE incident_id = ?", [$id]);
        json_response(['incident' => $incident, 'alerts' => $alerts]);
    }

    public function triggerSync(array $params = []): void
    {
        Csrf::validateOrFail();
        json_response($this->sync((int)($params['tenantId'] ?? 0)));
    }
}
