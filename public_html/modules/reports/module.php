<?php
/**
 * Módulo: Reportes
 * Genera reportes periódicos (diario, semanal, mensual, trimestral, anual)
 * componiendo datos almacenados de todos los módulos.
 */

declare(strict_types=1);

class Module_Reports extends BaseModule
{
    public function key(): string { return 'reports'; }
    public function name(): string { return 'Reportes'; }
    public function description(): string { return 'Generación de reportes periódicos'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return []; // No llama a Graph directamente, usa datos almacenados
    }

    public function isSyncable(): bool
    {
        return false; // No sincroniza, genera reportes bajo demanda
    }

    public function sync(int $tenantId): array
    {
        return ['success' => true, 'records' => 0];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Reportes',
            'url'   => base_url('modules/reports'),
            'icon'  => 'bar-chart-3',
            'group' => 'Análisis',
        ];
    }

    /**
     * Calcula el rango de fechas para un periodo.
     */
    public function getPeriodRange(string $periodType, ?string $referenceDate = null): array
    {
        $ref = $referenceDate ? strtotime($referenceDate) : time();

        return match ($periodType) {
            'daily' => [
                'start' => gmdate('Y-m-d\T00:00:00\Z', $ref - 86400),
                'end'   => gmdate('Y-m-d\T00:00:00\Z', $ref),
                'label' => 'Diario — ' . gmdate('d/m/Y', $ref - 86400),
            ],
            'weekly' => [
                'start' => gmdate('Y-m-d\T00:00:00\Z', $ref - (7 * 86400)),
                'end'   => gmdate('Y-m-d\T00:00:00\Z', $ref),
                'label' => 'Semanal — Semana del ' . gmdate('d/m/Y', $ref - (7 * 86400)),
            ],
            'monthly' => [
                'start' => gmdate('Y-m-01\T00:00:00\Z', $ref),
                'end'   => gmdate('Y-m-01\T00:00:00\Z', strtotime('+1 month', strtotime(gmdate('Y-m-01', $ref)))),
                'label' => 'Mensual — ' . gmdate('F Y', $ref),
            ],
            'quarterly' => [
                'start' => gmdate('Y-m-01\T00:00:00\Z', strtotime('first day of -' . (floor(gmdate('n', $ref) / 3) * 3) . ' months', strtotime(gmdate('Y-01-01', $ref)))),
                'end'   => gmdate('Y-m-01\T00:00:00\Z', strtotime('+3 months', strtotime(gmdate('Y-m-01\T00:00:00\Z', strtotime('first day of -' . (floor(gmdate('n', $ref) / 3) * 3) . ' months', strtotime(gmdate('Y-01-01', $ref))))))),
                'label' => 'Trimestral — Q' . (floor((gmdate('n', $ref) - 1) / 3) + 1) . ' ' . gmdate('Y', $ref),
            ],
            'yearly' => [
                'start' => gmdate('Y-01-01\T00:00:00\Z', $ref),
                'end'   => gmdate('Y-01-01\T00:00:00\Z', strtotime('+1 year', strtotime(gmdate('Y-01-01', $ref)))),
                'label' => 'Anual — ' . gmdate('Y', $ref),
            ],
            default => [
                'start' => gmdate('Y-m-d\T00:00:00\Z', $ref - (30 * 86400)),
                'end'   => gmdate('Y-m-d\T00:00:00\Z', $ref),
                'label' => 'Personalizado',
            ],
        };
    }

    /**
     * Genera un reporte completo para un tenant o grupo de tenants.
     */
    public function generateReport(int $tenantId, ?int $groupId, string $reportType, string $periodType, ?string $referenceDate = null): array
    {
        $range = $this->getPeriodRange($periodType, $referenceDate);
        $data = [];

        switch ($reportType) {
            case 'executive':
                $data = $this->buildExecutiveSummary($tenantId, $range);
                break;
            case 'incidents':
                $data = $this->buildIncidentsReport($tenantId, $range);
                break;
            case 'vulnerabilities':
                $data = $this->buildVulnerabilitiesReport($tenantId, $range);
                break;
            case 'threat_intel':
                $data = $this->buildThreatIntelReport($tenantId, $range);
                break;
            case 'secure_score':
                $data = $this->buildSecureScoreReport($tenantId, $range);
                break;
            case 'full':
            default:
                $data = array_merge(
                    $this->buildExecutiveSummary($tenantId, $range),
                    $this->buildIncidentsReport($tenantId, $range),
                    $this->buildVulnerabilitiesReport($tenantId, $range),
                    $this->buildThreatIntelReport($tenantId, $range),
                    $this->buildSecureScoreReport($tenantId, $range)
                );
                break;
        }

        $title = sprintf(
            'Reporte %s — %s — %s',
            ucfirst($reportType),
            TenantManager::getById($tenantId)['name'] ?? "Tenant $tenantId",
            $range['label']
        );

        $reportId = Database::insert(
            "INSERT INTO reports (tenant_id, group_id, report_type, period_type, period_start, period_end, title, data, generated_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                $tenantId,
                $groupId,
                $reportType,
                $periodType,
                $range['start'],
                $range['end'],
                $title,
                json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE),
                Auth::id(),
            ]
        );

        return [
            'success'   => true,
            'report_id' => $reportId,
            'title'     => $title,
            'period'    => $range,
            'data'      => $data,
        ];
    }

    // ============================================================
    // Constructores de secciones del reporte
    // ============================================================

    private function buildExecutiveSummary(int $tenantId, array $range): array
    {
        $stats = TenantManager::getStats($tenantId);

        $incidentsBySeverity = Database::fetchAll(
            "SELECT severity, COUNT(*) as cnt FROM incidents
             WHERE tenant_id = ? AND created_date BETWEEN ? AND ?
             GROUP BY severity",
            [$tenantId, $range['start'], $range['end']]
        );

        $latestScore = Database::fetchOne(
            "SELECT current_score, max_score FROM secure_scores
             WHERE tenant_id = ? ORDER BY score_date DESC LIMIT 1",
            [$tenantId]
        );

        $criticalVulns = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM vulnerabilities
             WHERE tenant_id = ? AND severity = 'Critical'",
            [$tenantId]
        )['cnt'];

        $exploitedVulns = (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM vulnerabilities
             WHERE tenant_id = ? AND public_exploit = 1",
            [$tenantId]
        )['cnt'];

        return [
            'executive' => [
                'totalIncidents'      => $stats['incidents'],
                'totalAlerts'         => $stats['alerts'],
                'totalIocs'           => $stats['iocs'],
                'totalMachines'       => $stats['machines'],
                'totalVulnerabilities'=> $stats['vulnerabilities'],
                'criticalVulns'       => $criticalVulns,
                'exploitedVulns'      => $exploitedVulns,
                'secureScore'         => $latestScore ? round($latestScore['current_score'] * 100 / max(1, $latestScore['max_score']), 1) : null,
                'incidentsBySeverity' => $incidentsBySeverity,
            ],
        ];
    }

    private function buildIncidentsReport(int $tenantId, array $range): array
    {
        $incidents = Database::fetchAll(
            "SELECT severity, status, COUNT(*) as cnt FROM incidents
             WHERE tenant_id = ? AND created_date BETWEEN ? AND ?
             GROUP BY severity, status ORDER BY cnt DESC",
            [$tenantId, $range['start'], $range['end']]
        );

        $topIncidents = Database::fetchAll(
            "SELECT i.display_name, i.severity, i.status, i.created_date, COUNT(a.id) as alert_count
             FROM incidents i
             LEFT JOIN alerts a ON i.id = a.incident_id AND a.tenant_id = i.tenant_id
             WHERE i.tenant_id = ? AND i.created_date BETWEEN ? AND ?
             GROUP BY i.id ORDER BY i.severity DESC, alert_count DESC LIMIT 10",
            [$tenantId, $range['start'], $range['end']]
        );

        $alertsByService = Database::fetchAll(
            "SELECT service_source, COUNT(*) as cnt FROM alerts
             WHERE tenant_id = ? AND last_activity BETWEEN ? AND ?
             GROUP BY service_source ORDER BY cnt DESC",
            [$tenantId, $range['start'], $range['end']]
        );

        return [
            'incidents' => [
                'bySeverityStatus' => $incidents,
                'topIncidents'     => $topIncidents,
                'alertsByService'  => $alertsByService,
            ],
        ];
    }

    private function buildVulnerabilitiesReport(int $tenantId, array $range): array
    {
        $bySeverity = Database::fetchAll(
            "SELECT severity, COUNT(*) as cnt, COUNT(DISTINCT machine_id) as machines
             FROM vulnerabilities WHERE tenant_id = ? GROUP BY severity
             ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END",
            [$tenantId]
        );

        $topCves = Database::fetchAll(
            "SELECT cve_id, COUNT(DISTINCT machine_id) as affected, MAX(cvss_v3) as max_cvss, public_exploit, exploit_verified, epss
             FROM vulnerabilities WHERE tenant_id = ? GROUP BY cve_id
             ORDER BY affected DESC, max_cvss DESC LIMIT 15",
            [$tenantId]
        );

        $exposedMachines = Database::fetchAll(
            "SELECT m.computer_dns_name, m.os_platform, m.exposure_level,
                    COUNT(v.id) as vuln_count,
                    SUM(CASE WHEN v.severity = 'Critical' THEN 1 ELSE 0 END) as critical_count
             FROM machines m
             LEFT JOIN vulnerabilities v ON m.id = v.machine_id AND m.tenant_id = v.tenant_id
             WHERE m.tenant_id = ?
             GROUP BY m.id ORDER BY critical_count DESC, vuln_count DESC LIMIT 10",
            [$tenantId]
        );

        return [
            'vulnerabilities' => [
                'bySeverity'     => $bySeverity,
                'topCves'        => $topCves,
                'exposedMachines'=> $exposedMachines,
            ],
        ];
    }

    private function buildThreatIntelReport(int $tenantId, array $range): array
    {
        $articles = Database::fetchAll(
            "SELECT title, created_date, last_updated, tags FROM ti_articles
             WHERE tenant_id = ? AND created_date BETWEEN ? AND ?
             ORDER BY created_date DESC LIMIT 20",
            [$tenantId, $range['start'], $range['end']]
        );

        $iocsByType = Database::fetchAll(
            "SELECT ioc_type, COUNT(*) as cnt FROM ti_iocs
             WHERE tenant_id = ? AND fetched_at BETWEEN ? AND ?
             GROUP BY ioc_type ORDER BY cnt DESC",
            [$tenantId, $range['start'], $range['end']]
        );

        $recentIocs = Database::fetchAll(
            "SELECT ioc_type, ioc_value, source, severity, fetched_at FROM ti_iocs
             WHERE tenant_id = ? AND fetched_at BETWEEN ? AND ?
             ORDER BY fetched_at DESC LIMIT 50",
            [$tenantId, $range['start'], $range['end']]
        );

        return [
            'threatIntel' => [
                'articles'   => $articles,
                'iocsByType' => $iocsByType,
                'recentIocs' => $recentIocs,
            ],
        ];
    }

    private function buildSecureScoreReport(int $tenantId, array $range): array
    {
        $trend = Database::fetchAll(
            "SELECT score_date, current_score, max_score,
                    ROUND(current_score * 100.0 / NULLIF(max_score, 0), 1) as percentage
             FROM secure_scores
             WHERE tenant_id = ? AND score_date BETWEEN ? AND ?
             ORDER BY score_date ASC",
            [$tenantId, $range['start'], $range['end']]
        );

        return [
            'secureScore' => ['trend' => $trend],
        ];
    }

    /**
     * Obtiene reportes generados.
     */
    public function getReports(int $tenantId = 0, int $page = 1, int $perPage = 20): array
    {
        // La consulta hace JOIN con tenants (que también tiene columna tenant_id),
        // así que hay que cualificar con "r." para evitar "ambiguous column name".
        $where = $tenantId ? 'WHERE r.tenant_id = ?' : '';
        $params = $tenantId ? [$tenantId] : [];
        $offset = ($page - 1) * $perPage;

        $total = (int)Database::fetchOne("SELECT COUNT(*) as cnt FROM reports r $where", $params)['cnt'];
        $params[] = $perPage;
        $params[] = $offset;

        $reports = Database::fetchAll(
            "SELECT r.*, t.name as tenant_name, u.username as generated_by_name
             FROM reports r
             LEFT JOIN tenants t ON r.tenant_id = t.id
             LEFT JOIN users u ON r.generated_by = u.id
             $where
             ORDER BY r.generated_at DESC LIMIT ? OFFSET ?",
            $params
        );

        return ['data' => $reports, 'total' => $total, 'page' => $page, 'perPage' => $perPage, 'totalPages' => (int)ceil($total / $perPage)];
    }

    /**
     * Obtiene un reporte por ID.
     */
    public function getReport(int $id): ?array
    {
        $report = Database::fetchOne("SELECT * FROM reports WHERE id = ?", [$id]);
        if (!$report) return null;
        $report['data'] = safe_json_decode($report['data'], []);
        return $report;
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                       'handler' => [$this, 'index']],
            ['method' => 'POST', 'pattern' => 'generate',               'handler' => [$this, 'generate']],
            ['method' => 'GET',  'pattern' => 'list',                   'handler' => [$this, 'listReports']],
            ['method' => 'GET',  'pattern' => 'view/{id}',              'handler' => [$this, 'viewReport']],
            ['method' => 'GET',  'pattern' => 'periods',                'handler' => [$this, 'getPeriods']],
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $groups = TenantManager::getGroups();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $reports = $this->getReports($selectedTenant);

        echo $this->page('index', [
            'module' => $this, 'tenants' => $tenants, 'groups' => $groups,
            'selectedTenant' => $selectedTenant, 'reports' => $reports,
        ]);
    }

    public function generate(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

        try {
            $result = $this->generateReport(
                (int)($input['tenant_id'] ?? 0),
                !empty($input['group_id']) ? (int)$input['group_id'] : null,
                $input['report_type'] ?? 'full',
                $input['period_type'] ?? 'monthly',
                $input['reference_date'] ?? null
            );
        } catch (Throwable $e) {
            log_activity('report.generate_error', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()]);
        }

        json_response($result);
    }

    public function listReports(array $params = []): void
    {
        json_response($this->getReports((int)($_GET['tenant'] ?? 0), (int)($_GET['page'] ?? 1)));
    }

    public function viewReport(array $params = []): void
    {
        $report = $this->getReport((int)($params['id'] ?? 0));
        if (!$report) {
            http_response_code(404);
            echo $this->page('error', ['module' => $this, 'message' => 'Reporte no encontrado']);
            return;
        }
        echo $this->page('view', ['module' => $this, 'report' => $report]);
    }

    public function getPeriods(array $params = []): void
    {
        $types = ['daily', 'weekly', 'monthly', 'quarterly', 'yearly'];
        $periods = [];
        foreach ($types as $type) {
            $range = $this->getPeriodRange($type);
            $periods[$type] = $range['label'];
        }
        json_response(['periods' => $periods]);
    }
}
