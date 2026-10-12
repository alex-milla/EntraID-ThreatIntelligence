<?php
/**
 * Módulo: Secure Score
 * Extrae la evolución del Secure Score de Microsoft 365.
 * Permiso: SecurityEvents.Read.All
 */

declare(strict_types=1);

class Module_SecureScore extends BaseModule
{
    public function key(): string { return 'secure_score'; }
    public function name(): string { return 'Secure Score'; }
    public function description(): string { return 'Evolución de la postura de seguridad'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return ['SecurityEvents.Read.All'];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Secure Score',
            'url'   => base_url('modules/secure_score'),
            'icon'  => 'gauge',
            'group' => 'Seguridad',
        ];
    }

    public function sync(int $tenantId): array
    {
        $client = $this->getGraphClient($tenantId);

        try {
            $scores = $client->graphGetAll('security/secureScores');
            $recordCount = 0;

            foreach ($scores as $score) {
                Database::insert(
                    "INSERT OR REPLACE INTO secure_scores
                     (tenant_id, score_date, current_score, max_score, active_user_count, licensed_user_count,
                      enabled_services, average_comparative, raw_data, fetched_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                    [
                        $tenantId,
                        $score['createdDateTime'] ?? date('Y-m-d'),
                        $score['currentScore'] ?? null,
                        $score['maxScore'] ?? null,
                        $score['activeUserCount'] ?? null,
                        $score['licensedUserCount'] ?? null,
                        json_encode($score['enabledServices'] ?? []),
                        json_encode($score['averageComparativeScores'] ?? []),
                        json_encode($score),
                    ]
                );
                $recordCount++;
            }

            $this->logSync($tenantId, 'secure_score', 'success', $recordCount);
            return ['success' => true, 'records' => $recordCount];

        } catch (Throwable $e) {
            $this->logSync($tenantId, 'secure_score', 'error', 0, $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Obtiene la tendencia del Secure Score.
     */
    public function getTrend(int $tenantId, string $period = '12m'): array
    {
        $months = match ($period) {
            '3m'  => 3,
            '6m'  => 6,
            '24m' => 24,
            default => 12,
        };
        $since = gmdate('Y-m-d', time() - ($months * 30 * 86400));

        $data = Database::fetchAll(
            "SELECT score_date, current_score, max_score,
                    ROUND(current_score * 100.0 / NULLIF(max_score, 0), 1) as percentage
             FROM secure_scores
             WHERE tenant_id = ? AND score_date >= ?
             ORDER BY score_date ASC",
            [$tenantId, $since]
        );

        $latest = Database::fetchOne(
            "SELECT * FROM secure_scores WHERE tenant_id = ? ORDER BY score_date DESC LIMIT 1",
            [$tenantId]
        );

        return ['trend' => $data, 'latest' => $latest];
    }

    /**
     * Obtiene los control profiles (detalle por control).
     */
    public function getControlProfiles(int $tenantId): array
    {
        $client = $this->getGraphClient($tenantId);
        try {
            $profiles = $client->graphGetAll('security/secureScoreControlProfiles');
            return ['success' => true, 'data' => $profiles];
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                       'handler' => [$this, 'index']],
            ['method' => 'GET',  'pattern' => 'trend',                  'handler' => [$this, 'getTrendData']],
            ['method' => 'GET',  'pattern' => 'profiles',               'handler' => [$this, 'getProfiles']],
            ['method' => 'POST', 'pattern' => 'sync/{tenantId}',        'handler' => [$this, 'triggerSync']],
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $trend = $selectedTenant ? $this->getTrend($selectedTenant) : ['trend' => [], 'latest' => null];
        $industry = null;
        if ($selectedTenant) {
            $t = TenantManager::getById($selectedTenant);
            $industry = $t['industry'] ?? null;
        }
        echo $this->page('index', [
            'module' => $this, 'tenants' => $tenants,
            'selectedTenant' => $selectedTenant, 'trend' => $trend,
            'industry' => $industry,
        ]);
    }

    public function getTrendData(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        $period = $_GET['period'] ?? '12m';
        json_response($this->getTrend($tenantId, $period));
    }

    public function getProfiles(array $params = []): void
    {
        $tenantId = (int)($_GET['tenant'] ?? 0);
        json_response($this->getControlProfiles($tenantId));
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
