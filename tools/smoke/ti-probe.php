<?php
/**
 * ti-probe.php — Pruebas de la sonda de novedades y de la cola de artículos
 * del módulo Threat Intelligence.
 *
 *   php tools/smoke/ti-probe.php
 *
 * Sin red y sin cURL: usa un doble de GraphClient. Crea un tenant temporal y
 * lo borra al terminar (las FK en cascada limpian jobs y cola).
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    echo ($ok ? 'OK   ' : 'FALLO ') . $label . (!$ok && $detail !== '' ? ' — ' . $detail : '') . PHP_EOL;
    if (!$ok) { $fail++; }
}

/** Doble de GraphClient con respuestas programables. */
final class FakeGraph extends GraphClient
{
    public array $calls = [];
    public array $list = [];
    public int $filterHits = 0;
    public bool $rejectFilter = false;
    public bool $failLists = false;
    public string $latest = '';

    public function __construct()
    {
        parent::__construct('tenant-test', 'client-test', 'secret-test');
    }

    public function graphGet(string $path, array $queryParams = [], array $extraHeaders = []): array
    {
        $this->calls[] = ['get', $path, $queryParams];
        return $this->dispatch($path, $queryParams);
    }

    public function graphGetAll(string $path, array $queryParams = [], int $maxPages = 100): array
    {
        $this->calls[] = ['getAll', $path, $queryParams];
        $res = $this->dispatch($path, $queryParams);
        return $res['value'] ?? [];
    }

    public function getAllCalls(): int
    {
        $n = 0;
        foreach ($this->calls as $c) { if ($c[0] === 'getAll') { $n++; } }
        return $n;
    }

    private function dispatch(string $path, array $q): array
    {
        if (str_contains($path, '/indicators')) {
            return ['value' => []];
        }
        if (isset($q['$filter']) && $this->rejectFilter) {
            throw new RuntimeException('API Error [BadRequest] (400): $filter is not supported — URL: ' . $path);
        }
        if ($this->failLists) {
            throw new RuntimeException('Error cURL: Operation timed out');
        }
        if (isset($q['$orderby'])) {
            return ['value' => [['id' => 'latest', 'lastUpdatedDateTime' => $this->latest]]];
        }
        if (isset($q['$filter'])) {
            return ['value' => array_slice($this->list, 0, $this->filterHits)];
        }
        if (str_starts_with($path, 'security/threatIntelligence/articles/')) {
            $id = substr($path, strlen('security/threatIntelligence/articles/'));
            return [
                'id'                => $id,
                'title'             => 'Artículo ' . $id,
                'createdDateTime'   => gmdate('c', time() - 3600),
                'lastUpdatedDateTime' => gmdate('c', time() - 60),
                'summary'           => ['content' => 'Resumen'],
                'body'              => ['content' => 'Cuerpo'],
                'tags'              => [],
                'isFeatured'        => false,
            ];
        }
        return ['value' => $this->list];
    }
}

/** Módulo con Graph inyectado y sonda programable. */
final class TiTestModule extends Module_ThreatIntelligence
{
    public ?GraphClient $fake = null;
    public ?int $probeCount = null;
    public string $probeVariant = 'test';

    protected function getGraphClient(int $tenantId): GraphClient
    {
        return $this->fake;
    }

    protected function probeNewArticles(GraphClient $client, int $tenantId): array
    {
        if ($this->probeCount === null) {
            return parent::probeNewArticles($client, $tenantId);
        }
        return ['ok' => true, 'count' => $this->probeCount, 'variant' => $this->probeVariant, 'error' => ''];
    }
}

// ============================================================
// Preparación: tenant temporal + un artículo previo
// ============================================================
$tenantId = (int)Database::insert(
    "INSERT INTO tenants (name, slug, tenant_id, client_id, client_secret_encrypted, client_secret_iv)
     VALUES ('__probe_test__', '__probe_test__', 't', 'c', 'enc', 'iv')"
);
check('tenant temporal creado', $tenantId > 0);

$settingsBefore = [];
foreach (['ti_probe_last_at', 'ti_probe_last_total', 'ti_probe_variant', 'ti_probe_last_tenant'] as $k) {
    $settingsBefore[$k] = Database::fetchOne('SELECT setting_value, is_encrypted FROM settings WHERE setting_key = ?', [$k]);
}

$cleanup = static function () use ($tenantId, $settingsBefore): void {    try { Database::query('DELETE FROM tenants WHERE id = ?', [$tenantId]); } catch (Throwable $e) {}
    foreach ($settingsBefore as $k => $row) {
        try {
            if ($row === null) {
                Database::query('DELETE FROM settings WHERE setting_key = ?', [$k]);
            } else {
                Database::query(
                    "INSERT OR REPLACE INTO settings (setting_key, setting_value, is_encrypted, updated_at)
                     VALUES (?, ?, ?, datetime('now'))",
                    [$k, (string)$row['setting_value'], (int)$row['is_encrypted']]
                );
            }
        } catch (Throwable $e) {}
    }
};

/** Cierra los jobs activos para que cada caso empiece limpio. */
$resetJobs = static function () use ($tenantId): void {
    Database::query(
        "UPDATE sync_jobs SET status = 'done', finished_at = datetime('now'), updated_at = datetime('now')
         WHERE tenant_id = ? AND status IN ('queued','running')",
        [$tenantId]
    );
};

try {
    // Artículo previo (no se vuelve a procesar si no cambia).
    $oldUpdated = gmdate('c', time() - (10 * 86400));
    Database::query(
        "INSERT INTO ti_articles (tenant_id, article_id, title, created_date, last_updated, fetched_at)
         VALUES (?, 'old1', 'Viejo', ?, ?, datetime('now'))",
        [$tenantId, $oldUpdated, $oldUpdated]
    );

    // ============================================================
    // A · Sonda con $filter: 0 novedades → no se crea job
    // ============================================================
    $fake = new FakeGraph();
    $fake->filterHits = 0;

    $mod = new TiTestModule();
    $mod->fake = $fake;

    $probe = (function () use ($mod, $fake, $tenantId) {
        $m = new ReflectionMethod($mod, 'probeNewArticles');
        $m->setAccessible(true);
        return $m->invoke($mod, $fake, $tenantId);
    })();

    check('A: sonda ok', !empty($probe['ok']));
    check('A: usa $filter', ($probe['variant'] ?? '') === 'filter', json_encode($probe));
    check('A: 0 novedades', (int)($probe['count'] ?? -1) === 0);

    $resA = $mod->startSyncJob($tenantId, 'ti_full', 'https://example.test');
    check('A: startSyncJob skipped', !empty($resA['skipped']), json_encode($resA));
    check('A: sin job creado', (int)(Database::fetchOne('SELECT COUNT(*) AS c FROM sync_jobs WHERE tenant_id = ?', [$tenantId])['c'] ?? 0) === 0);

    // ============================================================
    // B · Sonda con novedades → job creado
    // ============================================================
    $resetJobs();
    $fake2 = new FakeGraph();
    $fake2->filterHits = 2;
    $mod2 = new TiTestModule();
    $mod2->fake = $fake2;
    $mod2->probeCount = 2;

    $resB = $mod2->startSyncJob($tenantId, 'ti_full', 'https://example.test');
    check('B: job creado', empty($resB['skipped']) && !empty($resB['job_id']), json_encode($resB));
    $jobB = (int)($resB['job_id'] ?? 0);
    $rowB = Database::fetchOne('SELECT queue_state FROM sync_jobs WHERE id = ?', [$jobB]);
    check('B: cola pendiente', ($rowB['queue_state'] ?? null) === null || ($rowB['queue_state'] ?? '') === 'pending');

    // ============================================================
    // C · $filter rechazado → fallback a $orderby
    // ============================================================
    $fake3 = new FakeGraph();
    $fake3->rejectFilter = true;
    $fake3->latest = gmdate('c', time() - 30); // más nuevo que el guardado (10 días)

    $mod3 = new TiTestModule();
    $mod3->fake = $fake3;
    $probe3 = (function () use ($mod3, $fake3, $tenantId) {
        $m = new ReflectionMethod($mod3, 'probeNewArticles');
        $m->setAccessible(true);
        return $m->invoke($mod3, $fake3, $tenantId);
    })();
    check('C: variante orderby', ($probe3['variant'] ?? '') === 'orderby', json_encode($probe3));
    check('C: detecta novedad', (int)($probe3['count'] ?? -1) === 1, json_encode($probe3));

    $fake3b = new FakeGraph();
    $fake3b->rejectFilter = true;
    $fake3b->latest = $oldUpdated; // igual que lo guardado → sin novedades
    $mod3b = new TiTestModule();
    $mod3b->fake = $fake3b;
    $probe3b = (function () use ($mod3b, $fake3b, $tenantId) {
        $m = new ReflectionMethod($mod3b, 'probeNewArticles');
        $m->setAccessible(true);
        return $m->invoke($mod3b, $fake3b, $tenantId);
    })();
    check('C: sin novedad por orderby', (int)($probe3b['count'] ?? -1) === 0, json_encode($probe3b));

    // ============================================================
    // D · Sonda no concluyente → fail-open (job creado)
    // ============================================================
    $resetJobs();
    $fake4 = new FakeGraph();
    $fake4->failLists = true;
    $mod4 = new TiTestModule();
    $mod4->fake = $fake4;
    $probe4 = (function () use ($mod4, $fake4, $tenantId) {
        $m = new ReflectionMethod($mod4, 'probeNewArticles');
        $m->setAccessible(true);
        return $m->invoke($mod4, $fake4, $tenantId);
    })();
    check('D: sonda no concluyente', empty($probe4['ok']), json_encode($probe4));

    $mod4->probeCount = null;
    $resD = $mod4->startSyncJob($tenantId, 'ti_full', 'https://example.test');
    check('D: fail-open crea job', empty($resD['skipped']) && !empty($resD['job_id']), json_encode($resD));

    // ============================================================
    // E · Cola: un solo listado y dos pasos
    // ============================================================
    $resetJobs();
    $fake5 = new FakeGraph();
    $fake5->filterHits = 4;
    $fake5->list = [
        ['id' => 'a1', 'createdDateTime' => gmdate('c', time() - 7200), 'lastUpdatedDateTime' => gmdate('c', time() - 3600)],
        ['id' => 'a2', 'createdDateTime' => gmdate('c', time() - 7200), 'lastUpdatedDateTime' => gmdate('c', time() - 3500)],
        ['id' => 'a3', 'createdDateTime' => gmdate('c', time() - 7200), 'lastUpdatedDateTime' => gmdate('c', time() - 3400)],
        ['id' => 'old1', 'createdDateTime' => $oldUpdated, 'lastUpdatedDateTime' => $oldUpdated],
    ];
    $mod5 = new TiTestModule();
    $mod5->fake = $fake5;
    $mod5->probeCount = 4;

    $resE = $mod5->startSyncJob($tenantId, 'ti_full', 'https://example.test');
    $jobE = (int)($resE['job_id'] ?? 0);
    check('E: job creado', $jobE > 0, json_encode($resE));

    $step1 = $mod5->syncStepArticles($fake5, $tenantId, 0, 2, $jobE);
    check('E: cola rellenada (3 nuevos, old1 sin cambios)', (int)($step1['total'] ?? -1) === 3, json_encode($step1));
    check('E: primer paso no termina', empty($step1['done']), json_encode($step1));
    check('E: un solo listado', $fake5->getAllCalls() === 1, 'llamadas getAll=' . $fake5->getAllCalls());
    check('E: 2 procesados', (int)($step1['processed'] ?? -1) === 2, json_encode($step1));

    $step2 = $mod5->syncStepArticles($fake5, $tenantId, 2, 2, $jobE);
    check('E: segundo paso termina', !empty($step2['done']), json_encode($step2));
    check('E: sigue con un solo listado', $fake5->getAllCalls() === 1, 'llamadas getAll=' . $fake5->getAllCalls());
    check('E: 3 artículos en BD', (int)(Database::fetchOne('SELECT COUNT(*) AS c FROM ti_articles WHERE tenant_id = ?', [$tenantId])['c'] ?? 0) === 4);
    check('E: cola completada', (int)(Database::fetchOne("SELECT COUNT(*) AS c FROM ti_sync_queue WHERE job_id = ? AND status = 'done'", [$jobE])['c'] ?? 0) === 3);

    // ============================================================
    // F · Sin poder listar → modo degradado (camino clásico)
    // ============================================================
    $resetJobs();
    $fake6 = new FakeGraph();
    $fake6->failLists = true;
    $mod6 = new TiTestModule();
    $mod6->fake = $fake6;
    $mod6->probeCount = 1;
    $resF = $mod6->startSyncJob($tenantId, 'ti_full', 'https://example.test');
    $jobF = (int)($resF['job_id'] ?? 0);

    $threw = false;
    try {
        $mod6->syncStepArticles($fake6, $tenantId, 0, 2, $jobF);
    } catch (Throwable $e) {
        $threw = true; // el camino clásico propaga el error de red (igual que antes)
    }
    $rowF = Database::fetchOne('SELECT queue_state FROM sync_jobs WHERE id = ?', [$jobF]);
    check('F: job marcado degradado', ($rowF['queue_state'] ?? '') === 'degraded', json_encode($rowF));
    check('F: el error de red se propaga como antes', $threw);
} finally {
    $cleanup();
}

echo PHP_EOL . ($fail === 0 ? 'RESULTADO: OK (' . $total . ' comprobaciones)' : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
