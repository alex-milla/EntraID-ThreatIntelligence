<?php
/**
 * exposed_console.php — Smoke test de la consola de Equipos expuestos (v0.4.25).
 *
 *   php tools/smoke/exposed_console.php
 *
 * Cubre, sin red:
 *   · importación del export completo como snapshot
 *   · etiquetas inferidas de la descripción y resumen de software
 *   · filtros del portal (severidad, edad, amenazas, tags, estado, equipos,
 *     software y búsqueda) con sus contadores
 *   · ordenación (más antiguo a más nuevo, equipos, CVSS)
 *   · grupos de análisis y plan de actuación
 *
 * Usa el cve.sqlite real con un snapshot marcado y lo elimina en `finally`.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    if ($ok) {
        echo "OK   {$label}\n";
        return;
    }
    $fail++;
    echo "FALLO {$label}" . ($detail !== '' ? ' — ' . $detail : '') . "\n";
}

/* =====================================================================
 * 1. Etiquetas inferidas y resumen de software
 * ================================================================== */

$tags = CveTvmImport::describeTags('Summary: a zero-day in Chrome. No security update available for it.');
check('tags: zero-day', isset($tags['zero_day']));
check('tags: sin actualización', isset($tags['no_security_update']));
check('tags: no marca security_update si no hay parche', !isset($tags['security_update']));

$tags2 = CveTvmImport::describeTags('Apply the latest patches: security update released. Part of an exploit kit.');
check('tags: security update', isset($tags2['security_update']));
check('tags: exploit kit', isset($tags2['exploit_kit']));
check('tags: sin zero-day', !isset($tags2['zero_day']));

$tags3 = CveTvmImport::describeTags('An exploit is verified and actively exploited in the wild.');
check('tags: exploit verificado', isset($tags3['exploit_verified']));

$summary = CveTvmImport::softwareSummary('microsoft:chrome;google:chrome;linux:kernel;' . str_repeat('vendor:product;', 400));
check('software: etiquetas principales', $summary['labels'] !== [] && count($summary['labels']) <= 6);
check('software: total de pares', $summary['total'] >= 403);
check('software: tokens acotados', strlen($summary['tokens']) <= 1600);
check('software: el token de chrome está', str_contains($summary['tokens'], 'chrome'));

/* =====================================================================
 * 2. Fixture del export completo
 * ================================================================== */

$header = [
    'Name', 'Severity', 'CVSS v3', 'Epss score', 'Age (days)', 'Published',
    'First detected', 'Updated', 'Has Exploit', 'Has Known Threats',
    'Has Associated Alerts', 'Related Software', 'Exposed Machines',
    'Description', 'Status',
];

$data = [
    ['CVE-2026-90001', 'Critical', '9.8', '0.95000', 200, '01 May, 2026', '02 May, 2026', '18 Nov, 2026', 'True', 'True', 'True', 'microsoft:chrome;google:chrome', 600, 'Summary: zero-day en Chrome. No security update available.', 'RemediationRequired'],
    ['CVE-2026-90002', 'High', '8.8', '0.50000', 100, '10 Jul, 2026', '11 Jul, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'linux:kernel', 50, 'Summary: fallo en el kernel. No security update available.', 'RemediationRequired'],
    ['CVE-2026-90003', 'Medium', '6.5', '0.20000', 75, '01 Aug, 2026', '02 Aug, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'microsoft:chrome', 5, 'Summary: fallo de validación.', 'RemediationRequired'],
    ['CVE-2026-90004', 'Low', '3.1', '0.01000', 45, '01 Sep, 2026', '02 Sep, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'nginx:nginx', 0, 'Summary: error menor.', 'RemediationRequired'],
    ['CVE-2026-90005', 'Critical', '9.1', '0.70000', 10, '01 Oct, 2026', '02 Oct, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'microsoft:edge_chromium-based', 10, 'Summary: corrupción de memoria.', 'RemediationRequired'],
    ['CVE-2026-90006', 'Critical', '9.9', '0.90000', 120, '01 Jul, 2026', '02 Jul, 2026', '18 Nov, 2026', 'True', 'False', 'False', 'google:chrome', 200, 'Summary: ejecución de código.', 'RemediationRequired'],
    ['CVE-2026-90007', 'High', '7.5', '0.30000', 35, '01 Oct, 2026', '12 Oct, 2026', '18 Nov, 2026', 'False', 'True', 'False', 'linux:kernel', 500, 'Summary: amenaza conocida.', 'RemediationRequired'],
    ['CVE-2026-90008', 'Medium', '5.5', '0.10000', 65, '01 Sep, 2026', '05 Sep, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'google:chrome', 100, 'Summary: fuga de información.', 'UnderException'],
    ['CVE-2026-90009', 'High', '8.1', '0.40000', 95, '01 Aug, 2026', '06 Aug, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'linux:kernel', 20, 'Summary: elevación de privilegios.', 'NoActionRequired'],
    ['CVE-2026-90010', 'Informational', '0.0', '0.00000', 5, '01 Nov, 2026', '02 Nov, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'microsoft:windows', 1, 'Summary: informativo.', 'PartialException'],
    ['CVE-2026-90011', 'Low', '2.5', '0.02000', 89, '01 Aug, 2026', '03 Aug, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'microsoft:chrome', 15, 'Summary: error de configuración.', 'RemediationRequired'],
    ['CVE-2026-90012', 'Medium', '6.0', '0.15000', 30, '01 Oct, 2026', '04 Oct, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'oracle:java', 30, 'Summary: security update available for it.', 'RemediationRequired'],
    ['CVE-2026-90013', 'Medium', '6.9', '0.80000', 5, '01 Nov, 2026', '05 Nov, 2026', '18 Nov, 2026', 'False', 'False', 'True', 'linux:kernel', 20, 'Summary: <SIN DATOS VÁLIDOS>', 'RemediationRequired'],
];

$fh = fopen('php://temp', 'r+');
fputcsv($fh, ['Vulnerabilities Export', '18 Nov 2026 05:54 PM +00:00'], ',', '"', '\\');
fputcsv($fh, $header, ',', '"', '\\');
foreach ($data as $row) {
    fputcsv($fh, $row, ',', '"', '\\');
}
rewind($fh);
$csv = (string)stream_get_contents($fh);
fclose($fh);

$parsedLight = CveTvmImport::parseCsv($csv, 100, ['software_pairs' => false]);
check('parser: modo consola sin pares', count($parsedLight['rows']) === 13);
check('parser: sin pares expandidos', ($parsedLight['rows'][0]['software_pairs'] ?? null) === []);
check('parser: etiquetas de software', ($parsedLight['rows'][0]['software_labels'] ?? []) !== []);
check('parser: tokens de búsqueda', str_contains((string)($parsedLight['rows'][0]['software_tokens'] ?? ''), 'chrome'));

/* =====================================================================
 * 3. Importación del snapshot y limpieza garantizada
 * ================================================================== */

$snapshotId = 0;
$groupId = 0;
$marker = 'smoke-console-' . bin2hex(random_bytes(4)) . '.csv';

try {
    $res = ExposedConsoleStore::importCsv($csv, $marker, 0);
    $snapshotId = (int)($res['snapshot_id'] ?? 0);
    check('snapshot: importa', $res['ok'], $res['error']);
    check('snapshot: 13 filas', (int)$res['rows'] === 13);

    $snapshot = ExposedConsoleStore::getSnapshot($snapshotId);
    check('snapshot: recuperable', $snapshot !== null && (string)$snapshot['filename'] === $marker);
    check('snapshot: fecha del export', (string)($snapshot['export_date'] ?? '') === '2026-11-18');

    /* -----------------------------------------------------------------
     * 4. Filtros
     * -------------------------------------------------------------- */

    $empty = ExposedConsoleStore::filtersFromInput([]);
    check('filtros: por defecto orden oldest', ($empty['sort'] ?? '') === 'oldest');
    check('filtros: sin bloques', ($empty['severity'] ?? []) === [] && ($empty['machines'] ?? 0) === 0);

    check('filtros: total del snapshot', ExposedConsoleStore::count($snapshotId, $empty) === 13);

    $critical = ExposedConsoleStore::filtersFromInput(['severity' => ['critical']]);
    check('filtros: severidad crítica', ExposedConsoleStore::count($snapshotId, $critical) === 3);

    $older90 = ExposedConsoleStore::filtersFromInput(['age' => ['90+']]);
    check('filtros: 90+ días', ExposedConsoleStore::count($snapshotId, $older90) === 4);

    $exploit = ExposedConsoleStore::filtersFromInput(['threats' => ['exploit']]);
    check('filtros: con exploit', ExposedConsoleStore::count($snapshotId, $exploit) === 2);

    $threats = ExposedConsoleStore::filtersFromInput(['threats' => ['known']]);
    check('filtros: con amenazas conocidas', ExposedConsoleStore::count($snapshotId, $threats) === 2);

    $alerts = ExposedConsoleStore::filtersFromInput(['threats' => ['alert']]);
    check('filtros: alertas asociadas', ExposedConsoleStore::count($snapshotId, $alerts) === 2);

    $zeroDay = ExposedConsoleStore::filtersFromInput(['tags' => ['zero_day']]);
    check('filtros: zero-day inferido', ExposedConsoleStore::count($snapshotId, $zeroDay) === 1);

    $noUpdate = ExposedConsoleStore::filtersFromInput(['tags' => ['no_security_update']]);
    check('filtros: sin actualización inferido', ExposedConsoleStore::count($snapshotId, $noUpdate) === 2);

    $withUpdate = ExposedConsoleStore::filtersFromInput(['tags' => ['security_update']]);
    check('filtros: actualización mencionada', ExposedConsoleStore::count($snapshotId, $withUpdate) === 1);

    $machines = ExposedConsoleStore::filtersFromInput(['machines' => '100']);
    check('filtros: >= 100 equipos', ExposedConsoleStore::count($snapshotId, $machines) === 4);

    $software = ExposedConsoleStore::filtersFromInput(['software' => 'chrome']);
    check('filtros: software chrome', ExposedConsoleStore::count($snapshotId, $software) === 5);

    $query = ExposedConsoleStore::filtersFromInput(['q' => 'cve-2026-90001']);
    check('filtros: búsqueda por CVE', ExposedConsoleStore::count($snapshotId, $query) === 1);

    $status = ExposedConsoleStore::filtersFromInput(['status' => ['UnderException']]);
    check('filtros: estado under exception', ExposedConsoleStore::count($snapshotId, $status) === 1);

    $combo = ExposedConsoleStore::filtersFromInput([
        'severity' => ['critical', 'high'],
        'age'      => ['90+'],
        'threats'  => ['exploit'],
    ]);
    check('filtros: combinación AND entre bloques', ExposedConsoleStore::count($snapshotId, $combo) === 2);

    check('filtros: los valores raros se descartan',
        (ExposedConsoleStore::filtersFromInput(['severity' => ['nope'], 'machines' => '9999', 'sort' => 'x'])['severity'] ?? null) === []
        && (ExposedConsoleStore::filtersFromInput(['machines' => '9999'])['machines'] ?? -1) === 0
        && (ExposedConsoleStore::filtersFromInput(['sort' => 'x'])['sort'] ?? '') === 'oldest');

    /* -----------------------------------------------------------------
     * 5. Ordenación y contadores
     * -------------------------------------------------------------- */

    $oldest = ExposedConsoleStore::rows($snapshotId, $empty, 5, 0);
    check('orden: primero el más antiguo', count($oldest) === 5 && (string)$oldest[0]['cve_id'] === 'CVE-2026-90001');
    check('orden: segundo por antigüedad', (string)$oldest[1]['cve_id'] === 'CVE-2026-90006');

    $newest = ExposedConsoleStore::rows(
        $snapshotId,
        ExposedConsoleStore::filtersFromInput(['sort' => 'newest']),
        3,
        0
    );
    check('orden: más nuevo primero', count($newest) === 3 && (int)$newest[0]['age_days'] === 5);

    $byMachines = ExposedConsoleStore::rows(
        $snapshotId,
        ExposedConsoleStore::filtersFromInput(['sort' => 'machines']),
        1,
        0
    );
    check('orden: más equipos primero', (int)($byMachines[0]['exposed_machines'] ?? 0) === 600);

    $stats = ExposedConsoleStore::stats($snapshotId, $empty);
    check('stats: total', (int)$stats['total'] === 13);
    check('stats: críticas', (int)$stats['critical'] === 3);
    check('stats: con exploit', (int)$stats['exploitable'] === 2);
    check('stats: máx. equipos', (int)$stats['machines_max'] === 600);
    check('stats: +90 días', (int)$stats['older90'] === 4);

    $facets = ExposedConsoleStore::facets($snapshotId, $empty);
    check('facets: suma de severidades = total', array_sum($facets['severity']) === 13);
    check('facets: edad suma total', array_sum($facets['age']) === 13);
    check('facets: estados suman total', array_sum($facets['status']) === 13);
    check('facets: amenazas con exploit/alertas', (int)($facets['threats']['exploit'] ?? 0) === 2
        && (int)($facets['threats']['known'] ?? 0) === 2
        && (int)($facets['threats']['alert'] ?? 0) === 2);
    check('facets: sin firmas inventadas', (int)($facets['threats']['verified'] ?? 0) === 0
        && (int)($facets['threats']['kit'] ?? 0) === 0);

    $allIds = ExposedConsoleStore::allIds($snapshotId, $critical);
    check('selección: todos los ids del filtro', count($allIds) === 3 && in_array('CVE-2026-90006', $allIds, true));

    /* -----------------------------------------------------------------
     * 5 bis. Vista: el formulario no puede autorellenarse con «Array»
     * (v0.4.25.1: (string) de un array de tokens rompía TODOS los filtros)
     * -------------------------------------------------------------- */

    $renderConsole = static function (array $consoleData) use ($module): string {
        ob_start();
        (static function () use ($consoleData, $module): void {
            $console = $consoleData;
            require dirname(__DIR__, 2) . '/public_html/modules/exposed_report/views/_console.php';
        })();
        return (string)ob_get_clean();
    };

    $viewFilters = ExposedConsoleStore::filtersFromInput(['severity' => ['critical']]);
    $consoleView = [
        'snapshots'      => ExposedConsoleStore::listSnapshots(),
        'snapshot'       => $snapshot,
        'snapshotId'     => $snapshotId,
        'filters'        => $viewFilters,
        'filterQuery'    => ExposedConsoleStore::filtersToQuery($viewFilters),
        'rows'           => ExposedConsoleStore::rows($snapshotId, $viewFilters, 100, 0),
        'stats'          => ExposedConsoleStore::stats($snapshotId, $viewFilters),
        'facets'         => ExposedConsoleStore::facets($snapshotId, $viewFilters),
        'total'          => 3,
        'page'           => 1,
        'pages'          => 1,
        'perPage'        => 100,
        'groups'         => [],
        'maxBytesLabel'  => '30 MB',
        'maxRowsConsole' => 20000,
        'counts'         => ['total' => 13],
    ];
    $consoleHtml = $renderConsole($consoleView);

    check('vista: el input de software no pinta «Array»', !str_contains($consoleHtml, 'value="Array"'));
    check('vista: el input de software queda vacío',
        preg_match('/name="software"[^>]*value=""/s', $consoleHtml) === 1);
    check('vista: filtro crítica pinta sus 3 CVE',
        substr_count($consoleHtml, 'CVE-2026-90001') >= 1
        && substr_count($consoleHtml, 'CVE-2026-90005') >= 1
        && substr_count($consoleHtml, 'CVE-2026-90006') >= 1);
    check('vista: el filtro excluye las no críticas', !str_contains($consoleHtml, 'CVE-2026-90004'));
    check('vista: checkbox de crítica marcado',
        preg_match('/name="severity\[\]"\s+value="critical"\s+checked/', $consoleHtml) === 1
        || preg_match('/value="critical"\s+checked/', $consoleHtml) === 1);
    check('vista: dos botones Apply (arriba y abajo)',
        substr_count($consoleHtml, 'Apply filters') === 2);

    $viewFilters2 = ExposedConsoleStore::filtersFromInput(['machines' => '100', 'software' => 'google chrome']);
    $consoleView2 = $consoleView;
    $consoleView2['filters'] = $viewFilters2;
    $consoleView2['filterQuery'] = ExposedConsoleStore::filtersToQuery($viewFilters2);
    $consoleView2['rows'] = ExposedConsoleStore::rows($snapshotId, $viewFilters2, 100, 0);
    $consoleView2['stats'] = ExposedConsoleStore::stats($snapshotId, $viewFilters2);
    $consoleView2['total'] = ExposedConsoleStore::count($snapshotId, $viewFilters2);
    $consoleHtml2 = $renderConsole($consoleView2);

    check('vista: software muestra el texto original',
        preg_match('/name="software"[^>]*value="google chrome"/s', $consoleHtml2) === 1);
    check('vista: los ocultos del grupo no envuelven escalares en []',
        !str_contains($consoleHtml2, 'name="machines[]"')
        && preg_match('/name="machines"\s+value="100"/', $consoleHtml2) === 1);
    check('vista: filtro por equipos y software devuelve filas',
        (int)$consoleView2['total'] === 3);

    /* -----------------------------------------------------------------
     * 6. Grupos
     * -------------------------------------------------------------- */

    $created = ExposedConsoleStore::createGroup(
        'Smoke · críticos',
        $snapshotId,
        $critical,
        ['CVE-2026-90001', 'CVE-2026-90002', 'CVE-2026-90006', 'no-es-un-cve'],
        0
    );
    $groupId = (int)$created['group_id'];
    check('grupo: creado', $created['ok'] && $groupId > 0, $created['error']);

    $group = ExposedConsoleStore::getGroup($groupId);
    check('grupo: nombre', $group !== null && (string)$group['name'] === 'Smoke · críticos');
    check('grupo: 3 CVE (el id inválido se descarta)', $group !== null && (int)$group['cve_count'] === 3);

    $groupRows = ExposedConsoleStore::groupRows($groupId);
    check('grupo: filas con datos TVM', count($groupRows) === 3 && $groupRows[0]['snapshot_id'] !== null);
    check('grupo: orden por severidad y equipos', (string)$groupRows[0]['cve_id'] === 'CVE-2026-90001');

    $added = ExposedConsoleStore::addCves($groupId, ['CVE-2026-90005', 'CVE-2026-90005']);
    check('grupo: añadir CVE', $added['ok'] && (int)$added['added'] === 1);

    $removed = ExposedConsoleStore::removeCve($groupId, 'CVE-2026-90002');
    check('grupo: quitar CVE', $removed['ok'] && (int)(ExposedConsoleStore::getGroup($groupId)['cve_count'] ?? 0) === 3);

    $emptyGroup = ExposedConsoleStore::createGroup('', $snapshotId, [], [], 0);
    check('grupo: nombre obligatorio', !$emptyGroup['ok']);

    $noCves = ExposedConsoleStore::createGroup('Sin CVE', $snapshotId, [], [], 0);
    check('grupo: exige CVE', !$noCves['ok']);

    /* -----------------------------------------------------------------
     * 7. Plan de actuación
     * -------------------------------------------------------------- */

    ExposedConsoleStore::savePlan($groupId, "## 1. Resumen ejecutivo\n\nPlan de prueba.", 3, 'modelo-x', 2);
    $plan = ExposedConsoleStore::getPlan($groupId);
    check('plan: guardado', $plan !== null && str_contains((string)$plan['content_text'], 'Plan de prueba'));
    check('plan: HTML generado', trim((string)($plan['content_html'] ?? '')) !== '');
    check('plan: metadatos', (int)($plan['cve_count'] ?? 0) === 3 && (string)($plan['model'] ?? '') === 'modelo-x');

    ExposedConsoleStore::savePlan($groupId, "## 1. Resumen ejecutivo\n\nPlan regenerado.", 4, 'modelo-y', 2);
    $plan2 = ExposedConsoleStore::getPlan($groupId);
    check('plan: se sustituye', $plan2 !== null && str_contains((string)$plan2['content_text'], 'regenerado'));
    check('plan: una fila por grupo', (int)CveDatabase::fetchOne(
        "SELECT COUNT(*) AS c FROM exposed_group_plans WHERE group_id = ?",
        [$groupId]
    )['c'] === 1);

    /* -----------------------------------------------------------------
     * 8. Borrado del snapshot bloqueado por grupos
     * -------------------------------------------------------------- */

    $blocked = ExposedConsoleStore::deleteSnapshot($snapshotId);
    check('snapshot: no se borra con grupos', !$blocked['ok'] && str_contains($blocked['error'], 'grupos'));

    $deletedGroup = ExposedConsoleStore::deleteGroup($groupId);
    check('grupo: eliminado', $deletedGroup['ok']);
    $groupId = 0;

    $deletedSnapshot = ExposedConsoleStore::deleteSnapshot($snapshotId);
    check('snapshot: eliminado tras el grupo', $deletedSnapshot['ok'], $deletedSnapshot['error']);
    check('snapshot: filas limpias', (int)CveDatabase::fetchOne(
        "SELECT COUNT(*) AS c FROM exposed_cves WHERE snapshot_id = ?",
        [$snapshotId]
    )['c'] === 0);
    $snapshotId = 0;
} finally {
    if ($groupId > 0) {
        ExposedConsoleStore::deleteGroup($groupId);
    }
    if ($snapshotId > 0) {
        CveDatabase::query("DELETE FROM exposed_group_cves WHERE group_id IN (SELECT id FROM exposed_groups WHERE snapshot_id = ?)", [$snapshotId]);
        CveDatabase::query("DELETE FROM exposed_group_plans WHERE group_id IN (SELECT id FROM exposed_groups WHERE snapshot_id = ?)", [$snapshotId]);
        CveDatabase::query("DELETE FROM exposed_groups WHERE snapshot_id = ?", [$snapshotId]);
        CveDatabase::query("DELETE FROM exposed_cves WHERE snapshot_id = ?", [$snapshotId]);
        CveDatabase::query("DELETE FROM exposed_snapshots WHERE id = ?", [$snapshotId]);
    }
}

/* =====================================================================
 * 9. Esquema y prompts
 * ================================================================== */

$tables = array_column(
    CveDatabase::fetchAll("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'exposed_%'"),
    'name'
);
foreach (['exposed_snapshots', 'exposed_cves', 'exposed_groups', 'exposed_group_cves', 'exposed_group_plans'] as $table) {
    check('esquema: tabla ' . $table, in_array($table, $tables, true));
}

$catalog = llm_prompts_catalog();
check('prompts: plan de actuación', isset($catalog['llm.exposed.action_plan']));
check('prompts: plan en scope Equipos expuestos',
    ($catalog['llm.exposed.action_plan']['scope_label'] ?? '') === 'Equipos expuestos');
$planPrompt = (string)($catalog['llm.exposed.action_plan']['default'] ?? '');
check('prompts: el plan exige fases', str_contains($planPrompt, 'Fase 1') && str_contains($planPrompt, 'Fase 2'));
check('prompts: el plan prohíbe inventar', str_contains($planPrompt, 'no inventes'));
check('tareas: plan asignable', array_key_exists('exposed_action_plan', llm_task_catalog()));

$module = ModuleManager::get('exposed_report');
check('módulo: versión 2', $module instanceof Module_ExposedReport && $module->version() === '2.0.0');
check('módulo: 11 rutas', $module !== null && count($module->routes()) === 11);

echo "\n" . ($total - $fail) . "/{$total} pruebas correctas\n";
echo $fail === 0 ? "OK\n" : "FALLOS: {$fail}\n";
exit($fail === 0 ? 0 : 1);
