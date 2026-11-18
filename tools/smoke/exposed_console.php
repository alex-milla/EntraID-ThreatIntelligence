<?php
/**
 * exposed_console.php — Smoke test de la consola de Equipos expuestos.
 *
 *   php tools/smoke/exposed_console.php
 *
 * Cubre, sin red:
 *   · etiquetas inferidas y resumen de software
 *   · importación incremental en la lista maestra única
 *     (nuevo / actualizado / sin cambios), varias filas y tope de 6.000
 *   · filtros del portal (severidad, edad, amenazas, tags, estado, equipos,
 *     software y búsqueda) con sus contadores
 *   · ordenación, grupos de análisis y plan de actuación
 *   · regresión del formulario (nunca `value="Array"`)
 *   · esquema de la lista maestra y prompts
 *
 * Hace copia de `cve.sqlite` antes de escribir y la restaura en `finally`:
 * nunca deja datos de prueba en la base real.
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
    ['CVE-2026-90001', 'Critical', '9.8', '0.95000', 200, '01 May, 2026', '02 May, 2026', '18 Nov, 2026', 'True', 'True', 'True', 'microsoft:chrome;google:chrome', 600, 'Summary: zero-day en Chrome. No security update available. Ver CVE-2026-90006.', 'RemediationRequired'],
    ['CVE-2026-90002', 'High', '8.8', '0.50000', 100, '10 Jul, 2026', '11 Jul, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'linux:kernel', 50, 'Summary: fallo en el kernel. No security update available. Relacionado con CVE-2026-90001.', 'RemediationRequired'],
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

$buildCsv = static function (array $rows, array $header): string {
    $fh = fopen('php://temp', 'r+');
    fputcsv($fh, ['Vulnerabilities Export', '18 Nov 2026 05:54 PM +00:00'], ',', '"', '\\');
    fputcsv($fh, $header, ',', '"', '\\');
    foreach ($rows as $row) {
        fputcsv($fh, $row, ',', '"', '\\');
    }
    rewind($fh);
    $csv = (string)stream_get_contents($fh);
    fclose($fh);
    return $csv;
};

$csv = $buildCsv($data, $header);

$parsedLight = CveTvmImport::parseCsv($csv, 100, ['software_pairs' => false]);
check('parser: modo consola sin pares', count($parsedLight['rows']) === 13);
check('parser: sin pares expandidos', ($parsedLight['rows'][0]['software_pairs'] ?? null) === []);
check('parser: etiquetas de software', ($parsedLight['rows'][0]['software_labels'] ?? []) !== []);
check('parser: tokens de búsqueda', str_contains((string)($parsedLight['rows'][0]['software_tokens'] ?? ''), 'chrome'));

/* =====================================================================
 * 3. Copia de seguridad de cve.sqlite (el test escribe en la lista maestra)
 * ================================================================== */

$dbPath = defined('CVE_DB_PATH') ? CVE_DB_PATH : (STORAGE_PATH . '/cve.sqlite');
$dbFiles = ['cve.sqlite', 'cve.sqlite-wal', 'cve.sqlite-shm'];
$backupDir = sys_get_temp_dir() . '/exposed-smoke-' . bin2hex(random_bytes(4));
if (!is_dir($backupDir)) {
    mkdir($backupDir, 0777, true);
}
foreach ($dbFiles as $file) {
    $src = dirname($dbPath) . '/' . $file;
    if (is_file($src)) {
        copy($src, $backupDir . '/' . $file);
    }
}

$snapshotId = 0;
$groupId = 0;
$mergeId = 0;
$truncId = 0;

try {
    // Estado de partida conocido (se restaura el fichero al terminar).
    ExposedConsoleStore::clearAll();
    CveDatabase::query("DELETE FROM exposed_snapshots");

    /* -----------------------------------------------------------------
     * 4. Importación en la lista maestra
     * -------------------------------------------------------------- */

    $first = ExposedConsoleStore::importCsv($csv, 'smoke-console.csv', 0);
    check('import: guarda el CSV', $first['ok'], $first['error']);
    check('import: 13 nuevos', (int)$first['inserted'] === 13
        && (int)$first['updated'] === 0
        && (int)$first['unchanged'] === 0);
    check('import: total 13', (int)$first['total'] === 13);
    check('import: sin truncado', empty($first['truncated']));
    check('import: registra historial', (int)$first['import_id'] > 0);
    $mergeId = (int)$first['import_id'];

    /* -----------------------------------------------------------------
     * 5. Filtros sobre la lista maestra
     * -------------------------------------------------------------- */

    $empty = ExposedConsoleStore::filtersFromInput([]);
    check('filtros: por defecto orden oldest', ($empty['sort'] ?? '') === 'oldest');
    check('filtros: sin bloques', ($empty['severity'] ?? []) === [] && ($empty['machines'] ?? 0) === 0);
    check('filtros: total de la base', ExposedConsoleStore::count($empty) === 13);

    $critical = ExposedConsoleStore::filtersFromInput(['severity' => ['critical']]);
    check('filtros: severidad crítica', ExposedConsoleStore::count($critical) === 3);

    $older90 = ExposedConsoleStore::filtersFromInput(['age' => ['90+']]);
    check('filtros: 90+ días', ExposedConsoleStore::count($older90) === 4);

    $exploit = ExposedConsoleStore::filtersFromInput(['threats' => ['exploit']]);
    check('filtros: con exploit', ExposedConsoleStore::count($exploit) === 2);

    $threats = ExposedConsoleStore::filtersFromInput(['threats' => ['known']]);
    check('filtros: con amenazas conocidas', ExposedConsoleStore::count($threats) === 2);

    $alerts = ExposedConsoleStore::filtersFromInput(['threats' => ['alert']]);
    check('filtros: alertas asociadas', ExposedConsoleStore::count($alerts) === 2);

    $zeroDay = ExposedConsoleStore::filtersFromInput(['tags' => ['zero_day']]);
    check('filtros: zero-day inferido', ExposedConsoleStore::count($zeroDay) === 1);

    $noUpdate = ExposedConsoleStore::filtersFromInput(['tags' => ['no_security_update']]);
    check('filtros: sin actualización inferido', ExposedConsoleStore::count($noUpdate) === 2);

    $withUpdate = ExposedConsoleStore::filtersFromInput(['tags' => ['security_update']]);
    check('filtros: actualización mencionada', ExposedConsoleStore::count($withUpdate) === 1);

    $machines = ExposedConsoleStore::filtersFromInput(['machines' => '100']);
    check('filtros: >= 100 equipos', ExposedConsoleStore::count($machines) === 4);

    $software = ExposedConsoleStore::filtersFromInput(['software' => 'chrome']);
    check('filtros: software chrome', ExposedConsoleStore::count($software) === 5);

    $query = ExposedConsoleStore::filtersFromInput(['q' => 'cve-2026-90001']);
    check('filtros: búsqueda por CVE', ExposedConsoleStore::count($query) === 1);

    $status = ExposedConsoleStore::filtersFromInput(['status' => ['UnderException']]);
    check('filtros: estado under exception', ExposedConsoleStore::count($status) === 1);

    $combo = ExposedConsoleStore::filtersFromInput([
        'severity' => ['critical', 'high'],
        'age'      => ['90+'],
        'threats'  => ['exploit'],
    ]);
    check('filtros: combinación AND entre bloques', ExposedConsoleStore::count($combo) === 2);

    check('filtros: los valores raros se descartan',
        (ExposedConsoleStore::filtersFromInput(['severity' => ['nope'], 'machines' => '9999', 'sort' => 'x'])['severity'] ?? null) === []
        && (ExposedConsoleStore::filtersFromInput(['machines' => '9999'])['machines'] ?? -1) === 0
        && (ExposedConsoleStore::filtersFromInput(['sort' => 'x'])['sort'] ?? '') === 'oldest');

    /* -----------------------------------------------------------------
     * 6. Orden, contadores y vista
     * -------------------------------------------------------------- */

    $oldest = ExposedConsoleStore::rows($empty, 5, 0);
    check('orden: primero el más antiguo', count($oldest) === 5 && (string)$oldest[0]['cve_id'] === 'CVE-2026-90001');
    check('orden: segundo por antigüedad', (string)$oldest[1]['cve_id'] === 'CVE-2026-90006');

    $newest = ExposedConsoleStore::rows(
        ExposedConsoleStore::filtersFromInput(['sort' => 'newest']),
        3,
        0
    );
    check('orden: más nuevo primero', count($newest) === 3 && (int)$newest[0]['age_days'] === 5);

    $byMachines = ExposedConsoleStore::rows(
        ExposedConsoleStore::filtersFromInput(['sort' => 'machines']),
        1,
        0
    );
    check('orden: más equipos primero', (int)($byMachines[0]['exposed_machines'] ?? 0) === 600);

    // Ordenación por cabecera (v0.4.25.4)
    $cveAsc = ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'cve_asc']), 1, 0);
    check('orden: CVE ascendente', (string)($cveAsc[0]['cve_id'] ?? '') === 'CVE-2026-90001');
    $cveDesc = ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'cve_desc']), 1, 0);
    check('orden: CVE descendente', (string)($cveDesc[0]['cve_id'] ?? '') === 'CVE-2026-90013');

    $cvssDesc = ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'cvss_desc']), 1, 0);
    check('orden: CVSS descendente', (string)($cvssDesc[0]['cve_id'] ?? '') === 'CVE-2026-90006');
    $cvssAsc = ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'cvss_asc']), 1, 0);
    check('orden: CVSS ascendente', (string)($cvssAsc[0]['cve_id'] ?? '') === 'CVE-2026-90010');

    $sevAsc = ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'sev_asc']), 1, 0);
    check('orden: severidad, crítica primero', (string)($sevAsc[0]['cve_id'] ?? '') === 'CVE-2026-90001');

    $epssDesc = ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'epss_desc']), 1, 0);
    check('orden: EPSS descendente', (string)($epssDesc[0]['cve_id'] ?? '') === 'CVE-2026-90001');

    $machinesAsc = ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'machines_asc']), 1, 0);
    check('orden: equipos ascendente', (string)($machinesAsc[0]['cve_id'] ?? '') === 'CVE-2026-90004');

    $detectedDesc = ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'detected_desc']), 1, 0);
    check('orden: detectado, más reciente primero', (string)($detectedDesc[0]['cve_id'] ?? '') === 'CVE-2026-90013');
    $detectedAsc = ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'detected_asc']), 1, 0);
    check('orden: detectado, más antiguo primero', (string)($detectedAsc[0]['cve_id'] ?? '') === 'CVE-2026-90001');

    check('orden: todos los modos admitidos', in_array('cve_desc', ExposedConsoleStore::SORTS, true)
        && in_array('cvss_asc', ExposedConsoleStore::SORTS, true)
        && in_array('detected_desc', ExposedConsoleStore::SORTS, true));
    check('orden: se conserva en la URL', (ExposedConsoleStore::filtersToQuery(
        ExposedConsoleStore::filtersFromInput(['sort' => 'cvss_asc'])
    )['sort'] ?? '') === 'cvss_asc');
    $stats = ExposedConsoleStore::stats($empty);
    check('stats: total', (int)$stats['total'] === 13);
    check('stats: críticas', (int)$stats['critical'] === 3);
    check('stats: con exploit', (int)$stats['exploitable'] === 2);
    check('stats: máx. equipos', (int)$stats['machines_max'] === 600);
    check('stats: +90 días', (int)$stats['older90'] === 4);

    $facets = ExposedConsoleStore::facets($empty);
    check('facets: suma de severidades = total', array_sum($facets['severity']) === 13);
    check('facets: edad suma total', array_sum($facets['age']) === 13);
    check('facets: estados suman total', array_sum($facets['status']) === 13);
    check('facets: amenazas con exploit/alertas', (int)($facets['threats']['exploit'] ?? 0) === 2
        && (int)($facets['threats']['known'] ?? 0) === 2
        && (int)($facets['threats']['alert'] ?? 0) === 2);
    check('facets: sin firmas inventadas', (int)($facets['threats']['verified'] ?? 0) === 0
        && (int)($facets['threats']['kit'] ?? 0) === 0);

    $allIds = ExposedConsoleStore::allIds($critical);
    check('selección: todos los ids del filtro', count($allIds) === 3 && in_array('CVE-2026-90006', $allIds, true));

    $master = ExposedConsoleStore::masterTotals();
    check('maestra: totales de la base', (int)$master['total'] === 13
        && (int)$master['critical'] === 3
        && (int)$master['machines_max'] === 600
        && $master['last_seen_at'] !== '');

    /* -----------------------------------------------------------------
     * 6 bis. CVEs relacionados (determinista, sin IA)
     * -------------------------------------------------------------- */

    check('relacionados: menciones salientes y entrantes', ExposedConsoleStore::relatedMentionsCount('CVE-2026-90001') === 2);
    $related = ExposedConsoleStore::relatedCves('CVE-2026-90001');
    $descIds = array_map(static fn(array $r): string => (string)$r['cve_id'], (array)$related['description']);
    sort($descIds);
    check('relacionados: descripción en ambos sentidos', $descIds === ['CVE-2026-90002', 'CVE-2026-90006'], implode(',', $descIds));
    check('relacionados: relación anotada', in_array(
        'citado por',
        array_map(static fn(array $r): string => (string)($r['relation'] ?? ''), (array)$related['description']),
        true
    ));
    $softwareIds = array_map(
        static fn(array $r): string => (string)$r['cve_id'],
        (array)$related['software']
    );
    sort($softwareIds);
    check('relacionados: mismo software', $softwareIds === ['CVE-2026-90003', 'CVE-2026-90011'], implode(',', $softwareIds));
    check('relacionados: sin lote (fechas y equipos distintos)', (array)$related['batch'] === []);
    check('relacionados: software principal', ExposedConsoleStore::mainSoftware('microsoft:chrome, google:chrome') === 'microsoft:chrome');
    $missingRelated = ExposedConsoleStore::relatedCves('CVE-2099-0001');
    check('relacionados: CVE inexistente', $missingRelated['row'] === null);

    $module = ModuleManager::get('exposed_report');

    $renderConsole = static function (array $consoleData) use ($module): string {
        ob_start();
        (static function () use ($consoleData, $module): void {
            $console = $consoleData;
            require dirname(__DIR__, 2) . '/public_html/modules/exposed_report/views/_console.php';
        })();
        return (string)ob_get_clean();
    };

    $viewFilters = $critical;
    $consoleView = [
        'imports'        => ExposedConsoleStore::listImports(),
        'latestImport'   => ExposedConsoleStore::latestSnapshot(),
        'totals'         => $master,
        'filters'        => $viewFilters,
        'filterQuery'    => ExposedConsoleStore::filtersToQuery($viewFilters),
        'rows'           => ExposedConsoleStore::rows($viewFilters, 100, 0),
        'stats'          => ExposedConsoleStore::stats($viewFilters),
        'facets'         => ExposedConsoleStore::facets($viewFilters),
        'total'          => 3,
        'page'           => 1,
        'pages'          => 1,
        'perPage'        => 100,
        'groups'         => [],
        'maxBytesLabel'  => '30 MB',
        'maxRowsConsole' => 20000,
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
    check('vista: cabeceras ordenables', str_contains($consoleHtml, 'sort=cve_desc')
        && str_contains($consoleHtml, 'sort=cvss_desc')
        && str_contains($consoleHtml, 'sort=age_asc'));
    check('vista: historial de importaciones visible', str_contains($consoleHtml, 'Historial de importaciones'));
    check('vista: botón de vaciar base', str_contains($consoleHtml, 'Vaciar base'));
    $posBar = strpos($consoleHtml, 'exposed-group-target');
    $posTable = strpos($consoleHtml, 'Vulnerabilidades del tenant');
    check('vista: barra de grupo encima de la tabla',
        $posBar !== false && $posTable !== false && $posBar < $posTable);
    check('vista: barra de grupo fija (sticky)', str_contains($consoleHtml, 'sticky top-'));
    check('vista: memoria de filtros por snapshot', str_contains($consoleHtml, "exposed.state.")
        && str_contains($consoleHtml, 'exposedClearState'));

    $viewFilters2 = ExposedConsoleStore::filtersFromInput(['machines' => '100', 'software' => 'google chrome']);
    $consoleView2 = $consoleView;
    $consoleView2['filters'] = $viewFilters2;
    $consoleView2['filterQuery'] = ExposedConsoleStore::filtersToQuery($viewFilters2);
    $consoleView2['rows'] = ExposedConsoleStore::rows($viewFilters2, 100, 0);
    $consoleView2['stats'] = ExposedConsoleStore::stats($viewFilters2);
    $consoleView2['total'] = ExposedConsoleStore::count($viewFilters2);
    $consoleHtml2 = $renderConsole($consoleView2);

    check('vista: software muestra el texto original',
        preg_match('/name="software"[^>]*value="google chrome"/s', $consoleHtml2) === 1);
    check('vista: los ocultos del grupo no envuelven escalares en []',
        !str_contains($consoleHtml2, 'name="machines[]"')
        && preg_match('/name="machines"\s+value="100"/', $consoleHtml2) === 1);
    check('vista: filtro por equipos y software devuelve filas',
        (int)$consoleView2['total'] === 3);

    $viewFilters3 = ExposedConsoleStore::filtersFromInput(['sort' => 'cvss_asc']);
    $consoleView3 = $consoleView;
    $consoleView3['filters'] = $viewFilters3;
    $consoleView3['filterQuery'] = ExposedConsoleStore::filtersToQuery($viewFilters3);
    $consoleView3['rows'] = ExposedConsoleStore::rows($viewFilters3, 5, 0);
    $consoleHtml3 = $renderConsole($consoleView3);
    check('vista: CVSS ascendente activo con flecha ↑',
        str_contains($consoleHtml3, 'sort=cvss_desc')
        && str_contains($consoleHtml3, 'CVSS <span aria-hidden="true" class="text-[10px]">↑</span>'));
    check('vista: el resto de cabeceras invita a ordenar',
        str_contains($consoleHtml3, 'sort=cve_desc')
        && str_contains($consoleHtml3, '↕'));

    // Pestañas: los grupos de análisis ya no viven al final de la consola.
    $indexData = [
        'module' => $module, 'console' => $consoleView, 'profiles' => [], 'defaultProfileId' => null,
        'profileId' => null, 'llmConfigured' => true, 'isAdmin' => false, 'activeTab' => 'console',
        'kql' => 'KQL', 'columns' => [], 'maxUploadLabel' => '30 MB', 'maxRows' => 500,
        'error' => null, 'errors' => [], 'warnings' => [], 'warningsTotal' => 0, 'stats' => null,
        'reportMd' => '', 'reportHtml' => '', 'mode' => 'compact', 'filename' => '', 'elapsedMs' => 0,
        'downloadName' => '', 'enrich' => 'catalog', 'enrichNotice' => null, 'enrichSources' => [],
        'catalogAvailable' => true, 'inventoryAvailable' => false, 'specJson' => '',
        'specCustom' => false, 'specNotice' => null, 'cveIds' => [], 'analysesMissing' => [],
        'queueNotice' => null,
    ];
    unset($_GET['tab']);
    $indexHtml = $module->render('index', $indexData);
    check('pestañas: grupos arriba', str_contains($indexHtml, 'exposed-tab-groups')
        && str_contains($indexHtml, 'id="exposed-pane-groups"'));
    check('pestañas: la consola arranca activa', str_contains($indexHtml, 'id="exposed-pane-console"')
        && preg_match('/id="exposed-pane-groups"\s+hidden/', $indexHtml) === 1);

    $_GET['tab'] = 'groups';
    $indexGroups = $module->render('index', $indexData);
    check('pestañas: ?tab=groups abre los grupos',
        preg_match('/id="exposed-pane-groups"(?!\s+hidden)/', $indexGroups) === 1);
    check('pestañas: la pestaña queda en la URL', str_contains($indexHtml, 'history.replaceState')
        && str_contains($indexHtml, "url.searchParams.set('tab'"));
    unset($_GET['tab']);

    /* -----------------------------------------------------------------
     * 7. Ingesta incremental: nuevo / actualizado / sin cambios
     * -------------------------------------------------------------- */

    $again = ExposedConsoleStore::importCsv($csv, 'smoke-again.csv', 0);
    check('fusión: reimportar idéntico', $again['ok']);
    check('fusión: 0 nuevos y 13 sin cambios', (int)$again['inserted'] === 0
        && (int)$again['updated'] === 0
        && (int)$again['unchanged'] === 13);
    check('fusión: no duplica filas', (int)$again['total'] === 13);

    // Un dato cambia (equipos expuestos 600 → 601): solo ese CVE se actualiza.
    $changedCsv = str_replace('google:chrome,600,', 'google:chrome,601,', $csv);
    $changed = ExposedConsoleStore::importCsv($changedCsv, 'smoke-changed.csv', 0);
    check('fusión: 1 actualizado y 12 sin cambios', (int)$changed['updated'] === 1
        && (int)$changed['inserted'] === 0
        && (int)$changed['unchanged'] === 12);
    $changedRow = CveDatabase::fetchOne(
        "SELECT exposed_machines FROM exposed_cves WHERE cve_id = ?",
        ['CVE-2026-90001']
    );
    check('fusión: el dato actualizado se guarda', (int)($changedRow['exposed_machines'] ?? 0) === 601);

    // Fila nueva.
    $extraCsv = $changedCsv . implode('', [
        'CVE-2026-90014,High,7.2,0.11,20,"01 Nov, 2026","02 Nov, 2026","18 Nov, 2026",',
        'False,False,False,microsoft:windows,3,"Summary: nueva detección.",RemediationRequired', "\n",
    ]);
    $extra = ExposedConsoleStore::importCsv($extraCsv, 'smoke-extra.csv', 0);
    check('fusión: 1 nuevo y 13 sin cambios', (int)$extra['inserted'] === 1
        && (int)$extra['updated'] === 0
        && (int)$extra['unchanged'] === 13);
    check('fusión: total 14', (int)$extra['total'] === 14);

    // Aviso del tope de 6.000 filas de Defender (6000 filas → 1 CVE único).
    $manyRows = [];
    for ($i = 0; $i < 6000; $i++) {
        $manyRows[] = $data[0];
    }
    $truncCsv = $buildCsv($manyRows, $header);
    $trunc = ExposedConsoleStore::importCsv($truncCsv, 'smoke-6000.csv', 0);
    $truncId = (int)$trunc['import_id'];
    check('tope: 6.000 filas detectadas', $trunc['ok'] && !empty($trunc['truncated']));
    check('tope: rango informado', (string)$trunc['range'] !== '' && str_contains((string)$trunc['range'], 'CVE-2026-90001'));
    check('tope: deduplica filas repetidas', (int)$trunc['rows'] === 1);

    $history = ExposedConsoleStore::listImports();
    check('historial: 5 importaciones', count($history) === 5);
    check('historial: guarda contadores', (int)$history[0]['rows_inserted'] >= 0
        && (int)$history[0]['rows_unchanged'] >= 0);

    /* -----------------------------------------------------------------
     * 8. Grupos
     * -------------------------------------------------------------- */

    $created = ExposedConsoleStore::createGroup(
        'Smoke · críticos',
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
    check('grupo: filas con datos TVM', count($groupRows) === 3 && $groupRows[0]['last_seen_at'] !== null);
    check('grupo: orden por severidad y equipos', (string)$groupRows[0]['cve_id'] === 'CVE-2026-90001');

    $added = ExposedConsoleStore::addCves($groupId, ['CVE-2026-90005', 'CVE-2026-90005']);
    check('grupo: añadir CVE', $added['ok'] && (int)$added['added'] === 1);

    $removed = ExposedConsoleStore::removeCve($groupId, 'CVE-2026-90002');
    check('grupo: quitar CVE', $removed['ok'] && (int)(ExposedConsoleStore::getGroup($groupId)['cve_count'] ?? 0) === 3);

    $emptyGroup = ExposedConsoleStore::createGroup('', [], [], 0);
    check('grupo: nombre obligatorio', !$emptyGroup['ok']);

    $noCves = ExposedConsoleStore::createGroup('Sin CVE', [], [], 0);
    check('grupo: exige CVE', !$noCves['ok']);

    /* -----------------------------------------------------------------
     * 9. Plan de actuación
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

    // Informe de vulnerabilidad (formato SploitScan, v0.4.26.3).
    $dossier = ExposedReportDossier::build(
        $group,
        $groupRows,
        ExposedPriority::defaults(),
        "## Lectura del riesgo\n\nTexto de prueba de la IA."
    );
    check('informe: cabecera de vulnerabilidad', str_contains((string)$dossier['html'], 'Informe de vulnerabilidad')
        && str_contains((string)$dossier['markdown'], '# Informe de vulnerabilidad'));
    check('informe: tarjeta por CVE', str_contains((string)$dossier['html'], 'CVE-2026-90001')
        && str_contains((string)$dossier['html'], 'Equipos expuestos')
        && str_contains((string)$dossier['html'], 'CISA KEV'));
    check('informe: prioridad A+/A/B/C/D', (string)$dossier['max_priority'] !== ''
        && preg_match('/Prioridad (A\+|A|B|C|D)/', (string)$dossier['html']) === 1);
    check('informe: tabla de trabajo', str_contains((string)$dossier['html'], 'Tabla de trabajo')
        && str_contains((string)$dossier['markdown'], '## Tabla de trabajo'));
    check('informe: racimos', str_contains((string)$dossier['html'], 'Racimos por software'));
    check('informe: excepciones, verificación y decisiones',
        str_contains((string)$dossier['html'], 'Excepciones')
        && str_contains((string)$dossier['html'], 'Verificación')
        && str_contains((string)$dossier['html'], 'Decisiones'));
    check('informe: lectura de la IA al final', str_contains((string)$dossier['html'], 'Lectura del riesgo (IA)')
        && str_contains((string)$dossier['markdown'], 'Texto de prueba de la IA'));
    check('informe: contadores', (int)$dossier['count'] === count($groupRows)
        && (int)$dossier['tiers']['p1'] >= 1);

    $single = ExposedReportDossier::build($group, [$groupRows[0]], ExposedPriority::defaults(), null, (string)$groupRows[0]['cve_id']);
    check('informe: vista de un solo CVE',
        str_contains((string)$single['html'], '<h1')
        && str_contains((string)$single['html'], (string)$groupRows[0]['cve_id'])
        && (int)$single['count'] === 1);
    check('informe: tarjeta respirable', str_contains((string)$dossier['html'], '<ul')
        && str_contains((string)$dossier['html'], 'exposed-full-desc'));
    check('informe: markdown en viñetas', str_contains((string)$dossier['markdown'], '**Qué es**'));

    // Progreso de los informes por CVE (cve_ai_reports).
    $reportId = CveDatabase::insert(
        "INSERT INTO cve_ai_reports (cve_ids, title, status, token, no_ai, mode, total_items, processed_items)
         VALUES (?, ?, 'done', ?, 1, 'extended', 1, 1)",
        [json_encode([(string)$groupRows[0]['cve_id']], JSON_UNESCAPED_SLASHES), 'smoke grupo', bin2hex(random_bytes(8))]
    );
    ExposedConsoleStore::setGroupReports($groupId, [$reportId]);
    $gr = ExposedConsoleStore::groupReports($groupId);
    check('progreso: informe contado', (int)$gr['total'] === 1 && (int)$gr['processed'] === 1 && (int)$gr['done'] === 1);
    check('progreso: sin trabajo pendiente', empty($gr['has_job']));
    check('progreso: CVE del informe', ($gr['rows'][0]['cve_list'][0] ?? '') === (string)$groupRows[0]['cve_id']);

    // Informe conjunto con un ítem «done» y otro en «error»: el progreso debe
    // salir del detalle por CVE, no del estado global del informe.
    $partialReportId = CveDatabase::insert(
        "INSERT INTO cve_ai_reports (cve_ids, title, status, token, no_ai, mode, total_items, processed_items, ai_error)
         VALUES (?, ?, 'done', ?, 1, 'extended', 2, 2, '1 de 2 análisis fallaron: tiempo de espera agotado')",
        [
            json_encode([(string)$groupRows[0]['cve_id'], (string)$groupRows[1]['cve_id']], JSON_UNESCAPED_SLASHES),
            'smoke parcial', bin2hex(random_bytes(8)),
        ]
    );
    CveDatabase::insert(
        "INSERT INTO cve_ai_report_items (report_id, cve_id, position, status)
         VALUES (?, ?, 0, 'done')",
        [$partialReportId, (string)$groupRows[0]['cve_id']]
    );
    CveDatabase::insert(
        "INSERT INTO cve_ai_report_items (report_id, cve_id, position, status, ai_error)
         VALUES (?, ?, 1, 'error', 'Tiempo de espera agotado al llamar al modelo')",
        [$partialReportId, (string)$groupRows[1]['cve_id']]
    );
    ExposedConsoleStore::setGroupReports($groupId, [$partialReportId]);
    $grPartial = ExposedConsoleStore::groupReports($groupId);
    check('progreso: fallo contado por CVE',
        (int)$grPartial['total'] === 2 && (int)$grPartial['done'] === 1 && (int)$grPartial['failed'] === 1);
    check('progreso: informe parcial marcado', (int)$grPartial['failed_reports'] === 1);
    check('progreso: CVE fallido identificado',
        ($grPartial['rows'][0]['error_cves'][0]['cve_id'] ?? '') === (string)$groupRows[1]['cve_id']);
    check('progreso: detecta el timeout', !empty($grPartial['timeout']));
    check('progreso: sin trabajo pendiente', empty($grPartial['has_job']));

    // Troceado del plan: agrupa por software y no parte un racimo.
    $chunkMethod = new ReflectionMethod(Module_ExposedReport::class, 'planChunks');
    $chunkMethod->setAccessible(true);
    $chunks = $chunkMethod->invoke($module, $groupRows, 2);
    check('plan: se trocea en varias partes', count($chunks) >= 2);
    $flat = [];
    foreach ($chunks as $chunk) {
        $flat = array_merge($flat, $chunk);
    }
    check('plan: no pierde ningún CVE', count($flat) === count($groupRows));
    $clusterRows = [
        ['cve_id' => 'CVE-2026-91001', 'software_labels' => 'acme:server;other:lib'],
        ['cve_id' => 'CVE-2026-91002', 'software_labels' => 'acme:server'],
        ['cve_id' => 'CVE-2026-91003', 'software_labels' => 'zeta:app'],
    ];
    $clusterChunks = $chunkMethod->invoke($module, $clusterRows, 2);
    $clusterTogether = false;
    foreach ($clusterChunks as $chunk) {
        $ids = array_column($chunk, 'cve_id');
        if (in_array('CVE-2026-91001', $ids, true)) {
            $clusterTogether = in_array('CVE-2026-91002', $ids, true);
        }
    }
    check('plan: el racimo de software no se parte', $clusterTogether);

    // Vista del grupo: la hoja no debe llevar «md-body» (rompía el modo oscuro)
    // y debe avisar de que aún no hay análisis de IA.
    $groupHtml = $module->render('group', [
        'module'        => $module,
        'group'         => $group,
        'groupId'       => $groupId,
        'rows'          => $groupRows,
        'plan'          => null,
        'dossier'       => $dossier,
        'profiles'      => [],
        'orgs'          => [],
        'downloadName'  => 'informe.md',
    ]);
    check('vista grupo: hoja sin md-body', !str_contains($groupHtml, 'doc-sheet md-body'));
    check('vista grupo: aviso de que no es la IA', str_contains($groupHtml, 'Esto todavía no es el análisis de la IA'));
    check('vista grupo: informe renderizado', str_contains($groupHtml, 'Informe de vulnerabilidad')
        && str_contains($groupHtml, 'Sin análisis IA'));

    $groupHtmlProgress = $module->render('group', [
        'module'        => $module,
        'group'         => $group,
        'groupId'       => $groupId,
        'rows'          => $groupRows,
        'plan'          => null,
        'dossier'       => $dossier,
        'profiles'      => [],
        'orgs'          => [],
        'downloadName'  => 'informe.md',
        'groupReports'  => $gr,
    ]);
    check('vista grupo: tarjeta de progreso', str_contains($groupHtmlProgress, 'Análisis por CVE')
        && str_contains($groupHtmlProgress, '1/1 generados'));
    check('vista grupo: selector por CVE', str_contains($groupHtmlProgress, 'Por CVE…')
        && str_contains($groupHtmlProgress, 'Conjunto'));
    check('vista grupo: exportación con JS aunque no haya plan',
        str_contains($groupHtml, 'window.exposedDownloadMd')
        && str_contains($groupHtml, 'window.exposedDownloadHtml')
        && str_contains($groupHtml, 'window.exposedPrint')
        && str_contains($groupHtml, '@media print'));
    check('vista grupo: applyStyles respeta el estilo en línea',
        str_contains($groupHtml, "node.getAttribute('style')"));
    check('vista grupo: exportar sin informe avisa',
        str_contains($groupHtml, 'No hay informe que exportar.'));

    $groupHtmlRetry = $module->render('group', [
        'module'        => $module,
        'group'         => $group,
        'groupId'       => $groupId,
        'rows'          => $groupRows,
        'plan'          => null,
        'dossier'       => $dossier,
        'profiles'      => [],
        'orgs'          => [],
        'downloadName'  => 'informe.md',
        'groupReports'  => $grPartial,
    ]);
    check('vista grupo: botón de reintentar fallidos',
        str_contains($groupHtmlRetry, 'analyze-retry')
        && str_contains($groupHtmlRetry, 'Reintentar los 1 fallidos'));
    check('vista grupo: pista de timeout con enlace a Admin',
        str_contains($groupHtmlRetry, 'tiempo de espera del perfil')
        && str_contains($groupHtmlRetry, 'Admin → APIs'));
    check('vista grupo: informe parcial', str_contains($groupHtmlRetry, 'Parcial'));

    // Reintento: reabre solo los ítems en error y conserva los «done».
    $requeue = ExposedConsoleStore::requeueFailedReports($groupId);
    check('reintento: un informe reencolado', (int)$requeue['queued'] === 1);
    check('reintento: token nuevo', (string)($requeue['tokens'][$partialReportId] ?? '') !== '');
    $grRequeued = ExposedConsoleStore::groupReports($groupId);
    check('reintento: conserva el CVE ya generado',
        (int)$grRequeued['done'] === 1 && (int)$grRequeued['pending'] === 1);
    check('reintento: el fallo pasa a la cola', (int)$grRequeued['failed'] === 0);
    check('reintento: el trabajo vuelve a estar vivo', !empty($grRequeued['has_job']));
    $requeueAgain = ExposedConsoleStore::requeueFailedReports($groupId);
    check('reintento: no duplica trabajo pendiente', (int)$requeueAgain['queued'] === 0);

    $groupHtmlBack = $module->render('group', [
        'module'        => $module,
        'group'         => $group,
        'groupId'       => $groupId,
        'rows'          => $groupRows,
        'plan'          => null,
        'dossier'       => $dossier,
        'profiles'      => [],
        'orgs'          => [],
        'downloadName'  => 'informe.md',
        'backUrl'       => $baseUrlWithFilters = base_url('modules/exposed_report') . '?severity%5B%5D=critical',
    ]);
    check('vista grupo: volver conserva filtros', str_contains($groupHtmlBack, 'severity%5B%5D=critical'));

    $groupHtmlWithPlan = $module->render('group', [
        'module'        => $module,
        'group'         => $group,
        'groupId'       => $groupId,
        'rows'          => $groupRows,
        'plan'          => ['content_text' => "## Lectura del riesgo\n\nPlan.", 'content_html' => '<p>Plan.</p>',
                            'generated_at' => '2026-11-18 10:00:00', 'cve_count' => 3, 'model' => 'modelo-x'],
        'dossier'       => $dossier,
        'profiles'      => [],
        'orgs'          => [],
        'downloadName'  => 'informe.md',
    ]);
    check('vista grupo: etiqueta de lectura IA', str_contains($groupHtmlWithPlan, 'Lectura del riesgo IA')
        && !str_contains($groupHtmlWithPlan, 'Esto todavía no es el análisis de la IA'));
    check('vista grupo: botones de exportación', str_contains($groupHtmlWithPlan, 'exposedCopyRich')
        && str_contains($groupHtmlWithPlan, 'exposedDownloadMd'));

    /* -----------------------------------------------------------------
     * 10. Esquema y prompts
     * -------------------------------------------------------------- */

    $tables = array_column(
        CveDatabase::fetchAll("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'exposed_%'"),
        'name'
    );
    foreach (['exposed_snapshots', 'exposed_cves', 'exposed_groups', 'exposed_group_cves', 'exposed_group_plans'] as $table) {
        check('esquema: tabla ' . $table, in_array($table, $tables, true));
    }

    $cveCols = [];
    foreach (CveDatabase::query("PRAGMA table_info(exposed_cves)") as $col) {
        $cveCols[$col['name']] = $col;
    }
    check('esquema: PK única cve_id', isset($cveCols['cve_id']) && (int)$cveCols['cve_id']['pk'] === 1);
    check('esquema: sin snapshot_id', !isset($cveCols['snapshot_id']));
    check('esquema: huella y marcas de tiempo', isset($cveCols['fingerprint'], $cveCols['first_seen_at'], $cveCols['last_seen_at']));

    $catalog = llm_prompts_catalog();
    check('prompts: plan de actuación', isset($catalog['llm.exposed.action_plan']));
    check('prompts: plan en scope Equipos expuestos',
        ($catalog['llm.exposed.action_plan']['scope_label'] ?? '') === 'Equipos expuestos');
    $planPrompt = (string)($catalog['llm.exposed.action_plan']['default'] ?? '');
    check('prompts: el informe pide lectura del riesgo y notas',
        str_contains($planPrompt, 'Lectura del riesgo') && str_contains($planPrompt, 'Notas de ejecución'));
    check('prompts: el informe prohíbe inventar', stripos($planPrompt, 'no inventes') !== false);
    check('prompts: el informe no repite las tablas',
        stripos($planPrompt, 'no debes repetir') !== false);
    check('tareas: plan asignable', array_key_exists('exposed_action_plan', llm_task_catalog()));

    $module = ModuleManager::get('exposed_report');
    check('módulo: versión 2', $module instanceof Module_ExposedReport && $module->version() === '2.0.0');
    check('módulo: 15 rutas', $module !== null && count($module->routes()) === 15);

    /* -----------------------------------------------------------------
     * 11. Orden numérico del CVE (distinta longitud de secuencia)
     * -------------------------------------------------------------- */

    $numericCsv = $buildCsv([
        ['CVE-2026-10000', 'Low', '1.0', '0.0', 5, '01 Nov, 2026', '02 Nov, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'x:y', 1, 'menor', 'RemediationRequired'],
        ['CVE-2026-9000', 'Low', '1.0', '0.0', 5, '01 Nov, 2026', '02 Nov, 2026', '18 Nov, 2026', 'False', 'False', 'False', 'x:y', 1, 'menor', 'RemediationRequired'],
    ], $header);
    ExposedConsoleStore::importCsv($numericCsv, 'numeric.csv', 0);
    $numericAsc = array_map(
        static fn(array $row): string => (string)$row['cve_id'],
        array_slice(ExposedConsoleStore::rows(ExposedConsoleStore::filtersFromInput(['sort' => 'cve_asc']), 2, 0), 0, 2)
    );
    check('orden: CVE numérico (9000 antes que 10000)',
        $numericAsc === ['CVE-2026-9000', 'CVE-2026-10000'],
        implode(',', $numericAsc));
    check('orden: expresión SQL numérica',
        str_contains(ExposedConsoleStore::orderBy('cve_asc'), 'CAST(SUBSTR(e.cve_id, 5, 4) AS INTEGER)'));
} finally {
    if ($groupId > 0) {
        ExposedConsoleStore::deleteGroup($groupId);
    }
    // Restaura cve.sqlite tal y como estaba antes del test.
    CveDatabase::disconnect();
    if (is_file($dbPath)) {
        @unlink($dbPath);
    }
    foreach ($dbFiles as $file) {
        $dst = dirname($dbPath) . '/' . $file;
        if (is_file($dst)) {
            @unlink($dst);
        }
        if (is_file($backupDir . '/' . $file)) {
            @copy($backupDir . '/' . $file, $dst);
        }
    }
    foreach ($dbFiles as $file) {
        @unlink($backupDir . '/' . $file);
    }
    @rmdir($backupDir);
}

echo "\n" . ($total - $fail) . "/{$total} pruebas correctas\n";
echo $fail === 0 ? "OK\n" : "FALLOS: {$fail}\n";
exit($fail === 0 ? 0 : 1);
