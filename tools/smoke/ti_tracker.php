<?php
/**
 * ti_tracker.php — Pruebas del módulo Seguimiento TI (sin red).
 *
 *   php tools/smoke/ti_tracker.php
 *
 * Verifica:
 *   · registro del módulo y sus rutas
 *   · almacén de búsquedas en una base temporal (alta, edición, borrado)
 *   · seguimiento de IOCs vistos y cálculo de novedades
 *   · recorte de días según la fuente (API 7 / base local 190)
 *   · exportación STIX, MISP y TXT con las opciones de la búsqueda
 *   · que la base real y las vistas no se tocan
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

/* ============================================================
 * 1. Base temporal aislada
 * ============================================================ */
$tmpDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'ti_tracker_smoke_' . bin2hex(random_bytes(4));
@mkdir($tmpDir, 0770, true);
$dbPath = $tmpDir . DIRECTORY_SEPARATOR . 'ti_tracker.sqlite';

try {
    $store = new TiTrackerStore($dbPath);
    check('Base temporal creada', is_file($dbPath));

    /* ============================================================
     * 2. CRUD de búsquedas
     * ============================================================ */
    $filters = ThreatfoxQuery::normalize([
        'source' => 'db', 'mode' => 'recent', 'search_term' => 'cobalt',
        'days' => 30, 'f_conf' => 80,
    ]);
    $filters['days'] = TiTrackerRunner::clampDays('db', 30);

    $id = $store->saveSearch([
        'name'         => 'Cobalt Strike',
        'notes'        => 'Revisar novedades cada mañana',
        'filters'      => $filters,
        'formats'      => ['stix', 'misp', 'txt'],
        'tlp'          => 'amber',
        'valid_days'   => 365,
        'source_name'  => 'abuse.ch ThreatFox',
        'threat_actor' => 'APT28',
        'extra_tags'   => 'c2',
    ]);
    check('Alta: devuelve id', $id > 0, 'id=' . $id);
    check('Alta: una búsqueda guardada', $store->count() === 1);

    $saved = $store->getSearch($id);
    check('Lectura: nombre guardado', ($saved['name'] ?? '') === 'Cobalt Strike');
    check('Lectura: filtros decodificados', ($saved['filters']['term'] ?? '') === 'cobalt');
    check('Lectura: formatos decodificados', ($saved['formats'] ?? []) === ['stix', 'misp', 'txt']);
    check('Lectura: opciones de export', ($saved['tlp'] ?? '') === 'amber' && (int)$saved['valid_days'] === 365);

    $store->saveSearch([
        'name'         => 'Cobalt Strike',
        'notes'        => 'Actualizada',
        'filters'      => $filters,
        'formats'      => ['stix'],
        'tlp'          => 'red',
        'valid_days'   => 90,
        'source_name'  => 'abuse.ch ThreatFox',
        'threat_actor' => '',
        'extra_tags'   => '',
    ], $id);
    $updated = $store->getSearch($id);
    check('Edición: no crea otra búsqueda', $store->count() === 1);
    check('Edición: guarda TLP y formatos', ($updated['tlp'] ?? '') === 'red' && ($updated['formats'] ?? []) === ['stix']);

    /* ============================================================
     * 3. Seguimiento y novedades
     * ============================================================ */
    $row = static fn(string $ioc): array => [
        'id' => 'id-' . md5($ioc), 'ioc' => $ioc, 'ioc_type' => 'domain',
        'confidence_level' => 90, 'first_seen' => '2026-11-01 00:00:00 UTC',
    ];

    $first = $store->markRun($id, [$row('a.example'), $row('b.example'), $row('c.example')], 'db');
    check('Primera ejecución: 3 filas', (int)$first['rows'] === 3);
    check('Primera ejecución: 3 novedades', (int)$first['new'] === 3);
    check('Primera ejecución: seguimiento = 3', $store->trackedCount($id) === 3);

    $second = $store->markRun($id, [$row('a.example'), $row('b.example'), $row('d.example')], 'db');
    check('Segunda ejecución: 3 filas', (int)$second['rows'] === 3);
    check('Segunda ejecución: solo 1 novedad', (int)$second['new'] === 1);
    check('Segunda ejecución: novedad identificada', ($second['new_iocs'] ?? []) === ['d.example']);
    check('Segunda ejecución: seguimiento = 4', $store->trackedCount($id) === 4);

    $empty = $store->markRun($id, [], 'db');
    check('Ejecución vacía: sin novedades', (int)$empty['new'] === 0);

    $history = $store->history($id, 10);
    check('Historial: tres ejecuciones', count($history) === 3);
    check('Historial: tipo run', ($history[0]['kind'] ?? '') === 'run');

    $store->logExport($id, 'stix', 4, 'iocs_stix_test.json');
    $history = $store->history($id, 10);
    check('Historial: exportación registrada', ($history[0]['kind'] ?? '') === 'export'
        && (int)$history[0]['rows'] === 4);

    $listed = $store->listSearches();
    check('Listado: una fila', count($listed) === 1);
    check('Listado: IOCs en seguimiento', (int)($listed[0]['tracked'] ?? 0) === 4);
    check('Listado: última ejecución informada', ($listed[0]['last_run_at'] ?? '') !== '');

    $totals = $store->totals();
    check('Totales: seguimiento global', (int)$totals['tracked'] === 4);
    check('Totales: exportaciones', (int)$totals['exports'] === 1);

    /* ============================================================
     * 4. Filtros y ventana de días
     * ============================================================ */
    check('Días: base local hasta 190', TiTrackerRunner::clampDays('db', 500) === TI_TRACKER_DAYS_DB_MAX);
    check('Días: API máximo 7', TiTrackerRunner::clampDays('api', 30) === THREATFOX_DAYS_MAX);
    check('Días: negativos a 0', TiTrackerRunner::clampDays('db', -3) === 0);

    $effective = TiTrackerRunner::filtersFor($saved);
    check('Filtros efectivos: conserva el término', ($effective['term'] ?? '') === 'cobalt');
    check('Filtros efectivos: días recortados', (int)($effective['days'] ?? -1) === 30);

    /* Un filtro benigno contra la base real: no escribe ni llama a la red. */
    $probe = ThreatfoxQuery::normalize(['source' => 'db', 'mode' => 'recent', 'days' => 7]);
    $probeRows = TiTrackerRunner::resolveRows($probe);
    check('Runner: consulta la base local', is_array($probeRows));
    check(
        'Runner: filas normalizadas (tags_list)',
        array_reduce($probeRows, static fn($ok, $r) => $ok && array_key_exists('tags_list', $r), true)
    );

    /* ============================================================
     * 5. Exportación con las opciones de la búsqueda
     * ============================================================ */
    $exporter = new ThreatfoxExport('amber', 365, [
        'sourceName'    => 'abuse.ch ThreatFox',
        'threatActor'   => 'APT28',
        'tags'          => 'c2',
        'indicatorType' => 'malicious-activity',
        'confidence'    => null,
        'ip_direction'  => 'ip-dst',
    ]);
    $sample = [
        $row('evil.example') + ['tags' => 'c2', 'reference' => ''],
        $row('good.example') + ['tags' => '', 'reference' => ''],
    ];

    $stix = $exporter->files($sample, 'stix', false);
    $bundle = json_decode((string)($stix['files'][0]['content'] ?? ''), true);
    check('Export STIX: bundle único', count($stix['files']) === 1 && ($bundle['type'] ?? '') === 'bundle');
    check('Export STIX: indicadores', count(array_filter((array)($bundle['objects'] ?? []),
        static fn($o) => ($o['type'] ?? '') === 'indicator')) === 2);

    $misp = $exporter->files($sample, 'misp', false);
    $event = json_decode((string)($misp['files'][0]['content'] ?? ''), true);
    check('Export MISP: evento con atributos', isset($event['Event']['Attribute']));

    $txt = $exporter->files($sample, 'txt', false);
    $lines = explode("\n", trim((string)($txt['files'][0]['content'] ?? '')));
    check('Export TXT: un IOC por línea', $lines === ['evil.example', 'good.example']);

    /* ============================================================
     * 6. Borrado
     * ============================================================ */
    $store->deleteSearch($id);
    check('Borrado: sin búsquedas', $store->count() === 0);
    check('Borrado: sin seguimiento', $store->trackedCount() === 0);

    foreach (['ti_tracker.sqlite', 'ti_tracker.sqlite-wal', 'ti_tracker.sqlite-shm'] as $file) {
        @unlink($tmpDir . DIRECTORY_SEPARATOR . $file);
    }
    @rmdir($tmpDir);
} catch (Throwable $e) {
    @unlink($dbPath);
    @rmdir($tmpDir);
    echo "FALLO excepción: " . $e->getMessage() . "\n";
    $fail++;
    $total++;
}

/* ============================================================
 * 7. Registro y rutas del módulo
 * ============================================================ */
$module = ModuleManager::get('ti_tracker');
check('Módulo: cargado en ModuleManager', $module !== null);
check('Módulo: clave correcta', $module !== null && $module->key() === 'ti_tracker');
check('Módulo: nombre visible', $module !== null && $module->name() === 'Seguimiento TI TF');
$dbName = (string)(Database::fetchOne("SELECT name FROM modules WHERE module_key = 'ti_tracker'")['name'] ?? '');
check('Módulo: nombre sincronizado en la BD', $dbName === 'Seguimiento TI TF', 'bd=' . $dbName);
check('Módulo: no sincroniza por tenant', $module !== null && $module->isSyncable() === false);
check('Módulo: sin permisos de Graph', $module !== null && $module->requiredPermissions() === []);
check('Módulo: grupo de navegación Inteligencia', ($module?->getNavItem()['group'] ?? '') === 'Inteligencia');

$patterns = array_map(static fn($r) => $r['pattern'], $module?->routes() ?? []);
foreach (['', 'new', 'edit/{id}', 'save', 'delete/{id}', 'run/{id}', 'export/{id}'] as $pattern) {
    check('Ruta registrada: /' . $pattern, in_array($pattern, $patterns, true));
}

/* Orden de navegación: Seguimiento TI debe quedar justo debajo de su módulo. */
$navKeys = array_map(
    static fn(array $item): string => basename((string)(parse_url((string)($item['url'] ?? ''), PHP_URL_PATH) ?? '')),
    ModuleManager::getNavigation()
);
$tiAt = array_search('threat_intelligence', $navKeys, true);
$tfAt = array_search('threatfox', $navKeys, true);
$ttAt = array_search('ti_tracker', $navKeys, true);
check(
    'Navegación: IOCs ThreatFox tras Threat Intel',
    is_int($tiAt) && is_int($tfAt) && $tfAt === $tiAt + 1,
    'indices=' . var_export([$tiAt, $tfAt], true)
);
check(
    'Navegación: Seguimiento TI justo debajo de IOCs ThreatFox',
    is_int($tfAt) && is_int($ttAt) && $ttAt === $tfAt + 1,
    'indices=' . var_export([$tfAt, $ttAt], true)
);

/* ============================================================
 * 8. Vistas y cron
 * ============================================================ */
$views = ['index', 'edit', 'run'];
foreach ($views as $view) {
    $path = MODULES_PATH . '/ti_tracker/views/' . $view . '.php';
    check('Vista presente: ' . $view, is_file($path));
}

$indexSource = (string)@file_get_contents(MODULES_PATH . '/ti_tracker/views/index.php');
check('Panel: botones de exportación', str_contains($indexSource, 'data-tt-export'));
check('Panel: confirmación de borrado', str_contains($indexSource, 'data-confirm-danger'));
check('Panel: formulario CSRF', str_contains($indexSource, 'Csrf::field'));

$editSource = (string)@file_get_contents(MODULES_PATH . '/ti_tracker/views/edit.php');
check('Formulario: formatos STIX/MISP/TXT', str_contains($editSource, 'formats[]'));
check('Formulario: ventana de días acotada', str_contains($editSource, 'TI_TRACKER_DAYS_DB_MAX'));

$runSource = (string)@file_get_contents(MODULES_PATH . '/ti_tracker/views/run.php');
check('Resultados: Primera vez visible en la tabla', str_contains($runSource, '<th>Primera vez</th>'));
check('Resultados: columna Estado (Nuevo/Ya visto)', str_contains($runSource, '>Estado<'));
check(
    'Resultados: ficha de detalle (JSON + botón Ver)',
    str_contains($runSource, 'tt-detail-data') && str_contains($runSource, 'data-tt-detail')
);

$moduleSource = (string)@file_get_contents(MODULES_PATH . '/ti_tracker/module.php');
check(
    'Resultados: ficha con los campos de IOCs ThreatFox',
    str_contains($moduleSource, "'Ingestado'")
        && str_contains($moduleSource, "'Tipo de amenaza'")
        && str_contains($moduleSource, "'Última vez'")
);

check('Cron: refresco del seguimiento', is_file(ROOT_PATH . '/cron/ti-tracker-run.php'));
check(
    'Cron: usa el runner compartido',
    str_contains((string)@file_get_contents(ROOT_PATH . '/cron/ti-tracker-run.php'), 'TiTrackerRunner::execute')
);

/* ============================================================
 * Resumen
 * ============================================================ */
echo "\n" . ($fail === 0 ? 'TODO OK' : 'FALLOS') . ": " . ($total - $fail) . "/{$total}\n";
exit($fail === 0 ? 0 : 1);
