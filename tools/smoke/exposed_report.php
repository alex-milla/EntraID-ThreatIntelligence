<?php
/**
 * Smoke test — módulo Equipos expuestos (exposed_report).
 *
 * Sin red y sin tocar las bases de CVE: solo el parser, el registro del
 * módulo, el catálogo de prompts y la vista.
 *
 * Uso: php tools/smoke/exposed_report.php
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
    echo "FALLA {$label}" . ($detail !== '' ? "\n     {$detail}" : '') . "\n";
}

/* =====================================================================
 * 1. Registro del módulo y navegación
 * ================================================================== */

$module = ModuleManager::get('exposed_report');
check('módulo registrado', $module instanceof Module_ExposedReport);
check('clave del módulo', $module !== null && $module->key() === 'exposed_report');
check('nombre visible', $module !== null && $module->name() === 'Equipos expuestos');
check('sin permisos Graph', $module !== null && $module->requiredPermissions() === []);
check('no sincronizable', $module !== null && $module->isSyncable() === false);
check('rutas registradas (2)', $module !== null && count($module->routes()) === 2);

$nav = $module?->getNavItem();
check('grupo Seguridad', is_array($nav) && ($nav['group'] ?? '') === 'Seguridad');
check('etiqueta del menú', is_array($nav) && ($nav['label'] ?? '') === 'Equipos expuestos');
check('ancla tras remediation', is_array($nav) && ($nav['after'] ?? '') === 'remediation');

$navLabels = array_map(static fn(array $n): string => (string)($n['label'] ?? ''), ModuleManager::getNavigation());
$remediationAt = array_search('Remediación', $navLabels, true);
$exposedAt = array_search('Equipos expuestos', $navLabels, true);
check('aparece en la navegación', $exposedAt !== false);
check('justo detrás de Remediación', $remediationAt !== false && $exposedAt === $remediationAt + 1,
    'remediation=' . var_export($remediationAt, true) . ' exposed=' . var_export($exposedAt, true));

/* =====================================================================
 * 2. Parser — CSV conforme a la especificación
 * ================================================================== */

$header = implode(',', ExposedReportParser::COLUMNS);

$csv = implode("\r\n", [
    $header,
    'srv01.contoso.com,High,WindowsServer2019,203.0.113.10,12,'
        . '"[""October 2026 Security Updates"",""October 2026 Security Updates (Last updated at Nov 1, 2026)"",""November 2026 Security Updates""]",'
        . '240,18,3,"[""CVE-2026-1111"",""CVE-2026-2222"",""CVE-2026-3333""]","Sep 8, 2026 10:00:00 PM",'
        . '"October 2026 Security Updates (Last updated at Nov 1, 2026)",64,1',
    'srv02.contoso.com,Medium,WindowsServer2022,203.0.113.11,2,'
        . '"[""November 2026 Security Updates"",""""]",30,1,0,"[]","Nov 10, 2026 6:30:00 PM",'
        . '"November 2026 Security Updates",1,0',
    '',
]);

$out = ExposedReportParser::parse($csv);
check('csv: parsea', $out['ok'], implode(' | ', $out['errors']));
check('csv: dos filas', count($out['rows']) === 2);
check('csv: sin avisos', $out['warnings'] === [], implode(' | ', $out['warnings']));
check('csv: servidores', (int)$out['stats']['servers'] === 2);
check('csv: High/Medium', (int)$out['stats']['high'] === 1 && (int)$out['stats']['medium'] === 1);
check('csv: con exploit', (int)$out['stats']['with_exploit'] === 1);
check('csv: CVEs totales', (int)$out['stats']['cves_total'] === 270);
check('csv: críticos totales', (int)$out['stats']['critical_total'] === 19);
check('csv: días máximos', (int)$out['stats']['max_days'] === 64);
check('csv: fecha más antigua', ($out['stats']['oldest'] ?? '') === '2026-09-08 22:00:00',
    (string)($out['stats']['oldest'] ?? ''));
check('csv: fecha legible', ($out['stats']['oldest_label'] ?? '') === '08/09/2026');

$first = $out['rows'][0] ?? [];
check('csv: dispositivo', ($first['device'] ?? '') === 'srv01.contoso.com');
check('csv: exposición', ($first['exposure'] ?? '') === 'High');
check('csv: KBs enteros', ($first['kbs'] ?? null) === 12);
check('csv: CVEs con exploit', ($first['exploit_cves'] ?? []) === ['CVE-2026-1111', 'CVE-2026-2222', 'CVE-2026-3333']);
check('csv: TieneExploit booleano', ($first['has_exploit'] ?? null) === true);
check('csv: fecha ISO', ($first['since'] ?? '') === '2026-09-08 22:00:00');
check('csv: paquetes deduplicados', ($first['packages'] ?? []) === ['October 2026 Security Updates', 'November 2026 Security Updates'],
    json_encode($first['packages'] ?? []));
check('csv: paquete más antiguo limpio', ($first['oldest_package'] ?? '') === 'October 2026 Security Updates');

$second = $out['rows'][1] ?? [];
check('csv: cadenas vacías ignoradas', ($second['packages'] ?? []) === ['November 2026 Security Updates']);
check('csv: exploit público vacío', ($second['exploit_cves'] ?? null) === []);
check('csv: sin exploit', ($second['has_exploit'] ?? null) === false);

check('csv: se conserva el CSV normalizado', substr_count($out['csv'], "\n") >= 1 && str_contains($out['csv'], 'srv02.contoso.com'));

/* =====================================================================
 * 3. Parser — BOM, cabecera y errores
 * ================================================================== */

$bom = "\xEF\xBB\xBF" . $csv;
$outBom = ExposedReportParser::parse($bom);
check('bom: parsea igual', $outBom['ok'] && count($outBom['rows']) === 2);
check('bom: el CSV enviado no lleva BOM', !str_starts_with($outBom['csv'], "\xEF\xBB\xBF"));

$empty = ExposedReportParser::parse('');
check('vacío: error', !$empty['ok'] && $empty['errors'] !== []);

$badHeader = ExposedReportParser::parse(str_replace('DiasSinParchear', 'Dias', $csv));
check('cabecera: error de contrato', !$badHeader['ok']);
check('cabecera: dice qué columna falla',
    str_contains(implode(' ', $badHeader['errors']), 'DiasSinParchear'));

$twoColumns = ExposedReportParser::parse("DeviceName,ExposureLevel\r\nsrv,High\r\n");
check('columnas: error por número', !$twoColumns['ok'] && str_contains(implode(' ', $twoColumns['errors']), '14'));

$onlyHeader = ExposedReportParser::parse($header . "\r\n");
check('sin filas: error', !$onlyHeader['ok']);

$nul = ExposedReportParser::parse($header . "\r\nsr\0v,High\r\n");
check('bytes nulos: error', !$nul['ok']);

/* =====================================================================
 * 4. Parser — avisos de coherencia (no bloquean)
 * ================================================================== */

$incoherent = implode("\r\n", [
    $header,
    'srv03.contoso.com,Low,WindowsServer2016,203.0.113.12,1,"[""October 2026 Security Updates""]",5,1,0,'
        . '"[""CVE-2026-9999""]","not-a-date","October 2026 Security Updates",99,1',
]);

$outBad = ExposedReportParser::parse($incoherent);
check('incoherencias: se genera igual', $outBad['ok'], implode(' | ', $outBad['errors']));
$joined = implode(' | ', $outBad['warnings']);
check('aviso: ExposureLevel', str_contains($joined, 'ExposureLevel'));
check('aviso: CVEsConExploit', str_contains($joined, 'CVEsConExploit'));
check('aviso: TieneExploit', str_contains($joined, 'TieneExploit'));
check('aviso: fecha', str_contains($joined, 'SinParchearDesde'));

$wrongDays = str_replace(',64,1', ',3,1', $csv);
$outDays = ExposedReportParser::parse($wrongDays);
check('aviso: DiasSinParchear', str_contains(implode(' | ', $outDays['warnings']), 'DiasSinParchear'));

/* =====================================================================
 * 5. Parser — límites
 * ================================================================== */

$manyRows = [$header];
for ($i = 1; $i <= ExposedReportParser::MAX_ROWS + 1; $i++) {
    $manyRows[] = 'srv' . $i . '.contoso.com,Medium,WindowsServer2022,203.0.113.12,1,"[]",1,0,0,"[]",'
        . '"Nov 10, 2026 6:30:00 PM","November 2026 Security Updates",1,0';
}
$overRows = ExposedReportParser::parse(implode("\r\n", $manyRows));
check('límite: más de MAX_ROWS se rechaza', !$overRows['ok']);
check('límite: el error explica el máximo',
    str_contains(implode(' ', $overRows['errors']), (string)ExposedReportParser::MAX_ROWS));

check('límite: maxUploadBytes acotado',
    ExposedReportParser::maxUploadBytes() > 0
    && ExposedReportParser::maxUploadBytes() <= ExposedReportParser::MAX_BYTES);
check('límite: iniBytes interpreta M', ExposedReportParser::iniBytes('8M') === 8388608);
check('límite: iniBytes interpreta K', ExposedReportParser::iniBytes('512K') === 524288);

/* =====================================================================
 * 6. Utilidades del parser
 * ================================================================== */

check('cleanPackage: quita el sufijo',
    ExposedReportParser::cleanPackage('October 2026 Security Updates (Last updated at Nov 1, 2026)')
    === 'October 2026 Security Updates');
check('cleanPackage: sin sufijo intacto',
    ExposedReportParser::cleanPackage('November 2026 Security Updates') === 'November 2026 Security Updates');

$parseDate = new ReflectionMethod('ExposedReportParser', 'parseDate');
check('fecha: formato inglés',
    $parseDate->invoke(null, 'Jan 27, 2026 5:34:24 PM') === '2026-01-27 17:34:24');
check('fecha: ISO',
    $parseDate->invoke(null, '2026-01-27 10:00:00') === '2026-01-27 10:00:00');
check('fecha: inválida devuelve null',
    $parseDate->invoke(null, 'no es una fecha') === null);

$sorted = ExposedReportParser::sortRows($out['rows']);
check('orden: exploit primero', ($sorted[0]['device'] ?? '') === 'srv01.contoso.com');

check('kql: consulta de origen', str_contains(ExposedReportParser::KQL, 'DeviceTvmSoftwareVulnerabilities')
    && str_contains(ExposedReportParser::KQL, 'IsInternetFacing'));
check('columnas: 14 y en orden',
    ExposedReportParser::COLUMNS === [
        'DeviceName', 'ExposureLevel', 'OSPlatform', 'PublicIP', 'KBsPendientes',
        'PaquetesPendientes', 'CVEs', 'Criticos', 'ExploitsPublicos', 'CVEsConExploit',
        'SinParchearDesde', 'PaqueteMasAntiguo', 'DiasSinParchear', 'TieneExploit',
    ]);

/* =====================================================================
 * 7. Prompts editables
 * ================================================================== */

$catalog = llm_prompts_catalog();
foreach (['llm.exposed.compact', 'llm.exposed.detailed', 'llm.exposed.spec'] as $key) {
    check('prompt: existe ' . $key, isset($catalog[$key]));
    check('prompt: scope Equipos expuestos · ' . $key,
        ($catalog[$key]['scope_label'] ?? '') === 'Equipos expuestos');
    check('prompt: default no vacío · ' . $key,
        trim((string)($catalog[$key]['default'] ?? '')) !== '');
}

$compact = (string)$catalog['llm.exposed.compact']['default'];
check('prompt compacto: 3 secciones', str_contains($compact, '1. Resumen')
    && str_contains($compact, '2. Tabla única') && str_contains($compact, '3. Top 3 acciones'));
check('prompt compacto: reglas de cota inferior', str_contains($compact, 'cota inferior'));
check('prompt compacto: reinicia la numeración', str_contains($compact, 'reinicia la numeración'));

$detailed = (string)$catalog['llm.exposed.detailed']['default'];
check('prompt detallado: exige el JSON', str_contains($detailed, 'JSON'));

$specRaw = (string)$catalog['llm.exposed.spec']['default'];
check('especificación: marcador {kql}', str_contains($specRaw, '{kql}'));
$spec = llm_prompt('llm.exposed.spec', $specRaw, ['{kql}' => ExposedReportParser::kqlJson()]);
$decoded = json_decode($spec, true);
check('especificación: JSON válido', is_array($decoded), json_last_error_msg());
check('especificación: 14 campos', is_array($decoded) && count($decoded['esquema_campos'] ?? []) === 14);
check('especificación: 8 secciones', is_array($decoded) && count($decoded['estructura_requerida_del_informe'] ?? []) === 8);
check('especificación: KQL sustituida', is_array($decoded)
    && str_contains((string)($decoded['metodologia_kql'] ?? ''), 'DeviceInfo'));

/* =====================================================================
 * 7 bis. Detalle de CVE (anexo determinista)
 * ================================================================== */

check('enriquecimiento: fuentes definidas',
    array_keys(ExposedReportEnrichment::SOURCES) === ['none', 'catalog', 'inventory']);

$exploitCves = ExposedReportEnrichment::collectExploitCves($out['rows']);
check('enriquecimiento: CVE con exploit del CSV', $exploitCves === ['CVE-2026-1111', 'CVE-2026-2222', 'CVE-2026-3333'],
    json_encode($exploitCves));
check('enriquecimiento: ignora CVE mal formados',
    ExposedReportEnrichment::collectExploitCves([['exploit_cves' => ['no-es-cve', 'CVE-2026-9']]]) === []);

// Inventario V2 sin sincronizar (instalación de pruebas)
check('enriquecimiento: inventario disponible solo con datos',
    ExposedReportEnrichment::inventoryAvailable() === false);
$annexNoInventory = ExposedReportEnrichment::annexInventory($out['rows']);
check('enriquecimiento: V2 sin datos avisa', $annexNoInventory['markdown'] === ''
    && is_string($annexNoInventory['notice']) && $annexNoInventory['notice'] !== '');

// Catálogo V1: se siembra un CVE de prueba y se limpia al final.
$testCve = 'CVE-2099-0001';
$seeded = false;
try {
    CveDatabase::query(
        "INSERT INTO cve_catalog (cve_id, description, severity, cvss_v3_score, published_at, nvd_url)
         VALUES (?, 'Descripción de prueba', 'critical', 9.8, '2026-01-27', 'https://example.invalid/cve')",
        [$testCve]
    );
    CveDatabase::query("INSERT INTO cve_epss (cve_id, epss, percentile, score_date) VALUES (?, 0.42, 0.97, '2026-11-01')", [$testCve]);
    CveDatabase::query(
        "INSERT INTO cve_kev (cve_id, vulnerability_name, known_ransomware, due_date) VALUES (?, 'Prueba KEV', 'Known', '2026-02-10')",
        [$testCve]
    );
    CveDatabase::query(
        "INSERT INTO cve_exploit (cve_id, source, title, url, published_at) VALUES (?, 'github', 'PoC', 'https://example.invalid/poc', '2026-01-28')",
        [$testCve]
    );
    $seeded = true;

    check('catálogo: disponible con datos', ExposedReportEnrichment::catalogAvailable() === true);

    $catalog = ExposedReportEnrichment::fromCatalog([$testCve, 'CVE-2099-9999']);
    check('catálogo: devuelve el CVE sembrado', isset($catalog[$testCve]));
    check('catálogo: severidad', ($catalog[$testCve]['severity'] ?? '') === 'critical');
    check('catálogo: CVSS', ($catalog[$testCve]['cvss'] ?? null) === 9.8);
    check('catálogo: EPSS', ($catalog[$testCve]['epss'] ?? null) === 0.42);
    check('catálogo: KEV', ($catalog[$testCve]['kev'] ?? false) === true);
    check('catálogo: exploits', ($catalog[$testCve]['exploits'] ?? 0) === 1);
    check('catálogo: descripción', ($catalog[$testCve]['description'] ?? '') === 'Descripción de prueba');
    check('catálogo: no inventa los ausentes', !isset($catalog['CVE-2099-9999']));

    $rowsForAnnex = [[
        'device'       => 'srv01.contoso.com',
        'exposure'     => 'High',
        'exploit_cves' => [$testCve],
    ], [
        'device'       => 'srv02.contoso.com',
        'exposure'     => 'Medium',
        'exploit_cves' => ['CVE-2099-9999'],
    ]];
    $annex = ExposedReportEnrichment::annexCatalog($rowsForAnnex, $catalog);
    check('anexo C: se genera', str_contains($annex['markdown'], 'Anexo C. Detalle de los CVE'));
    check('anexo C: cabecera de tabla', str_contains($annex['markdown'], '| Servidor | CVE | Severidad | CVSS | EPSS | KEV | Exploit | Publicado |'));
    check('anexo C: fila con datos', str_contains($annex['markdown'], 'Crítica') && str_contains($annex['markdown'], '9,8'));
    check('anexo C: EPSS en porcentaje', str_contains($annex['markdown'], '42,0 %'));
    check('anexo C: KEV', str_contains($annex['markdown'], '| Sí |'));
    check('anexo C: fuentes de exploit', str_contains($annex['markdown'], '1 fuente'));
    check('anexo C: CVE ausente marcado con —', str_contains($annex['markdown'], 'CVE-2099-9999'));
    check('anexo C: avisa de los ausentes',
        str_contains($annex['markdown'], 'no constan en el catálogo local'));

    check('anexo C: sin CVE en el CSV no genera tabla',
        ExposedReportEnrichment::annexCatalog([['exploit_cves' => []]], $catalog)['markdown'] === '');

    // Catálogo sin datos para TODOS los CVE: se listan los identificadores.
    $onlyMissing = ExposedReportEnrichment::annexCatalog([
        ['device' => 'srv03.contoso.com', 'exploit_cves' => ['CVE-2099-8888']],
    ], []);
    check('anexo C: sin cobertura no pinta tabla',
        !str_contains($onlyMissing['markdown'], '| Servidor | CVE |')
        && str_contains($onlyMissing['markdown'], 'CVE-2099-8888'));
    check('anexo C: sin cobertura avisa en la interfaz',
        is_string($onlyMissing['notice']) && $onlyMissing['notice'] !== '');
} catch (Throwable $e) {
    check('catálogo: preparación de la prueba', false, $e->getMessage());
} finally {
    if ($seeded) {
        try {
            CveDatabase::query("DELETE FROM cve_catalog WHERE cve_id = ?", [$testCve]);
            CveDatabase::query("DELETE FROM cve_epss WHERE cve_id = ?", [$testCve]);
            CveDatabase::query("DELETE FROM cve_kev WHERE cve_id = ?", [$testCve]);
            CveDatabase::query("DELETE FROM cve_exploit WHERE cve_id = ?", [$testCve]);
        } catch (Throwable $e) {
            // nada que limpiar
        }
    }
}
check('catálogo: la prueba no deja datos',
    CveDatabase::fetchOne("SELECT cve_id FROM cve_catalog WHERE cve_id = ?", [$testCve]) === null);

/* =====================================================================
 * 8. La vista se renderiza
 * ================================================================== */

$viewData = [
    'module'           => $module,
    'profiles'         => [],
    'defaultProfileId' => null,
    'profileId'        => 0,
    'llmConfigured'    => false,
    'isAdmin'          => false,
    'kql'              => ExposedReportParser::KQL,
    'columns'          => ExposedReportParser::COLUMNS,
    'maxUploadLabel'   => ExposedReportParser::formatBytes(ExposedReportParser::maxUploadBytes()),
    'maxRows'          => ExposedReportParser::MAX_ROWS,
    'error'            => null,
    'errors'           => [],
    'warnings'         => [],
    'warningsTotal'    => 0,
    'stats'            => null,
    'reportMd'         => '',
    'reportHtml'       => '',
    'mode'             => 'compact',
    'filename'         => '',
    'elapsedMs'        => 0,
    'downloadName'     => '',
    'enrich'           => ExposedReportEnrichment::SOURCE_CATALOG,
    'enrichNotice'     => null,
    'enrichSources'    => ExposedReportEnrichment::SOURCES,
    'catalogAvailable' => ExposedReportEnrichment::catalogAvailable(),
    'inventoryAvailable' => ExposedReportEnrichment::inventoryAvailable(),
];

$html = $module !== null ? $module->render('index', $viewData) : '';
check('vista: renderiza', $html !== '' && !str_contains($html, 'Vista no encontrada'));
check('vista: muestra la KQL', str_contains($html, 'IsInternetFacing'));
check('vista: la KQL va en una nota plegada', str_contains($html, 'Notas técnicas · consulta de origen (KQL)')
    && str_contains($html, '<details'));
check('vista: sin tarjeta de consulta arriba', !str_contains($html, '1 · Consulta de origen'));
check('vista: explica que la IA no está configurada', str_contains($html, 'La IA no está configurada'));
check('vista: aviso de límites', str_contains($html, (string)ExposedReportParser::MAX_ROWS));
check('vista: selector de detalle de CVE', str_contains($html, 'name="enrich"'));
check('vista: inventario deshabilitado sin datos', str_contains($html, 'sin inventario sincronizado'));

$viewWithReport = $viewData;
$viewWithReport['stats'] = $out['stats'];
$viewWithReport['reportMd'] = "# Informe\n\nPrueba";
$viewWithReport['reportHtml'] = render_ai_markdown($viewWithReport['reportMd']);
$viewWithReport['mode'] = 'detailed';
$viewWithReport['filename'] = 'export.csv';
$viewWithReport['downloadName'] = 'informe-parcheo-20261111-1200.md';
$htmlReport = $module !== null ? $module->render('index', $viewWithReport) : '';
check('vista: pinta el informe', str_contains($htmlReport, 'Informe generado'));
check('vista: hoja de documento', str_contains($htmlReport, 'id="doc-sheet"') && str_contains($htmlReport, 'class="doc-sheet"'));
check('vista: vista Markdown disponible', str_contains($htmlReport, 'id="doc-raw"') && str_contains($htmlReport, 'showDocView(\'markdown\')'));
check('vista: copiar con formato', str_contains($htmlReport, 'copyRich()') && str_contains($htmlReport, 'Copiar informe'));
check('vista: copiar Markdown', str_contains($htmlReport, 'copyMarkdown()'));
check('vista: descarga html y md', str_contains($htmlReport, 'downloadHtml()') && str_contains($htmlReport, 'downloadMd()'));
check('vista: imprimir/PDF', str_contains($htmlReport, 'printReport()'));
check('vista: botón de descarga', str_contains($htmlReport, 'informe-parcheo-20261111-1200.md'));
check('vista: KPIs deterministas', str_contains($htmlReport, 'Con exploit público'));
check('vista: ciclos pendientes', str_contains($htmlReport, 'October 2026 Security Updates'));

/* =====================================================================
 * Resultado
 * ================================================================== */

echo PHP_EOL . ($fail === 0 ? 'OK' : 'FALLOS') . ': ' . ($total - $fail) . '/' . $total . PHP_EOL;
exit($fail === 0 ? 0 : 1);
