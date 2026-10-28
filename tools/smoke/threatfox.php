<?php
/**
 * threatfox.php — Pruebas del módulo IOCs ThreatFox (sin red).
 *
 *   php tools/smoke/threatfox.php
 *
 * Verifica:
 *   · normalización y acotado de los filtros de la interfaz
 *   · detección del tipo de término en modo automático
 *   · consultas a la base local (filtros, multi-término y paginación)
 *   · exportación CSV, JSON, TXT, STIX 2.1 (bundle/split) y MISP
 *   · que la API sin Auth-Key devuelve un aviso y no llama a la red
 *
 * Usa la base real de storage/threatfox.sqlite en modo solo lectura.
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

$store = new ThreatfoxStore();
$dbTotal = $store->count();

/* ============================================================
 * 1. Base local
 * ============================================================ */
check('Base local: hay IOCs cargados', $dbTotal > 0, 'total=' . $dbTotal);

$stats = $store->stats();
check('Stats: total coincide con count()', (int)$stats['total'] === $dbTotal);
check('Stats: familias de malware > 0', (int)$stats['malware'] > 0, 'malware=' . $stats['malware']);
check('Stats: rango de fechas informado', $stats['oldest'] !== '' && $stats['newest'] !== '');

$catalogs = ThreatfoxQuery::catalogs();
check('Catálogos: tipos de IOC no vacíos', count($catalogs['ioc_type']) > 0);
check('Catálogos: tipos de amenaza no vacíos', count($catalogs['threat_type']) > 0);

/* ============================================================
 * 2. Normalización de filtros
 * ============================================================ */
$f = ThreatfoxQuery::normalize([]);
check('Normaliza: fuente por defecto = db', $f['source'] === 'db');
check('Normaliza: modo por defecto = auto', $f['mode'] === 'auto');
check('Normaliza: límite acotado a 1000', ThreatfoxQuery::normalize(['limit' => 99999])['limit'] === 1000);
check('Normaliza: límite mínimo 1', ThreatfoxQuery::normalize(['limit' => 0])['limit'] >= 1);
check('Normaliza: días acotados a 7', ThreatfoxQuery::normalize(['days' => 99])['days'] === 7);
check('Normaliza: días negativos a 0', ThreatfoxQuery::normalize(['days' => -5])['days'] === 0);
check('Normaliza: confianza acotada a 100', ThreatfoxQuery::normalize(['f_conf' => 250])['conf'] === 100);
check('Normaliza: fuente inválida cae a db', ThreatfoxQuery::normalize(['source' => 'ftp'])['source'] === 'db');
check('Normaliza: modo inválido cae a auto', ThreatfoxQuery::normalize(['mode' => 'x'])['mode'] === 'auto');
check(
    'Normaliza: multi-término separado por comas',
    ThreatfoxQuery::normalize(['search_term' => 'c2, ransomware'])['terms'] === ['c2', 'ransomware']
);
check(
    'Normaliza: término truncado a 300 caracteres',
    strlen(ThreatfoxQuery::normalize(['search_term' => str_repeat('a', 500)])['term']) === 300
);
check(
    'Normaliza: caracteres de control eliminados',
    !str_contains(ThreatfoxQuery::normalize(['search_term' => "a\x00b"])['term'], "\x00")
);

/* ============================================================
 * 3. Detección del tipo de término (modo auto)
 * ============================================================ */
$detect = [
    'md5'     => str_repeat('a', 32),
    'sha1'    => str_repeat('b', 40),
    'sha256'  => str_repeat('c', 64),
    'url'     => 'http://evil.example/payload',
    'ip:port' => '185.10.10.10:8443',
    'ip'      => '185.10.10.10',
    'domain'  => 'evil.example.com',
    'text'    => 'cobalt strike',
];
foreach ($detect as $expected => $term) {
    check(
        'Detección: ' . $expected,
        ThreatfoxQuery::detectTermType($term) === $expected,
        'obtenido=' . ThreatfoxQuery::detectTermType($term)
    );
}

/* ============================================================
 * 4. Consultas a la base local
 * ============================================================ */
$base = ThreatfoxQuery::normalize(['source' => 'db', 'mode' => 'recent', 'days' => 7]);
$recent = ThreatfoxQuery::run($base, 1);
check('DB recientes (7 d): estado ok', $recent['status'] === 'ok', $recent['status']);
check('DB recientes (7 d): hay filas', count($recent['rows']) > 0);
check('DB recientes (7 d): total ≥ filas de la página', $recent['total'] >= count($recent['rows']));
check('DB recientes (7 d): 50 por página', (int)$recent['perPage'] === THREATFOX_PAGE_SIZE);

$all = ThreatfoxQuery::normalize(['source' => 'db', 'mode' => 'recent', 'days' => 0]);
$allResult = ThreatfoxQuery::run($all, 1);
check('DB sin ventana de días: más filas que 7 días', $allResult['total'] >= $recent['total']);

$byType = ThreatfoxQuery::normalize(['source' => 'db', 'mode' => 'recent', 'days' => 0, 'f_ioc_type' => 'domain']);
$byTypeResult = ThreatfoxQuery::run($byType, 1);
check('DB filtro por tipo: hay resultados', $byTypeResult['status'] === 'ok');
check(
    'DB filtro por tipo: todas las filas son del tipo',
    array_reduce($byTypeResult['rows'], static fn($ok, $row) => $ok && $row['ioc_type'] === 'domain', true)
);

$byConf = ThreatfoxQuery::normalize(['source' => 'db', 'mode' => 'recent', 'days' => 0, 'f_conf' => 90]);
$byConfResult = ThreatfoxQuery::run($byConf, 1);
check(
    'DB filtro por confianza: ninguna fila por debajo',
    array_reduce($byConfResult['rows'], static fn($ok, $row) => $ok && (int)$row['confidence_level'] >= 90, true)
);

$byRef = ThreatfoxQuery::normalize(['source' => 'db', 'mode' => 'recent', 'days' => 0, 'f_ref' => 1]);
$byRefResult = ThreatfoxQuery::run($byRef, 1);
check(
    'DB filtro con referencia: todas tienen referencia',
    array_reduce($byRefResult['rows'], static fn($ok, $row) => $ok && $row['reference'] !== '', true)
);

$multi = ThreatfoxQuery::normalize(['source' => 'db', 'mode' => 'recent', 'days' => 0, 'search_term' => 'win,sync']);
$multiResult = ThreatfoxQuery::run($multi, 1);
$multiOk = true;
foreach ($multiResult['rows'] as $row) {
    $haystack = strtolower($row['ioc'] . ' ' . $row['malware'] . ' ' . $row['malware_printable'] . ' ' . $row['tags']);
    if (!str_contains($haystack, 'win') || !str_contains($haystack, 'sync')) {
        $multiOk = false;
        break;
    }
}
check('DB multi-término: cada fila contiene todos los términos', $multiOk);

$sorted = $store->query([], 50, 0);
$confidences = array_map(static fn($r) => (int)$r['confidence_level'], $sorted);
$sortedCopy = $confidences;
rsort($sortedCopy);
check('DB orden: confianza descendente', $confidences === $sortedCopy);

$clamped = ThreatfoxQuery::run(['source' => 'db', 'mode' => 'recent', 'days' => 0] + ThreatfoxQuery::normalize([]), 9999);
check(
    'DB paginación: la página se recorta al rango válido',
    (int)$clamped['page'] === (int)$clamped['totalPages']
);

$injection = ThreatfoxQuery::normalize([
    'source' => 'db', 'mode' => 'recent', 'days' => 0,
    'search_term' => "' OR 1=1 --",
]);
$injectionResult = ThreatfoxQuery::run($injection, 1);
check(
    'DB entrada hostil: no rompe el SQL y no devuelve todo',
    in_array($injectionResult['status'], ['ok', 'no_result'], true)
        && (int)$injectionResult['total'] < $dbTotal
);

/* ============================================================
 * 5. Exportación
 * ============================================================ */
$sampleFilters = ThreatfoxQuery::normalize([
    'source' => 'db', 'mode' => 'recent', 'days' => 0, 'f_conf' => 80,
]);
$sampleRows = $store->queryAll(ThreatfoxQuery::storeFiltersFor($sampleFilters), 200);
check('Exportación: hay conjunto de muestra', count($sampleRows) > 0, 'filas=' . count($sampleRows));

$exporter = new ThreatfoxExport('green', 365, [
    'sourceName'    => 'abuse.ch ThreatFox',
    'threatActor'   => 'APT28',
    'tags'          => 'c2,banking',
    'indicatorType' => 'malicious-activity',
    'confidence'    => null,
    'ip_direction'  => 'both',
]);

$csv = $exporter->files($sampleRows, 'csv');
check('CSV: un fichero', count($csv['files']) === 1);
check('CSV: extensión .csv', str_ends_with($csv['files'][0]['filename'], '.csv'));
check('CSV: BOM UTF-8', str_starts_with($csv['files'][0]['content'], "\xEF\xBB\xBF"));
check('CSV: cabecera con separador ;', str_contains($csv['files'][0]['content'], "id;ioc;ioc_type"));
check(
    'CSV: una línea por fila (+cabecera)',
    count(explode("\n", trim($csv['files'][0]['content']))) === count($sampleRows) + 1
);

$jsonExport = $exporter->files($sampleRows, 'json');
$decoded = json_decode($jsonExport['files'][0]['content'], true);
check('JSON: estructura query_status/count/data', isset($decoded['query_status'], $decoded['count'], $decoded['data']));
check('JSON: count coincide con las filas', (int)$decoded['count'] === count($sampleRows));

$txtExport = $exporter->files($sampleRows, 'txt');
check(
    'TXT: un IOC por línea',
    count(explode("\n", trim($txtExport['files'][0]['content']))) === count($sampleRows)
);

$stix = $exporter->files($sampleRows, 'stix', false);
$bundle = json_decode($stix['files'][0]['content'], true);
check('STIX: un fichero en modo combinado', count($stix['files']) === 1);
check('STIX: tipo bundle', ($bundle['type'] ?? '') === 'bundle');
check('STIX: id de bundle', str_starts_with((string)($bundle['id'] ?? ''), 'bundle--'));
check(
    'STIX: incluye la marking-definition TLP:GREEN',
    ($bundle['objects'][0]['type'] ?? '') === 'marking-definition'
        && ($bundle['objects'][0]['id'] ?? '') === 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'
);
$indicators = array_values(array_filter(
    (array)($bundle['objects'] ?? []),
    static fn($o) => ($o['type'] ?? '') === 'indicator'
));
check('STIX: un indicator por fila exportable', count($indicators) === $stix['count'], 'indicators=' . count($indicators));

$firstIndicator = $indicators[0] ?? [];
check('STIX: spec_version 2.1', ($firstIndicator['spec_version'] ?? '') === '2.1');
check('STIX: indicador malicioso', ($firstIndicator['indicator_types'][0] ?? '') === 'malicious-activity');
check('STIX: threat_actor_names del panel', ($firstIndicator['threat_actor_names'][0] ?? '') === 'APT28');
check('STIX: valid_until > valid_from', ($firstIndicator['valid_until'] ?? '') > ($firstIndicator['valid_from'] ?? ''));
check(
    'STIX: object_marking_refs apunta al TLP',
    ($firstIndicator['object_marking_refs'][0] ?? '') === 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'
);

$patternsByType = [];
foreach ($indicators as $indicator) {
    $patternsByType[] = (string)($indicator['pattern'] ?? '');
}
check('STIX: patrones con sintaxis [tipo:campo = ...]', count(array_filter(
    $patternsByType,
    static fn($p) => (bool)preg_match('/^\[[a-z0-9-]+:/', $p)
)) === count($patternsByType));

$split = $exporter->files($sampleRows, 'stix', true);
check('STIX split: un fichero por tipo de objeto', count($split['files']) > 1, 'ficheros=' . count($split['files']));
$allSplitValid = true;
foreach ($split['files'] as $file) {
    $data = json_decode($file['content'], true);
    if (($data['type'] ?? '') !== 'bundle' || empty($data['objects'])) {
        $allSplitValid = false;
    }
}
check('STIX split: cada fichero es un bundle válido', $allSplitValid);

$misp = $exporter->files($sampleRows, 'misp', false);
$event = json_decode($misp['files'][0]['content'], true);
check('MISP: un evento en modo combinado', count($misp['files']) === 1);
check('MISP: estructura Event/Attribute/Tag', isset($event['Event']['Attribute'], $event['Event']['Tag']));
check('MISP: distribución TLP:GREEN = 2', ($event['Event']['distribution'] ?? '') === '2');
$tagNames = array_map(static fn($t) => $t['name'], (array)$event['Event']['Tag']);
check('MISP: incluye el tag tlp:green', in_array('tlp:green', $tagNames, true));
check('MISP: incluye las etiquetas del panel', in_array('c2', $tagNames, true) && in_array('banking', $tagNames, true));
check('MISP: at least one attribute'.'', count((array)$event['Event']['Attribute']) > 0);
check(
    'MISP: todos los atributos llevan to_ids',
    array_reduce((array)$event['Event']['Attribute'], static fn($ok, $a) => $ok && ($a['to_ids'] ?? false) === true, true)
);

$mispSplit = $exporter->files($sampleRows, 'misp', true);
check('MISP split: separa por tipo de atributo', count($mispSplit['files']) > 1, 'ficheros=' . count($mispSplit['files']));

/* Tipos concretos: patrón STIX y atributo MISP */
$oneDomain = [[
    'ioc' => 'evil.example.com', 'ioc_type' => 'domain', 'threat_type' => 'botnet_cc',
    'malware' => 'win.test', 'malware_printable' => 'Test', 'confidence_level' => 50,
    'first_seen' => '2026-01-01 00:00:00 UTC', 'tags' => 'c2', 'reference' => '',
]];
$domainStix = json_decode($exporter->files($oneDomain, 'stix', false)['files'][0]['content'], true);
$domainIndicator = $domainStix['objects'][1] ?? [];
check(
    'STIX domain: patrón domain-name',
    ($domainIndicator['pattern'] ?? '') === "[domain-name:value = 'evil.example.com']"
);
check('STIX domain: confianza del IOC (50)', (int)($domainIndicator['confidence'] ?? 0) === 50);

$oneIpPort = [[
    'ioc' => '185.10.10.10:8443', 'ioc_type' => 'ip:port', 'threat_type' => 'botnet_cc',
    'malware' => 'win.test', 'malware_printable' => 'Test', 'confidence_level' => 75,
    'first_seen' => '2026-01-01 00:00:00 UTC', 'tags' => '', 'reference' => '',
]];
$ipStix = json_decode($exporter->files($oneIpPort, 'stix', false)['files'][0]['content'], true);
$ipIndicator = $ipStix['objects'][1] ?? [];
check(
    'STIX ip:port: patrón network-traffic',
    str_contains((string)($ipIndicator['pattern'] ?? ''), 'network-traffic:dst_ref.value')
);

$ipMisp = json_decode($exporter->files($oneIpPort, 'misp', false)['files'][0]['content'], true);
check(
    'MISP ip:port con "both": dos atributos (origen y destino)',
    count((array)$ipMisp['Event']['Attribute']) === 2
);
$mispTypes = array_map(static fn($a) => $a['type'], (array)$ipMisp['Event']['Attribute']);
check('MISP ip:port: ip-src e ip-dst', in_array('ip-src', $mispTypes, true) && in_array('ip-dst', $mispTypes, true));

$hashMisp = [[
    'ioc' => str_repeat('d', 64), 'ioc_type' => 'sha256_hash', 'threat_type' => 'payload',
    'malware' => 'win.test', 'malware_printable' => 'Test', 'confidence_level' => 80,
    'first_seen' => '2026-01-01 00:00:00 UTC', 'tags' => '', 'reference' => '',
]];
$hashEvent = json_decode($exporter->files($hashMisp, 'misp', false)['files'][0]['content'], true);
check(
    'MISP sha256: atributo sha256 en Payload delivery',
    ($hashEvent['Event']['Attribute'][0]['type'] ?? '') === 'sha256'
        && ($hashEvent['Event']['Attribute'][0]['category'] ?? '') === 'Payload delivery'
);

/* ============================================================
 * 6. API sin Auth-Key: aviso, sin red
 * ============================================================ */
if (!ThreatfoxApi::hasAuthKey()) {
    $apiResult = ThreatfoxQuery::run(ThreatfoxQuery::normalize(['source' => 'api', 'mode' => 'ioc', 'search_term' => 'x']), 1);
    check('API sin clave: estado de error controlado', $apiResult['status'] === 'client_error');
    check('API sin clave: mensaje explicativo', str_contains($apiResult['message'], 'Auth-Key'));
} else {
    echo "SKIP API sin clave (hay Auth-Key configurada)\n";
}

/* ============================================================
 * 7. Rutas del módulo
 * ============================================================ */
$module = ModuleManager::get('threatfox');
check('Módulo: cargado en ModuleManager', $module !== null);
check('Módulo: clave correcta', $module !== null && $module->key() === 'threatfox');
check('Módulo: no sincroniza por tenant', $module !== null && $module->isSyncable() === false);
check('Módulo: sin permisos de Graph', $module !== null && $module->requiredPermissions() === []);
check('Módulo: grupo de navegación Inteligencia', ($module?->getNavItem()['group'] ?? '') === 'Inteligencia');

$routePatterns = array_map(static fn($r) => $r['pattern'], $module?->routes() ?? []);
foreach (['', 'settings', 'ingest', 'backfill/start', 'backfill/chunk', 'export', 'state'] as $pattern) {
    check('Ruta registrada: /' . $pattern, in_array($pattern, $routePatterns, true));
}

/* ============================================================
 * Resumen
 * ============================================================ */
echo "\n" . ($fail === 0 ? 'TODO OK' : 'FALLOS') . ": " . ($total - $fail) . "/{$total}\n";
exit($fail === 0 ? 0 : 1);
