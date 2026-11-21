<?php
/**
 * export_ioc.php — pruebas del asistente de extracción/exportación de IOCs.
 *
 *   php tools/smoke/export_ioc.php
 *
 * Cubre los builders puros (sobre listas explícitas), las opciones ampliadas
 * de STIX/MISP, el extractor genérico de texto y los puntos de entrada.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';
require __DIR__ . '/css_guard.php';

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    echo ($ok ? 'OK   ' : 'FALLO ') . $label . (!$ok && $detail !== '' ? ' - ' . $detail : '') . PHP_EOL;
    if (!$ok) { $fail++; }
}

$exporter = new Module_Export();
$sha256 = str_repeat('a', 64);
$iocs = [
    ['type' => 'ipv4-addr',  'value' => '45.83.1.2', 'description' => 'C2'],
    ['type' => 'domain-name', 'value' => 'evil.example.net', 'description' => 'Dominio'],
    ['type' => 'file',       'value' => $sha256, 'description' => 'Hash'],
    ['type' => 'url',        'value' => 'http://evil.example.net/a,b', 'description' => 'URL con coma'],
];

// --- TXT y CSV ---
$txt = $exporter->buildTxtContent($iocs);
check('TXT: un valor por línea', substr_count($txt, "\n") === 3 && str_contains($txt, '45.83.1.2'));
$csv = $exporter->buildCsvContent($iocs);
check('CSV: cabecera', str_starts_with($csv, '#,Type,Value,Description,Source,Severity,Fetched At'));
check('CSV: escapa comas', str_contains($csv, '"http://evil.example.net/a,b"'));
check('CSV: conserva descripción', str_contains($csv, 'Dominio'));

// --- STIX ---
$stix = $exporter->buildStixIndicators($iocs, [
    'tlp' => 'amber', 'confidence' => 42, 'valid_days' => 30,
    'source' => 'Prueba', 'indicator_type' => 'attribution',
    'threat_actor' => 'APT28', 'labels' => ['c2', 'banking'],
]);
check('STIX: 4 indicators', count($stix) === 4);
check('STIX: patrón IPv4', ($stix[0]['pattern'] ?? '') === "[ipv4-addr:value = '45.83.1.2']");
check('STIX: patrón SHA-256', str_contains((string)($stix[2]['pattern'] ?? ''), "file:hashes.'SHA-256'"));
check('STIX: TLP ámbar', ($stix[0]['object_marking_refs'][0] ?? '') === 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82');
check('STIX: confianza configurable', ($stix[0]['confidence'] ?? 0) === 42);
check('STIX: indicator_type configurable', ($stix[0]['indicator_types'] ?? []) === ['attribution']);
check('STIX: actor de amenaza', ($stix[0]['threat_actor_names'] ?? []) === ['APT28']);
check('STIX: etiquetas', ($stix[0]['labels'] ?? []) === ['c2', 'banking']);
check('STIX: descripción del IOC', ($stix[0]['description'] ?? '') === 'C2');
check('STIX: validez', str_contains((string)($stix[0]['valid_until'] ?? ''), date('Y', time() + 30 * 86400)));

$default = $exporter->buildStixIndicators([['ioc_type' => 'domain-name', 'ioc_value' => 'x.example.com', 'description' => 'd']]);
check('STIX: defaults intactos (catálogo)', ($default[0]['indicator_types'] ?? []) === ['malicious-activity']
    && ($default[0]['lang'] ?? '') === 'es'
    && str_contains((string)($default[0]['name'] ?? ''), 'EntraID TI'));

$split = $exporter->buildStixResult($iocs, ['format' => 'split']);
check('STIX: split agrupa por tipo', ($split['format'] ?? '') === 'split'
    && count($split['files'] ?? []) === 4
    && isset($split['files']['ipv4-addr'], $split['files']['domain-name'], $split['files']['file'], $split['files']['url']));
$merged = $exporter->buildStixResult($iocs, []);
check('STIX: merged, un bundle', ($merged['format'] ?? '') === 'merged'
    && str_contains((string)($merged['content'] ?? ''), '"type": "bundle"'));

// --- MISP ---
$misp = $exporter->buildMispEvent($iocs, [
    'tlp' => 'red', 'ip_direction' => 'both',
    'threat_actor' => 'APT28', 'labels' => ['c2'],
]);
$attrs = $misp['Event']['Attribute'] ?? [];
$ips = array_values(array_filter($attrs, static fn(array $a): bool => in_array($a['type'], ['ip-src', 'ip-dst'], true)));
check('MISP: IP en ambas direcciones', count($ips) === 2);
check('MISP: comment = descripción', ($attrs[0]['comment'] ?? '') === 'C2');
check('MISP: distribution por TLP', ($misp['Event']['distribution'] ?? '') === '0');
$tagNames = array_column($misp['Event']['Tag'] ?? [], 'name');
check('MISP: tags TLP + actor', in_array('tlp:red', $tagNames, true) && in_array('threat-actor:APT28', $tagNames, true));
$hashes = array_values(array_filter($attrs, static fn(array $a): bool => $a['type'] === 'sha256'));
check('MISP: hash por longitud', count($hashes) === 1);
$mispSplit = $exporter->buildMispResult($iocs, ['format' => 'split']);
check('MISP: split agrupa por atributo', ($mispSplit['format'] ?? '') === 'split' && count($mispSplit['files'] ?? []) >= 4);

// --- Extractor genérico de texto ---
require_once dirname(__DIR__, 2) . '/public_html/includes/ioc_text_extract.php';
$extracted = ioc_extract_text(
    "El dominio malicious[.]example.net y la IP 45.83.1.2. "
    . "También hxxp://evil.example.net/path y microsoft.com. "
    . "Versión 1.2.3.4 del producto."
);
$values = array_column($extracted['iocs'], 'value');
check('Texto: refang de dominio', in_array('malicious.example.net', $values, true));
check('Texto: refang de URL', in_array('http://evil.example.net/path', $values, true));
check('Texto: descarta dominio benigno', !in_array('microsoft.com', $values, true));
check('Texto: stats coherentes', ($extracted['stats']['unique'] ?? -1) === count($extracted['iocs']));
check('Texto: cuenta duplicados', isset($extracted['stats']['duplicates'], $extracted['stats']['categories']));

// --- Endpoints y puntos de entrada ---
$moduleSrc = (string)@file_get_contents(dirname(__DIR__, 2) . '/public_html/modules/export/module.php');
foreach (['extract', 'generate', 'iocs/save', 'u42-articles'] as $route) {
    check('Ruta POST/GET ' . $route, str_contains($moduleSrc, "'pattern' => '$route'"));
}
check('Endpoint genera sin descargar', str_contains($moduleSrc, 'function generateEndpoint')
    && !str_contains(substr($moduleSrc, strpos($moduleSrc, 'function generateEndpoint'), 900), 'Content-Disposition'));
check('Endpoint guarda correcciones', str_contains($moduleSrc, 'edited = 1'));

$cols = [];
foreach (Database::fetchAll('PRAGMA table_info(u42_iocs)') as $c) {
    $cols[(string)$c['name']] = true;
}
check('BD: u42_iocs.edited', isset($cols['edited']));

$footer = (string)@file_get_contents(dirname(__DIR__, 2) . '/public_html/views/layout/footer.php');
check('Layout: parcial del asistente', str_contains($footer, 'partials/ioc_extractor.php'));
check('Layout: JS del asistente', str_contains($footer, 'js/ioc-extractor.js'));
check('Layout: solo autenticados', str_contains($footer, '<?php if (Auth::check()): ?>'));

$panel = (string)@file_get_contents(dirname(__DIR__, 2) . '/public_html/modules/threat_intelligence/views/_unit42_panel.php');
check('Unit 42: sin enlaces directos', !str_contains($panel, 'modules/export/download'));
check('Unit 42: botón Extraer IOCs', str_contains($panel, 'Extraer IOCs')
    && str_contains($panel, "IOCExtractor.open({source:'u42'"));

$exportIndex = (string)@file_get_contents(dirname(__DIR__, 2) . '/public_html/modules/export/views/index.php');
check('Exportación: botones abren el asistente', str_contains($exportIndex, 'function openIocExtractor')
    && substr_count($exportIndex, 'openIocExtractor(') >= 5);

// --- Guardia de CSS compilado (v0.4.28.8) ---
$missing = smoke_css_missing_classes(
    ['views/partials/ioc_extractor.php'],
    ['text-green-500', 'text-gray-400', 'text-amber-400', 'text-gray-300',
     'dark:text-gray-600', 'material-icons', 'icon-16']
);
check('CSS: clases del asistente compiladas', $missing === [], implode(', ', $missing));

echo PHP_EOL . ($total - $fail) . '/' . $total . ' OK' . PHP_EOL;
exit($fail === 0 ? 0 : 1);
