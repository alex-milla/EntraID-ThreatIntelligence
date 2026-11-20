<?php
/**
 * unit42.php — pruebas del feed de Unit 42 (sin red).
 *
 *   php tools/smoke/unit42.php
 *
 * Cubre el parser (título, fecha, secciones y jerarquía), la extracción de
 * IOCs por tipología (con defanging y sin falsos positivos), la generación de
 * patrones STIX con el exportador existente y la decisión de no repetir
 * descargas.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    echo ($ok ? 'OK   ' : 'FALLO ') . $label . (!$ok && $detail !== '' ? ' - ' . $detail : '') . PHP_EOL;
    if (!$ok) {
        $fail++;
    }
}

$fixture = <<<'TXT'
2026-11-16 (Monday): ZIP Archive Contains Package Using DLL Side-Loading and Python Loader for PureLogs/PureRAT

AUTHORS:

- Shazan Khaja, Muhammet Algan

REFERENCES:

- https://www.linkedin.com/posts/purelogs-purerat-ugcPost-7528244027658420224-Wan8/

NOTES:

- Unit 42 observed a multi-stage delivery chain on 2026-10-21.
  -- The ZIP contains a legitimate, validly signed executable named wpspdf.exe.

INDICATORS:

SHA-256 hash of the side-loaded DLL:

- 7453f86a9b36a0067b37cf00627ae6195b9eeee9e64a58653a80069eae7bd6fa (krpt.dll)

Command and control server info:

- tea.vexexo[.]com - 185.139.214[.]102:443 (TLSv1)

File names and paths:

- C:\Users\Public\MicrosoftEdgeUpdate\MicrosoftEdgeUpdate.exe

XOR key for the encoded data file with the .pdf extension (hex): d9301f099d9dd27cc9a1c190e40719cfaff77f65
TXT;

try {
    // --- Parser ---
    $parsed = Unit42Feed::parseArticle('2026-11-16-PureLogs.txt', $fixture);
    check('parser: título', str_contains($parsed['title'], 'DLL Side-Loading'), $parsed['title']);
    check('parser: fecha', $parsed['published_at'] === '2026-11-16', $parsed['published_at']);
    check('parser: cuatro secciones', count($parsed['sections']) === 4, (string)count($parsed['sections']));
    check('parser: jerarquía de viñetas', isset($parsed['sections'][2]['items'][1])
        && (int)$parsed['sections'][2]['items'][1]['depth'] === 2);
    check('parser: etiquetas dentro de INDICATORS', (bool)($parsed['sections'][3]['items'][0]['label'] ?? false));

    $fallback = Unit42Feed::parseArticle('raro.txt', "Línea suelta\nOtra línea");
    check('parser: fallback sin secciones', count($fallback['sections']) === 1
        && ($fallback['sections'][0]['title'] ?? '') === 'TEXTO');

    // --- IOCs ---
    $iocs = Unit42Feed::extractIocs($parsed['sections']);
    $types = [];
    foreach ($iocs as $ioc) {
        $types[$ioc['ioc_type']] = ($types[$ioc['ioc_type']] ?? 0) + 1;
    }
    check('IOCs: dominio defangeado', in_array('tea.vexexo.com', array_column($iocs, 'ioc_value'), true));
    check('IOCs: IP defangeada', in_array('185.139.214.102', array_column($iocs, 'ioc_value'), true));
    check('IOCs: SHA-256', in_array('7453f86a9b36a0067b37cf00627ae6195b9eeee9e64a58653a80069eae7bd6fa', array_column($iocs, 'ioc_value'), true));
    check('IOCs: por tipología', isset($types['domain-name'], $types['ipv4-addr'], $types['file']), json_encode($types));
    check('IOCs: .exe NO es dominio', !in_array('microsoftedgeupdate.exe', array_column($iocs, 'ioc_value'), true));
    check('IOCs: clave XOR NO es hash', !in_array('d9301f099d9dd27cc9a1c190e40719cfaff77f65', array_column($iocs, 'ioc_value'), true));
    check('IOCs: sin IOCs fuera de INDICATORS', !in_array('wpspdf.exe', array_column($iocs, 'ioc_value'), true));

    // --- Compatibilidad con el exportador STIX ---
    $exporter = new Module_Export();
    foreach (array_keys($types) as $type) {
        $sample = '';
        foreach ($iocs as $ioc) {
            if ($ioc['ioc_type'] === $type) {
                $sample = $ioc['ioc_value'];
                break;
            }
        }
        $pattern = $exporter->generateStixPattern($type, $sample);
        check('STIX: patrón para ' . $type, is_string($pattern) && str_starts_with($pattern, '['), (string)$pattern);
    }

    // --- No repetir descargas ---
    $known = ['2026-11-16-PureLogs.txt' => 'sha-abc'];
    check('sync: no descarga si el SHA coincide', Unit42Feed::needsDownload('2026-11-16-PureLogs.txt', 'sha-abc', $known) === false);
    check('sync: descarga si cambió el SHA', Unit42Feed::needsDownload('2026-11-16-PureLogs.txt', 'sha-xyz', $known) === true);
    check('sync: descarga si es nuevo', Unit42Feed::needsDownload('otro.txt', 'sha-abc', $known) === true);

    /* check() cuenta sin escribir: se inserta una fila temporal como referencia */
    Database::query(
        "INSERT OR REPLACE INTO u42_articles (path, sha, size, title, content, first_seen_at)
         VALUES ('u42-smoke-check.txt', 'sha-abc', 100, 'smoke', 'x', datetime('now'))"
    );
    $before = (int)(Database::fetchOne("SELECT COUNT(*) AS c FROM u42_articles")['c'] ?? 0);
    $fakeFiles = [
        ['path' => 'u42-smoke-check.txt', 'sha' => 'sha-abc', 'size' => 100], // igual
        ['path' => 'otro.txt', 'sha' => 'sha-nuevo', 'size' => 100],           // nuevo
    ];
    $check = Unit42Feed::check($fakeFiles);
    Database::query("DELETE FROM u42_articles WHERE path = 'u42-smoke-check.txt'");
    check('check: detecta 1 nuevo y 1 sin cambios', $check['new'] === 1 && $check['unchanged'] === 1, json_encode($check));
    check('check: cuenta los pendientes', $check['pending'] === 1);
    check('check: no escribe en la BD', (int)(Database::fetchOne("SELECT COUNT(*) AS c FROM u42_articles")['c'] ?? 0) === $before - 1);
    check('check: error legible de hosting', str_contains(
        Unit42Feed::friendlyError(new RuntimeException('fallo de red')),
        'El servidor no pudo acceder a GitHub'
    ));

    // --- Esquema y vistas ---
    $syncCols = [];
    foreach (Database::fetchAll("PRAGMA table_info(u42_sync)") as $col) {
        $syncCols[(string)$col['name']] = true;
    }
    foreach (['state', 'pending', 'processed', 'started_at', 'finished_at'] as $col) {
        check('BD: u42_sync.' . $col, isset($syncCols[$col]));
    }
    foreach (['u42_articles', 'u42_iocs', 'u42_sync'] as $table) {
        $row = Database::fetchOne("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", [$table]);
        check('BD: tabla ' . $table, $row !== null);
    }
    $root = dirname(__DIR__, 2);
    $moduleSrc = (string)@file_get_contents($root . '/public_html/modules/threat_intelligence/module.php');
    check('módulo: pestaña y rutas Unit42', str_contains($moduleSrc, "'pattern' => 'unit42'")
        && str_contains($moduleSrc, 'unit42Sync'));
    check('módulo: status antes que {id}', strpos($moduleSrc, "'pattern' => 'unit42/status'") < strpos($moduleSrc, "'pattern' => 'unit42/{id}'"));
    $header = (string)@file_get_contents($root . '/public_html/views/partials/ti_header.php');
    check('módulo: pestaña visible', str_contains($header, "tiActive === 'unit42'"));
    $exportSrc = (string)@file_get_contents($root . '/public_html/modules/export/module.php');
    check('export: fuente Unit42', str_contains($exportSrc, "['source'] ?? '') === 'u42'"));
    $worker = (string)@file_get_contents($root . '/public_html/unit42-worker.php');
    check('worker: cron', str_contains($worker, 'Unit42Feed::sync()'));
} catch (Throwable $e) {
    check('excepción inesperada: ' . $e->getMessage(), false, $e->getFile() . ':' . $e->getLine());
}

echo PHP_EOL . ($total - $fail) . '/' . $total . ' OK' . PHP_EOL;
exit($fail === 0 ? 0 : 1);
