<?php
/**
 * ti_tracker_api.php — Pruebas de los feeds externos de Seguimiento TI TF.
 *
 *   php tools/smoke/ti_tracker_api.php
 *
 * Verifica (sin red, sobre una base temporal):
 *   · esquema aditivo api_enabled/slug y valores por defecto
 *   · selección de listas por id/slug y por permisos del token
 *   · ámbitos tracked/last/new, filtro por tipo y por fecha (since)
 *   · los 5 formatos generados con los builders de Module_Export
 *   · auditoría de lecturas y presencia de rutas en la API REST
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

$tmpDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'ti_feed_smoke_' . bin2hex(random_bytes(4));
@mkdir($tmpDir, 0770, true);
$dbPath = $tmpDir . DIRECTORY_SEPARATOR . 'ti_tracker.sqlite';

try {
    $store = new TiTrackerStore($dbPath);
    check('BD temporal creada', is_file($dbPath));

    /* ============================================================
     * 1. Esquema aditivo y publicación por defecto
     * ============================================================ */
    $cols = [];
    $pdo = new PDO('sqlite:' . $dbPath);
    foreach ($pdo->query('PRAGMA table_info(searches)') as $col) {
        $cols[(string)$col['name']] = true;
    }
    check('Esquema: columna api_enabled', isset($cols['api_enabled']));
    check('Esquema: columna slug', isset($cols['slug']));

    $base = [
        'notes' => '', 'formats' => ['stix', 'json'], 'tlp' => 'green',
        'valid_days' => 365, 'source_name' => 'abuse.ch ThreatFox',
        'threat_actor' => '', 'extra_tags' => '',
        'filters' => ['source' => 'db', 'mode' => 'recent', 'days' => 30],
    ];
    $id1 = $store->saveSearch($base + ['name' => 'Github IOCs']);
    $id2 = $store->saveSearch($base + ['name' => 'AWS IOCs', 'api_enabled' => 0]);
    $id3 = $store->saveSearch($base + ['name' => 'Docusign', 'slug' => 'Firma Digital!']);
    check('Alta: ids asignados', $id1 > 0 && $id2 > 0 && $id3 > 0);
    check('Publicación: por defecto activa', $store->getSearch($id1)['api_enabled'] === 1);
    check('Publicación: se puede desactivar', $store->getSearch($id2)['api_enabled'] === 0);
    check('Slug: generado desde el nombre', ($store->getSearch($id1)['slug'] ?? '') === 'github-iocs');
    check('Slug: saneado desde campo explícito', ($store->getSearch($id3)['slug'] ?? '') === 'firma-digital');

    $published = $store->listApiSearches();
    check('Listado API: solo búsquedas publicadas', count($published) === 2);
    check('Listado API: respeta permisos del token', count($store->listApiSearches([$id2, $id3])) === 1);
    check('Listado API: permiso vacío no publica nada', $store->listApiSearches([]) === []);
    check('Listado API: isApiEnabled', $store->isApiEnabled($id1) && !$store->isApiEnabled($id2));

    /* ============================================================
     * 2. Permisos del token
     * ============================================================ */
    check('Token: sin permissions ve todo', TiTrackerFeed::allowedIds(['permissions' => '[]']) === null);
    check(
        'Token: ámbito ti_tracker restringe',
        TiTrackerFeed::allowedIds(['permissions' => json_encode(['scope' => 'ti_tracker', 'search_ids' => [$id1, $id3]])]) === [$id1, $id3]
    );
    check(
        'Token: all_lists equivale a sin restricción',
        TiTrackerFeed::allowedIds(['permissions' => json_encode(['scope' => 'ti_tracker', 'all_lists' => true])]) === null
    );
    check(
        'Token: query-string solo si se autoriza',
        TiTrackerFeed::allowQueryToken(['permissions' => json_encode(['allow_query_token' => true])])
            && !TiTrackerFeed::allowQueryToken(['permissions' => '[]'])
    );

    /* ============================================================
     * 3. Resolución de listas
     * ============================================================ */
    check('Listas: todas por defecto', count(TiTrackerFeed::resolveSearches(null, '', $store)) === 2);
    check('Listas: todas con "all"', count(TiTrackerFeed::resolveSearches(null, 'all', $store)) === 2);
    check('Listas: por id', count(TiTrackerFeed::resolveSearches(null, (string)$id1, $store)) === 1);
    check('Listas: por slug', count(TiTrackerFeed::resolveSearches(null, 'firma-digital', $store)) === 1);
    check(
        'Listas: no salta el permiso del token',
        TiTrackerFeed::resolveSearches([$id1], (string)$id3, $store) === []
    );
    check(
        'Listas: varios ids combinados',
        count(TiTrackerFeed::resolveSearches(null, $id1 . ',' . $id3, $store)) === 2
    );

    /* ============================================================
     * 4. Datos de ejemplo y recogida de IOCs
     * ============================================================ */
    $row = static fn(string $ioc, string $type = 'domain'): array => [
        'id' => 'id-' . md5($ioc), 'ioc' => $ioc, 'ioc_type' => $type,
        'malware_printable' => 'Cobalt Strike', 'tags' => 'c2',
        'first_seen' => '2026-11-01 00:00:00 UTC',
    ];
    $rows1 = [
        $row('1.2.3.4', 'ip'),
        $row('evil.example', 'domain'),
        $row('https://evil.example/bad', 'url'),
        $row(str_repeat('a', 32), 'md5'),
    ];
    $store->markRun($id1, $rows1, 'db');
    $store->markRun($id3, [$row('firma-maliciosa.example', 'domain')], 'db');

    $catalog = TiTrackerFeed::catalog(null, $store);
    check('Catálogo: dos listas', count($catalog) === 2);
    $catalogGithub = null;
    foreach ($catalog as $item) {
        if (($item['slug'] ?? '') === 'github-iocs') { $catalogGithub = $item; }
    }
    check('Catálogo: metadatos de seguimiento', $catalogGithub !== null
        && (int)($catalogGithub['tracked'] ?? 0) === 4);

    $tracked = TiTrackerFeed::collect(TiTrackerFeed::resolveSearches(null, (string)$id1, $store), 'tracked', null, 'all', $store);
    check('Feed tracked: 4 IOCs', count($tracked['iocs']) === 4);
    check('Feed tracked: metadatos de lista', ($tracked['iocs'][0]['list_slug'] ?? '') === 'github-iocs');
    check('Feed: sin truncamiento', $tracked['truncated'] === false);

    $last = TiTrackerFeed::collect(TiTrackerFeed::resolveSearches(null, (string)$id1, $store), 'last', null, 'all', $store);
    check('Feed last: 4 IOCs', count($last['iocs']) === 4);
    $new = TiTrackerFeed::collect(TiTrackerFeed::resolveSearches(null, (string)$id1, $store), 'new', null, 'all', $store);
    check('Feed new: novedades de la ejecución', count($new['iocs']) === 4);

    /* Segunda ejecución: solo una novedad real. */
    $store->markRun($id1, [$row('1.2.3.4', 'ip'), $row('new.example', 'domain')], 'db');
    $new2 = TiTrackerFeed::collect(TiTrackerFeed::resolveSearches(null, (string)$id1, $store), 'new', null, 'all', $store);
    check('Feed new: tras segunda ejecución', count($new2['iocs']) === 1
        && ($new2['iocs'][0]['value'] ?? '') === 'new.example');
    $last2 = TiTrackerFeed::collect(TiTrackerFeed::resolveSearches(null, (string)$id1, $store), 'last', null, 'all', $store);
    check('Feed last: snapshot actualizado', count($last2['iocs']) === 2);

    /* Filtro por tipo y por fecha. */
    $onlyIp = TiTrackerFeed::collect(TiTrackerFeed::resolveSearches(null, (string)$id1, $store), 'tracked', null, 'ip', $store);
    check('Filtro tipo ip', count($onlyIp['iocs']) === 1
        && ($onlyIp['iocs'][0]['type'] ?? '') === 'ipv4-addr');
    $onlyDomain = TiTrackerFeed::collect(TiTrackerFeed::resolveSearches(null, (string)$id1, $store), 'tracked', null, 'domain', $store);
    check('Filtro tipo dominio', count($onlyDomain['iocs']) === 2);
    $future = TiTrackerFeed::normalizeSince('2099-01-01T00:00:00Z');
    $none = TiTrackerFeed::collect(TiTrackerFeed::resolveSearches(null, (string)$id1, $store), 'tracked', $future, 'all', $store);
    check('Filtro since: fecha futura no devuelve filas', $none['iocs'] === []);
    check('Filtro since: fecha inválida se rechaza', (static function (): bool {
        try { TiTrackerFeed::normalizeSince('no-es-fecha'); return false; } catch (Throwable $e) { return true; }
    })());

    /* Varias listas, deduplicación. */
    $both = TiTrackerFeed::collect(TiTrackerFeed::resolveSearches(null, $id1 . ',' . $id3, $store), 'tracked', null, 'all', $store);
    check('Varias listas: combinan y deduplican', count($both['iocs']) === 6
        && count($both['lists']) === 2);

    /* ============================================================
     * 5. Formatos y auditoría
     * ============================================================ */
    foreach (TiTrackerFeed::FORMATS as $format) {
        $out = TiTrackerFeed::render($tracked['iocs'], $format);
        check('Formato ' . $format . ': contenido y MIME', $out['content'] !== ''
            && str_contains($out['mime'], '/') && str_contains($out['filename'], 'ti_tf'));
    }
    $stix = TiTrackerFeed::render($tracked['iocs'], 'stix');
    check('STIX: bundle con indicators', str_contains($stix['content'], '"bundle"')
        && str_contains($stix['content'], '"indicator"'));
    $misp = TiTrackerFeed::render($tracked['iocs'], 'misp');
    check('MISP: evento con atributos', str_contains($misp['content'], '"Event"')
        && str_contains($misp['content'], '"Attribute"'));
    $txt = TiTrackerFeed::render($tracked['iocs'], 'txt');
    check('TXT: un IOC por línea', count(explode("\n", $txt['content'])) === 4);
    check('CSV: cabecera', str_starts_with(TiTrackerFeed::render($tracked['iocs'], 'csv')['content'], '#,Type,Value'));

    $store->logApiPull($id1, 4);
    $history = $store->history($id1, 10);
    check('Auditoría: lectura API registrada', ($history[0]['kind'] ?? '') === 'api_pull'
        && (int)$history[0]['rows'] === 4);

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
 * 6. Rutas y contrato de la API REST
 * ============================================================ */
$apiSource = (string)@file_get_contents(ROOT_PATH . '/api/index.php');
check('Ruta: grupo /api/ti-tf', str_contains($apiSource, "/api/ti-tf"));
check('Ruta: /lists', str_contains($apiSource, "$r->get('lists'"));
check('Ruta: /indicators y alias /feed', str_contains($apiSource, "$r->get('indicators'")
    && str_contains($apiSource, "$r->get('feed'"));
check('Auth: X-API-Key y Basic', str_contains($apiSource, 'HTTP_X_API_KEY')
    && str_contains($apiSource, "'Basic '"));
check('Auth: token por query-string solo si se autoriza',
    str_contains($apiSource, 'allowQueryToken'));
check('Compatibilidad: rutas anteriores intactas', str_contains($apiSource, "/api/tenants")
    && str_contains($apiSource, "/api/modules") && str_contains($apiSource, 'function apiRequireAuth'));

echo "\n" . ($fail === 0 ? 'TODO OK' : 'FALLOS') . ": " . ($total - $fail) . "/{$total}\n";
exit($fail === 0 ? 0 : 1);
