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

    /* Fase 3.4: Collection ID admite slug, nombre, id y UUID (estilo OTX). */
    $publishedNow = TiTrackerFeed::resolveSearches(null, '', $store);
    $bySlug = TiTrackerFeed::resolveCollection('github-iocs', $publishedNow);
    check('Fase 3.4: Collection ID por slug', $bySlug !== null && empty($bySlug['all'])
        && (int)($bySlug['searches'][0]['id'] ?? 0) === $id1);
    check('Fase 3.4: Collection ID "all"',
        (TiTrackerFeed::resolveCollection('all', $publishedNow)['all'] ?? false) === true);
    check('Fase 3.4: Collection ID "default"',
        (TiTrackerFeed::resolveCollection('default', $publishedNow)['all'] ?? false) === true);
    check('Fase 3.4: Collection ID por nombre',
        (int)(TiTrackerFeed::resolveCollection('GITHUB IOCS', $publishedNow)['searches'][0]['id'] ?? 0) === $id1);
    check('Fase 3.4: Collection ID por id',
        (int)(TiTrackerFeed::resolveCollection((string)$id1, $publishedNow)['searches'][0]['id'] ?? 0) === $id1);
    check('Fase 3.4: Collection ID por UUID',
        (int)(TiTrackerFeed::resolveCollection(TiTrackerFeed::collectionId($id1), $publishedNow)['searches'][0]['id'] ?? 0) === $id1);
    check('Fase 3.4: Collection ID desconocido',
        TiTrackerFeed::resolveCollection('no-existe', $publishedNow) === null);

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

    /* Fase 3: TAXII 2.1 y formato Microsoft Sentinel. */
    $uuidA = TiTrackerFeed::collectionId($id1);
    check('Fase 3: UUID de colección estable', $uuidA === TiTrackerFeed::collectionId($id1)
        && $uuidA !== TiTrackerFeed::collectionId());
    $taxiiA = TiTrackerFeed::taxiiObjects($tracked['iocs']);
    $taxiiB = TiTrackerFeed::taxiiObjects($tracked['iocs']);
    check('Fase 3: ids STIX estables entre sondeos', count($taxiiA) === count($taxiiB)
        && ($taxiiA[0]['id'] ?? '') === ($taxiiB[0]['id'] ?? '')
        && str_starts_with((string)($taxiiA[0]['id'] ?? ''), 'indicator--'));
    $stamped = TiTrackerFeed::taxiiObjects([[
        'type' => 'domain-name', 'value' => 'stamp.example',
        'description' => 'prueba', 'fetched_at' => '2020-01-02 03:04:05 UTC',
    ]]);
    check('Fase 3: created/modified desde el momento en que se vio',
        ($stamped[0]['created'] ?? '') === '2020-01-02T03:04:05.000Z'
            && ($stamped[0]['modified'] ?? '') === ($stamped[0]['created'] ?? ''));
    $ms = TiTrackerFeed::render($tracked['iocs'], 'ms-sentinel');
    $msData = safe_json_decode($ms['content'], []);
    check('Fase 3: formato ms-sentinel', is_array($msData) && isset($msData[0]['displayName'])
        && isset($msData[0]['pattern']) && str_contains($ms['mime'], 'json'));

    /* Fase 3.5: STIX estricto, TAXII 2.0 y Upload API. */
    $upload = TiTrackerFeed::render($tracked['iocs'], 'ms-upload-stix');
    $uploadData = safe_json_decode($upload['content'], []);
    check('Fase 3.5: formato ms-upload-stix', ($uploadData['sourcesystem'] ?? '') === 'EntraID-TI-TF'
        && is_array($uploadData['stixobjects'] ?? null));
    check('Fase 3.5: STIX estricto (sin propiedades propietarias)',
        !isset($taxiiA[0]['threat_actor_names'])
            && str_ends_with((string)($taxiiA[0]['created'] ?? ''), '.000Z')
            && ($taxiiA[0]['spec_version'] ?? '') === '2.1');
    $bundle20 = TiTrackerFeed::taxii20Bundle($tracked['iocs']);
    check('Fase 3.5: bundle STIX 2.0 para TAXII 2.0', ($bundle20['type'] ?? '') === 'bundle'
        && ($bundle20['spec_version'] ?? '') === '2.0'
        && !isset($bundle20['objects'][0]['spec_version'])
        && !isset($bundle20['objects'][0]['indicator_types']));

    $prevAccept = $_SERVER['HTTP_ACCEPT'] ?? null;
    $_SERVER['HTTP_ACCEPT'] = 'application/vnd.oasis.taxii+json; version=2.0';
    $is20 = TiTrackerFeed::isTaxii20();
    $_SERVER['HTTP_ACCEPT'] = 'application/taxii+json;version=2.1';
    $is21 = !TiTrackerFeed::isTaxii20();
    if ($prevAccept === null) { unset($_SERVER['HTTP_ACCEPT']); } else { $_SERVER['HTTP_ACCEPT'] = $prevAccept; }
    check('Fase 3.5: negociación TAXII 2.0/2.1', $is20 && $is21);

    $store->logApiPull($id1, 4);
    $store->logTaxiiRequest([
        'ip' => '127.0.0.1', 'method' => 'GET', 'path' => '/api/taxii2/ti-tf/collections/all/objects/',
        'accept' => 'application/vnd.oasis.taxii+json; version=2.0', 'auth_ok' => true, 'status' => 200,
    ]);
    $reqs = $store->listTaxiiRequests(15);
    check('Fase 3.5: bitácora TAXII', count($reqs) === 1
        && !empty($reqs[0]['auth_ok']) && (int)$reqs[0]['status'] === 200);
    $history = $store->history($id1, 10);
    check('Auditoría: lectura API registrada', ($history[0]['kind'] ?? '') === 'api_pull'
        && (int)$history[0]['rows'] === 4);

    /* Fase 2: publicación y permisos de tokens (sin tocar la BD real). */
    $store->setApiEnabled($id1, false);
    check('Fase 2: despublicar lista', !$store->isApiEnabled($id1)
        && count($store->listApiSearches()) === 1);
    $store->setApiEnabled($id1, true);
    check('Fase 2: republicar lista', $store->isApiEnabled($id1)
        && count($store->listApiSearches()) === 2);

    $permsAll = TiTrackerFeed::permissionsFromInput(['all_lists' => '1'], $published);
    check('Fase 2: permiso todas las listas', ($permsAll['scope'] ?? '') === 'ti_tracker'
        && !empty($permsAll['all_lists']) && ($permsAll['search_ids'] ?? null) === []);
    $permsSome = TiTrackerFeed::permissionsFromInput([
        'search_ids' => [(string)$id1, '99999'], 'allow_query_token' => '1',
    ], $published);
    check('Fase 2: permiso acotado y saneado', empty($permsSome['all_lists'])
        && ($permsSome['search_ids'] ?? null) === [$id1]
        && !empty($permsSome['allow_query_token']));
    check('Fase 2: resumen de permisos',
        str_contains(TiTrackerFeed::describePermissions($permsAll), 'Todas las listas')
            && str_contains(TiTrackerFeed::describePermissions($permsSome), 'token en URL permitido'));

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
check('Ruta: /lists', str_contains($apiSource, "get('lists'"));
check('Ruta: /indicators y alias /feed', str_contains($apiSource, "get('indicators'")
    && str_contains($apiSource, "get('feed'"));
check('Auth: X-API-Key y Basic', str_contains($apiSource, 'HTTP_X_API_KEY')
    && str_contains($apiSource, "'Basic '"));
check('Auth: token por query-string solo si se autoriza',
    str_contains($apiSource, 'allowQueryToken'));
check('Compatibilidad: rutas anteriores intactas', str_contains($apiSource, "/api/tenants")
    && str_contains($apiSource, "/api/modules") && str_contains($apiSource, 'function apiRequireAuth'));
check('Fase 3: rutas TAXII', str_contains($apiSource, "/api/taxii2")
    && str_contains($apiSource, "ti-tf/collections")
    && str_contains($apiSource, 'added_after'));
check('Fase 3: media type TAXII', str_contains($apiSource, 'application/taxii+json;version=2.1'));
check('Fase 3.3: detalle de colección para Sentinel',
    str_contains($apiSource, "'ti-tf/collections/{id}'") && str_contains($apiSource, "'collections/{id}'"));
check('Fase 3.3: Basic Auth de Apache/PHP-FPM',
    str_contains($apiSource, 'REDIRECT_HTTP_AUTHORIZATION') && str_contains($apiSource, 'PHP_AUTH_PW'));
check('Fase 3.3: media types y ventanas TAXII',
    str_contains($apiSource, 'vnd.oasis.stix+json; version=2.0')
        && str_contains($apiSource, 'X-TAXII-Date-Added-First')
        && str_contains($apiSource, 'X-TAXII-Date-Added-Last'));
check('Fase 3.4: negociación TAXII 2.0 / 2.1',
    str_contains($apiSource, 'function apiTfTaxiiMedia')
        && str_contains($apiSource, 'vnd.oasis.taxii+json'));
check('Fase 3.4: token también en Username',
    str_contains($apiSource, 'PHP_AUTH_USER') && str_contains($apiSource, 'resolveCollection'));
check('Fase 3.5: bundle 2.0 y bitácora en la API',
    str_contains($apiSource, 'taxii20Bundle') && str_contains($apiSource, 'apiTfTaxiiLog')
        && str_contains($apiSource, 'logTaxiiRequest'));

/* ============================================================
 * 7. Panel de gestión (Fase 2)
 * ============================================================ */
$apiView = (string)@file_get_contents(MODULES_PATH . '/ti_tracker/views/api.php');
check('Fase 2: vista del panel API', $apiView !== ''
    && str_contains($apiView, 'Constructor de feed')
    && str_contains($apiView, 'data-tf-copy')
    && str_contains($apiView, 'tf-feed-list'));
check('Fase 3.3: datos de conexión Sentinel en el panel',
    str_contains($apiView, 'Conexión Microsoft Sentinel')
        && str_contains($apiView, 'tf-api-root')
        && str_contains($apiView, 'tf-all-collection')
        && str_contains($apiView, 'Collection ID (TAXII)'));
check('Fase 3.4: panel indica slug y Username/Password',
    str_contains($apiView, 'Rellena <strong>Username y Password con el token</strong>')
        && str_contains($apiView, 'slug')
        && str_contains($apiView, '<code>all</code>'));
check('Fase 3.5: panel muestra el diagnóstico TAXII',
    str_contains($apiView, 'Diagnóstico TAXII')
        && str_contains($apiView, 'taxiiRequests'));
check('Fase 2: formularios de token', str_contains($apiView, '/api/token')
    && str_contains($apiView, 'allow_query_token')
    && str_contains($apiView, 'search_ids[]'));

$module = ModuleManager::get('ti_tracker');
$patterns = array_map(static fn($r) => $r['pattern'], $module?->routes() ?? []);
foreach (['api', 'api/publish/{id}', 'api/token', 'api/token/delete/{id}'] as $pattern) {
    check('Fase 2: ruta /' . $pattern, in_array($pattern, $patterns, true));
}

/* Render real del panel: sin errores y mostrando el token de un solo uso. */
$apiRenderError = '';
ob_start();
try {
    (static function (): void {
        $module = ModuleManager::get('ti_tracker');
        $published = [
            ['id' => 7, 'name' => 'Lista de prueba', 'slug' => 'lista-de-prueba',
             'tracked' => 3, 'last_run_at' => '2026-11-23 10:00:00 UTC'],
        ];
        $tokens = [];
        $formats = TiTrackerFeed::FORMATS;
        $scopes = TiTrackerFeed::SCOPES;
        $types = TiTrackerFeed::TYPES;
        $newToken = 'token_de_un_solo_uso';
        $notice = null;
        $taxiiRequests = [];
        include MODULES_PATH . '/ti_tracker/views/api.php';
    })();
} catch (Throwable $e) {
    $apiRenderError = $e->getMessage();
}
$apiRendered = (string)ob_get_clean();
check('Fase 2: render del panel API', $apiRenderError === ''
    && str_contains($apiRendered, 'token_de_un_solo_uso')
    && str_contains($apiRendered, 'Constructor de feed')
    && str_contains($apiRendered, 'tf-api-root'), $apiRenderError);

echo "\n" . ($fail === 0 ? 'TODO OK' : 'FALLOS') . ": " . ($total - $fail) . "/{$total}\n";
exit($fail === 0 ? 0 : 1);
