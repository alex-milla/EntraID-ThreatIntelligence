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
require __DIR__ . '/css_guard.php';

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
    foreach (['u42_articles', 'u42_iocs', 'u42_sync', 'u42_article_state'] as $table) {
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

    // --- Sección independiente de Unit 42 en el menú ---
    $tiModule = ModuleManager::get('threat_intelligence');
    $extra = $tiModule !== null ? $tiModule->getExtraNavItems() : [];
    check('menú: sección independiente con dos entradas', count($extra) === 2
        && ($extra[0]['label'] ?? '') === 'Publicaciones'
        && ($extra[0]['group'] ?? '') === 'Unit 42'
        && ($extra[1]['label'] ?? '') === 'Informes con IA'
        && ($extra[1]['group'] ?? '') === 'Unit 42');
    $nav = ModuleManager::getNavigation();
    $found = 0;
    foreach ($nav as $item) {
        if (($item['group'] ?? '') !== 'Unit 42') { continue; }
        $url = (string)($item['url'] ?? '');
        if ($url === base_url('modules/threat_intelligence/unit42')
            || $url === base_url('modules/threat_intelligence/unit42/reports')) {
            $found++;
        }
    }
    check('menú: navegación incluye publicaciones e informes', $found === 2);
    $sidebar = (string)@file_get_contents($root . '/public_html/views/layout/sidebar.php');
    check('menú: resaltado por ruta específica', str_contains($sidebar, '$bestNavPath'));

    // --- Estado de lectura y filtros (con filas temporales) ---
    $realUser = Database::fetchOne("SELECT id FROM users ORDER BY id LIMIT 1");
    $smokeUserId = (int)($realUser['id'] ?? 0);
    $ids = [];
    Database::query("DELETE FROM u42_articles WHERE path LIKE 'u42-smoke-%'");
    foreach (['2026-01-02' => 'U42 smoke B', '2026-02-03' => 'U42 smoke A'] as $date => $title) {
        $ids[] = Database::insert(
            "INSERT INTO u42_articles (path, sha, size, title, published_at, content, first_seen_at)
             VALUES (?, ?, 100, ?, ?, 'x', datetime('now'))",
            ['u42-smoke-' . $date . '.txt', 'sha-' . $date, $title, $date]
        );
    }
    Database::query(
        "INSERT INTO u42_iocs (article_id, ioc_type, ioc_value) VALUES (?, 'domain-name', 'smoke.example.com')",
        [$ids[0]]
    );
    Unit42Feed::setArticleState($smokeUserId, [$ids[0]], ['is_read' => 1]);
    Unit42Feed::setArticleState($smokeUserId, [$ids[1]], ['is_favorite' => 1]);

    $stateCounts = Unit42Feed::stateCounts($smokeUserId);
    check('estado: 1 leído y 1 favorito', $stateCounts['unread'] >= 1 && $stateCounts['favorites'] === 1, json_encode($stateCounts));

    $filtered = Unit42Feed::articles(['user_id' => $smokeUserId, 'from' => '2026-02-01', 'to' => '2026-02-28'], 50, 0);
    check('filtro: rango de fechas', count($filtered) === 1 && ($filtered[0]['title'] ?? '') === 'U42 smoke A', json_encode(array_column($filtered, 'title')));

    $unread = Unit42Feed::articles(['user_id' => $smokeUserId, 'only_unread' => true], 1000, 0);
    $unreadIds = array_map(static fn(array $r): int => (int)$r['id'], $unread);
    check('filtro: solo no leídas', in_array($ids[1], $unreadIds, true) && !in_array($ids[0], $unreadIds, true));

    $withIocs = Unit42Feed::articles(['user_id' => $smokeUserId, 'only_iocs' => true], 1000, 0);
    $iocIds = array_map(static fn(array $r): int => (int)$r['id'], $withIocs);
    check('filtro: solo con IOCs', in_array($ids[0], $iocIds, true));

    $favorites = Unit42Feed::articles(['user_id' => $smokeUserId, 'only_favorites' => true], 1000, 0);
    $favIds = array_map(static fn(array $r): int => (int)$r['id'], $favorites);
    check('filtro: favoritos', in_array($ids[1], $favIds, true));

    Unit42Feed::setArticleState($smokeUserId, [$ids[0]], ['is_read' => 0]);
    check('estado: se puede desmarcar como leído', (int)(Unit42Feed::statesFor($smokeUserId, [$ids[0]])[$ids[0]]['is_read'] ?? -1) === 0);

    foreach ($ids as $tempId) {
        Database::query("DELETE FROM u42_articles WHERE id = ?", [$tempId]);
    }
    check('rutas: estado y contadores', str_contains($moduleSrc, "'pattern' => 'unit42/state'")
        && str_contains($moduleSrc, "'pattern' => 'unit42/counts'"));
    check('rutas: acepta cambios anidados', str_contains($moduleSrc, "is_array(\$input['changes'] ?? null)"));

    // --- Informes con IA ---
    $kinds = Unit42Feed::reportKinds();
    check('IA: cuatro tipos de informe', array_keys($kinds) === ['resumen', 'divulgativa', 'impacto', 'indicadores']);
    foreach (['resumen', 'divulgativa', 'impacto', 'indicators'] as $key) {
        $prompt = llm_prompts_catalog()['llm.unit42.' . $key . '.system'] ?? [];
        check('IA: plantilla llm.unit42.' . $key . '.system', !empty($prompt['default']));
    }
    foreach (['format', 'sources'] as $key) {
        $prompt = llm_prompts_catalog()['llm.unit42.' . $key] ?? [];
        check('IA: plantilla llm.unit42.' . $key, !empty($prompt['default']));
    }
    check('IA: tarea en el catálogo', isset(llm_task_catalog()['unit42_report']));
    foreach (['u42_reports', 'u42_report_items'] as $table) {
        $row = Database::fetchOne("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", [$table]);
        check('BD: tabla ' . $table, $row !== null);
    }
    $iocCols = [];
    foreach (Database::fetchAll("PRAGMA table_info(u42_iocs)") as $col) {
        $iocCols[(string)$col['name']] = true;
    }
    check('BD: u42_iocs.source', isset($iocCols['source']));

    $tempId = Database::insert(
        "INSERT INTO u42_articles (path, sha, size, title, published_at, content, sections_json, first_seen_at)
         VALUES ('u42-ia-smoke.txt','x',100,'IA smoke','2026-04-01','x',?,datetime('now'))",
        [(string)json_encode([['title' => 'NOTES', 'items' => [['depth' => 1, 'text' => 'Dominio malicioso.example.com', 'label' => false]]]])]
    );
    $ctx = Unit42Feed::reportContext([$tempId], 0, 'resumen');
    check('IA: contexto incluye la publicación', str_contains($ctx, 'IA smoke') && str_contains($ctx, 'Dominio malicioso'));
    $word = Unit42Feed::reportWordHtml(['title' => 'Prueba', 'content_md' => "# Resumen\n\nTexto.\n\n| Tipo | Valor |\n|---|---|\n| domain-name | example.com |", 'articles' => [['title' => 'IA smoke', 'published_at' => '2026-04-01']]]);
    check('IA: HTML para Word', str_contains($word, '<table') && str_contains($word, 'INFORME UNIT 42') && str_contains($word, 'FUENTES CONSULTADAS'));

    $report = Unit42Feed::createReport((int)$realUser['id'], [$tempId], 'resumen', 0, 0);
    check('IA: crear informe en cola', !empty($report['success']) && (int)($report['id'] ?? 0) > 0, json_encode($report));
    $status = Unit42Feed::reportStatus((int)($report['id'] ?? 0));
    check('IA: estado inicial', ($status['status'] ?? '') === 'pending', json_encode($status));
    Database::query("DELETE FROM u42_reports WHERE id = ?", [(int)($report['id'] ?? 0)]);
    Database::query("DELETE FROM u42_articles WHERE id = ?", [$tempId]);
    check('rutas: informes con IA', str_contains($moduleSrc, "'pattern' => 'unit42/report-create'")
        && str_contains($moduleSrc, "'pattern' => 'unit42/report/{id}'"));

    // --- Selector masivo y despliegue en línea (v0.4.28.5) ---
    $listSrc = (string)@file_get_contents($root . '/public_html/modules/threat_intelligence/views/unit42.php');
    $panelSrc = (string)@file_get_contents($root . '/public_html/modules/threat_intelligence/views/_unit42_panel.php');
    $articleSrc = (string)@file_get_contents($root . '/public_html/modules/threat_intelligence/views/unit42_article.php');

    check('masivo: barra siempre visible', str_contains($listSrc, 'id="u42-mass-bar"')
        && !str_contains(substr($listSrc, strpos($listSrc, 'id="u42-mass-bar"'), 200), 'class="hidden'));
    check('masivo: checkbox maestro', str_contains($listSrc, 'id="u42-select-all"')
        && str_contains($listSrc, "ev.target.id === 'u42-select-all'"));
    check('masivo: marcar todo como leido y no leido', str_contains($listSrc, 'window.u42MarkAllRead')
        && str_contains($listSrc, 'window.u42MarkAllUnread')
        && str_contains($listSrc, 'Marcar todo como no leído'));
    check('masivo: aplica a los filtros, no solo a la pagina', str_contains($listSrc, 'all: true, filters: CURRENT_FILTERS'));
    check('masivo: barra de seleccion sigue condicional', str_contains($listSrc, 'id="u42-bulk-bar" class="hidden'));

    check('lectura: boton check en cada fila (aspecto TI)', str_contains($listSrc, 'data-role="read"')
        && str_contains($listSrc, "u42-read-toggle w-7 h-7")
        && str_contains($listSrc, "text-green-500' : 'text-gray-400"));
    check('lectura: cambia todas las instancias del articulo', str_contains($listSrc, "querySelectorAll('.u42-read-toggle[data-id=\"' + id") );

    check('panel: ruta registrada antes que la ficha', str_contains($moduleSrc, "'pattern' => 'unit42/{id}/panel'")
        && strpos($moduleSrc, "'pattern' => 'unit42/{id}/panel'") < strpos($moduleSrc, "'pattern' => 'unit42/{id}'"));
    check('panel: handler del modulo', str_contains($moduleSrc, 'function unit42ArticlePanel'));
    check('panel: enlace con data-u42-toggle', str_contains($listSrc, 'data-u42-toggle=')
        && str_contains($listSrc, 'function openArticle'));
    check('panel: URL compartible ?articulo=', str_contains($listSrc, "url.searchParams.set('articulo', id)"));
    check('panel: un solo abierto a la vez', str_contains($listSrc, "document.querySelectorAll('.u42-panel:not(.hidden)')"));
    check('panel: carga bajo demanda', str_contains($listSrc, 'PANEL_URL_TPL.replace'));
    check('panel: parcial compartido con la ficha', str_contains($articleSrc, "_unit42_panel.php")
        && str_contains($panelSrc, 'u42-read-toggle')
        && str_contains($panelSrc, 'u42-fav-toggle')
        && str_contains($panelSrc, 'u42-raw-toggle'));

    // --- Asistente de IOCs (v0.4.28.6) ---
    check('IOCs: botón Extraer IOCs en el panel', str_contains($panelSrc, "IOCExtractor.open({source:'u42'")
        && !str_contains($panelSrc, 'modules/export/download'));
    $footerSrc = (string)@file_get_contents($root . '/public_html/views/layout/footer.php');
    check('IOCs: asistente global en el layout', str_contains($footerSrc, 'partials/ioc_extractor.php')
        && str_contains($footerSrc, 'js/ioc-extractor.js'));

    // --- Aspecto de Threat Intelligence (v0.4.28.7) ---
    $fresh = Unit42Feed::freshness([
        'first_seen_at' => gmdate('Y-m-d H:i:s', time() - 3600),
        'updated_at' => gmdate('Y-m-d H:i:s'),
    ]);
    check('TI: frescura detecta descarga reciente', !empty($fresh['new24']) && !empty($fresh['updated'])
        && !empty($fresh['updated24']), json_encode($fresh));
    $freshOld = Unit42Feed::freshness([
        'first_seen_at' => '2026-01-01 00:00:00',
        'updated_at' => '2026-01-01 00:00:00',
    ]);
    check('TI: sin marcas en artículo antiguo', empty($freshOld['new24']) && empty($freshOld['updated'])
        && empty($freshOld['updated24']));
    $tmpTi = Database::insert(
        "INSERT INTO u42_articles (path, sha, size, title, published_at, content, first_seen_at)
         VALUES ('u42-ti-smoke.txt','x',10,'TI smoke','2026-08-01','x',datetime('now'))"
    );
    $listFields = Unit42Feed::articles(['user_id' => $smokeUserId], 5, 0);
    $tiRow = null;
    foreach ($listFields as $row) {
        if ((int)$row['id'] === (int)$tmpTi) { $tiRow = $row; break; }
    }
    check('TI: listado expone ioc_count', $tiRow !== null && array_key_exists('ioc_count', $tiRow), json_encode($tiRow));
    Database::query("DELETE FROM u42_articles WHERE id = ?", [$tmpTi]);
    $listSrc = (string)@file_get_contents($root . '/public_html/modules/threat_intelligence/views/unit42.php');
    check('TI: badge New naranja', str_contains($listSrc, 'bg-brand-500 text-white')
        && str_contains($listSrc, '>New<'));
    check('TI: borde izquierdo en recientes', str_contains($listSrc, 'border-l-2')
        && str_contains($listSrc, "'border-brand-500' : 'border-transparent'"));
    check('TI: meta con fecha, IOCs y actualizado', str_contains($listSrc, 'format_date($created)')
        && str_contains($listSrc, '<?= $iocCount ?> IOCs')
        && str_contains($listSrc, 'actualizado <?= e(format_date($updatedAt)) ?>'));
    check('TI: estrella y check a la derecha', str_contains($listSrc, 'data-role="fav"')
        && str_contains($listSrc, 'data-role="read"')
        && str_contains($listSrc, '<i class="material-icons icon-16" aria-hidden="true">check</i>'));
    check('TI: ya no usa el NUEVO antiguo', !str_contains($listSrc, 'bg-brand-100 text-brand-700')
        && !str_contains($listSrc, '>NUEVO<')
        && str_contains($panelSrc, 'format_date($updatedAt)'));
    check('TI: cabecera de publicaciones', str_contains($listSrc, '· por fecha de publicación'));

    // --- Perfil de IA en informes Unit 42 (v0.4.28.11) ---
    $reportCols = [];
    foreach (Database::fetchAll('PRAGMA table_info(u42_reports)') as $col) {
        $reportCols[(string)$col['name']] = true;
    }
    check('IA: u42_reports.profile_id', isset($reportCols['profile_id']));
    $feedSrc = (string)@file_get_contents($root . '/public_html/includes/unit42_feed.php');
    check('IA: createReport persiste el perfil', str_contains($feedSrc, 'INSERT INTO u42_reports (user_id, tenant_id, profile_id, kind')
        && str_contains($feedSrc, 'max(0, $profileId)'));
    check('IA: modal con selector de perfil', str_contains($listSrc, 'id="u42-report-profile"')
        && str_contains($listSrc, '— Modelo predeterminado —')
        && str_contains($listSrc, 'profile_id: profileId'));
    check('IA: handler pasa los perfiles', str_contains($moduleSrc, "'llmProfiles'    => function_exists('llm_profile_list')"));
    $reportViewSrc = (string)@file_get_contents($root . '/public_html/modules/threat_intelligence/views/unit42_report.php');
    check('IA: ficha muestra el perfil usado', str_contains($reportViewSrc, 'llm_profile_get($profileId)')
        && str_contains($reportViewSrc, 'perfil <?= e($profileName) ?>'));
    $tmpProfileArticle = Database::insert(
        "INSERT INTO u42_articles (path, sha, size, title, published_at, content, first_seen_at)
         VALUES ('u42-profile-smoke.txt','x',10,'Perfil smoke','2026-08-02','x',datetime('now'))"
    );
    $tmpProfileReport = Unit42Feed::createReport((int)$realUser['id'], [$tmpProfileArticle], 'resumen', 0, 7);
    check('IA: crear informe con perfil 7', !empty($tmpProfileReport['success']), json_encode($tmpProfileReport));
    $savedProfile = Database::fetchOne('SELECT profile_id FROM u42_reports WHERE id = ?', [(int)($tmpProfileReport['id'] ?? 0)]);
    check('IA: perfil 7 guardado en BD', (int)($savedProfile['profile_id'] ?? -1) === 7, json_encode($savedProfile));
    Database::query('DELETE FROM u42_reports WHERE id = ?', [(int)($tmpProfileReport['id'] ?? 0)]);
    Database::query('DELETE FROM u42_articles WHERE id = ?', [$tmpProfileArticle]);

    // --- Informes del artículo visibles al desplegar (v0.4.28.12) ---
    $artWithReport = Database::insert(
        "INSERT INTO u42_articles (path, sha, size, title, published_at, content, first_seen_at)
         VALUES ('u42-article-reports-smoke.txt','x',10,'Informes smoke','2026-08-03','x',datetime('now'))"
    );
    $emptyReports = Unit42Feed::reportsForArticle($artWithReport, (int)$realUser['id']);
    check('informes: artículo sin informes', $emptyReports === []);
    $rep = Unit42Feed::createReport((int)$realUser['id'], [$artWithReport], 'divulgativa', 0, 0);
    Database::query(
        "UPDATE u42_reports SET status = 'done', content_md = 'Informe de prueba', finished_at = datetime('now') WHERE id = ?",
        [(int)$rep['id']]
    );
    $withReports = Unit42Feed::reportsForArticle($artWithReport, (int)$realUser['id']);
    check('informes: reportsForArticle devuelve el informe', count($withReports) === 1
        && ($withReports[0]['kind'] ?? '') === 'divulgativa'
        && ($withReports[0]['status'] ?? '') === 'done', json_encode($withReports));
    $otherUserReports = Unit42Feed::reportsForArticle($artWithReport, 999999);
    check('informes: solo del usuario', $otherUserReports === []);
    check('informes: panel pasa reports al parcial', str_contains($moduleSrc, "'reports'    => Unit42Feed::reportsForArticle(\$id, \$userId)")
        && str_contains($moduleSrc, "'reports'        => Unit42Feed::reportsForArticle"));
    check('informes: tarjeta en el parcial', str_contains($panelSrc, 'Informes con IA de esta publicación')
        && str_contains($panelSrc, 'modules/threat_intelligence/unit42/report/')
        && str_contains($panelSrc, '$statusMap'));
    Database::query('DELETE FROM u42_reports WHERE id = ?', [(int)$rep['id']]);
    Database::query('DELETE FROM u42_articles WHERE id = ?', [$artWithReport]);
    $missingUi = smoke_css_missing_classes(
        [
            'modules/threat_intelligence/views/unit42.php',
            'modules/threat_intelligence/views/_unit42_panel.php',
            'modules/threat_intelligence/views/unit42_article.php',
        ],
        ['text-green-500', 'text-gray-400', 'text-amber-400', 'text-gray-300',
         'dark:text-gray-600', 'material-icons', 'icon-16']
    );
    check('CSS: clases del aspecto TI compiladas', $missingUi === [], implode(', ', $missingUi));
} catch (Throwable $e) {
    check('excepción inesperada: ' . $e->getMessage(), false, $e->getFile() . ':' . $e->getLine());
}

echo PHP_EOL . ($total - $fail) . '/' . $total . ' OK' . PHP_EOL;
exit($fail === 0 ? 0 : 1);
