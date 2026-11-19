<?php
/**
 * report_doc.php - Pruebas del copiado/exportación de documentos.
 *
 *   php tools/smoke/report_doc.php
 *
 * Cubre tres cosas sin tocar la base de datos:
 *   1. CveReportAi::renderMarkdown() produce el informe en Markdown.
 *   2. El documento del informe CVE ya no lleva metadatos técnicos dentro y
 *      expone la hoja (`#cve-report-doc`) y el Markdown (`#cve-report-md`).
 *   3. Las cuatro vistas que exportan documentos usan el helper compartido.
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
    if (!$ok) { $fail++; }
}

/**
 * Fragmento del documento entre <article …> y </article>.
 */
function articleFragment(string $html): string
{
    $start = strpos($html, '<article');
    $end = strpos($html, '</article>');
    if ($start === false || $end === false) {
        return '';
    }
    return substr($html, $start, $end - $start);
}

/**
 * Datos mínimos de un informe para renderizar el cuerpo.
 *
 * @return array<string,mixed>
 */
function fixtureReport(): array
{
    return [
        'id'              => 999001,
        'title'           => 'Informe CVE IA · CVE-2024-8522',
        'status'          => 'done',
        'cve_ids'         => '["CVE-2024-8522"]',
        'created_at'      => '2026-11-18 23:00:00',
        'updated_at'      => '2026-11-18 23:00:00',
        'revision'        => 1,
        'ai_model'        => 'Qwen_Qwen3.5-2B-Q4_K_M',
        'ai_duration_ms'  => 55100,
        'ai_profile_id'   => 1,
        'ai_profile_name' => 'Local',
        'ai_profile_model' => 'Qwen_Qwen3.5-2B-Q4_K_M',
        'ai_error'        => '',
        'no_ai'           => 0,
        'group_id'        => 0,
        'group_name'      => 'Microsoft SharePoint Server',
        'group_kind'      => 'company',
        'tags'            => '[]',
        'tags_array'      => [],
        'item_groups'     => [],
        'processed_items' => 1,
        'total_items'     => 1,
        'defender_json'   => null,
    ];
}

/**
 * @return array<int,array<string,mixed>>
 */
function fixtureItems(): array
{
    return [[
        'cve_id'         => 'CVE-2024-8522',
        'severity'       => 'Critical',
        'cvss'           => 10.0,
        'epss'           => 0.6288,
        'priority'       => 'A+',
        'vector'         => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'published_at'   => '2024-09-12',
        'description'    => 'The LINQPad for WordPress plugin is susceptible to SQL injection.',
        'description_es' => '',
        'nvd_url'        => 'https://nvd.nist.gov/vuln/detail/CVE-2024-8522',
        'kev'            => false,
        'kev_added'      => '',
        'kev_due'        => '',
        'kev_action'     => '',
        'kev_ransomware' => '',
        'github'         => [],
        'exploits'       => ['items' => []],
        'references'     => ['https://example.test/ref'],
        'tags'           => [],
        'group_name'     => '',
        'group_kind'     => '',
        'item_id'        => 0,
        'ai_status'      => 'done',
        'ai_sections'    => [[
            'title'      => 'Naturaleza y alcance',
            'bullets'    => ['El parámetro _wp_linqpad permite inyectar consultas.'],
            'paragraphs' => [],
        ]],
        'ai_error'       => '',
        'ai_model'       => 'Qwen_Qwen3.5-2B-Q4_K_M',
    ]];
}

try {
    // ---------------------------------------------------------------
    // 1. Markdown del informe
    // ---------------------------------------------------------------
    $report = fixtureReport();
    $items = fixtureItems();
    $md = CveReportAi::renderMarkdown($report, $items);

    check('markdown: cabecera del informe', str_contains($md, '# Informe de vulnerabilidad'));
    check('markdown: incluye el CVE', str_contains($md, '## Vulnerabilidad · CVE-2024-8522'));
    check('markdown: tabla de KPIs', str_contains($md, '| CVEs | En CISA KEV | CVSS máximo | Prioridad máxima |'));
    check('markdown: métricas del CVE', str_contains($md, '**CVSS:** 10.0') && str_contains($md, '**EPSS:** 62,88 %'));
    check('markdown: descripción', str_contains($md, '### Descripción') && str_contains($md, 'SQL injection'));
    check('markdown: secciones de IA', str_contains($md, '#### 1. Naturaleza y alcance'));
    check('markdown: viñetas de IA', str_contains($md, '- El parámetro _wp_linqpad permite inyectar consultas.'));
    check('markdown: referencias', str_contains($md, '### Referencias (1)'));
    check('markdown: pie con fuentes', str_contains($md, 'Fuentes: NVD · CISA KEV · EPSS'));
    check('markdown: sin modelo de IA', !str_contains($md, 'Qwen_Qwen3.5-2B'));
    check('markdown: sin duración de IA', !str_contains($md, '55,1 s'));
    check('markdown: sin fecha de generación', !str_contains($md, '18/11/2026 23:00'));

    $empty = CveReportAi::renderMarkdown(['tags_array' => [], 'item_groups' => []], []);
    check('markdown: informe vacío sin errores', str_contains($empty, '# Informe de vulnerabilidad'));

    // ---------------------------------------------------------------
    // 2. Cuerpo del informe: metadatos fuera del documento
    // ---------------------------------------------------------------
    $report = fixtureReport();
    $items = fixtureItems();
    $aiText = 'Análisis global de prueba.';
    $sections = [[
        'title'      => 'Resumen del conjunto',
        'bullets'    => ['Un punto del resumen.'],
        'paragraphs' => [],
    ]];
    $defender = [
        'generated_at' => '2026-11-18 10:00:00',
        'cves'         => [
            'CVE-2024-8522' => [
                'machine_total'    => 3,
                'exposed_machines' => 2,
                'public_exploit'   => true,
                'exploit_verified' => false,
                'products'         => ['SQL Server'],
                'tenants'          => ['Contoso'],
                'machines'         => [],
            ],
        ],
    ];
    $interactive = false;
    $isAdmin = false;
    $perItemMode = true;
    $reportMd = $md;

    ob_start();
    require MODULES_PATH . '/cve/views/_ai_report_body.php';
    $html = (string)ob_get_clean();

    $article = articleFragment($html);

    check('cuerpo: el documento tiene id para exportar', str_contains($html, 'id="cve-report-doc"'));
    check('cuerpo: el Markdown viaja oculto', str_contains($html, 'id="cve-report-md"'));
    check('cuerpo: el Markdown contiene el CVE', str_contains($html, 'CVE-2024-8522'));
    check('cuerpo: los metadatos existen en pantalla', str_contains($html, 'Ficha del informe'));
    check('cuerpo: el modelo se ve fuera del documento', str_contains($html, 'Modelo: Qwen_Qwen3.5-2B-Q4_K_M'));
    check('cuerpo: el modelo NO está dentro del documento', !str_contains($article, 'Modelo:'));
    check('cuerpo: la duración NO está dentro del documento', !str_contains($article, '55,1 s'));
    check('cuerpo: la fecha de generación NO está dentro del documento', !str_contains($article, '18/11/2026 23:00'));
    check('cuerpo: el badge del modelo sale de «Análisis con IA»', !str_contains($article, 'Qwen_Qwen3.5-2B'));
    check('cuerpo: la ficha del informe no se imprime', str_contains($html, 'ai-report-meta no-print'));
    check('cuerpo: los metadatos van antes del documento', strpos($html, 'ai-report-meta') < strpos($html, '<article'));
    check('cuerpo: KPIs y métricas marcadas para apilar', substr_count($html, 'data-rd-stack="metrics"') === 3);
    check('cuerpo: tarjetas marcadas como bloques', substr_count($html, 'data-rd-stack="blocks"') === 3);
    check('cuerpo: badges y chips marcados en línea', substr_count($html, 'data-rd-stack="inline"') >= 3);

    // ---------------------------------------------------------------
    // 3. Vistas y helper
    // ---------------------------------------------------------------
    $root = dirname(__DIR__, 2);
    $helper = @file_get_contents($root . '/public_html/assets/js/report-doc.js');
    $helper = is_string($helper) ? $helper : '';
    check('helper: existe report-doc.js', $helper !== '');
    check('helper: expone copyRich', str_contains($helper, 'ReportDoc.copyRich'));
    check('helper: expone downloadHtml', str_contains($helper, 'ReportDoc.downloadHtml'));
    check('helper: delega en data-rd-action', str_contains($helper, 'data-rd-action'));
    check('helper: exporta en columna única', str_contains($helper, 'data-rd-stack="metrics"')
        && str_contains($helper, 'data-rd-stack="blocks"')
        && str_contains($helper, 'data-rd-stack="inline"'));
    check('helper: construye líneas de métrica', str_contains($helper, 'function metricLine'));
    check('helper: reconstruye las barras como tabla', str_contains($helper, 'function buildBar'));
    check('helper: ya no convierte columnas en tablas', !str_contains($helper, 'toTable'));
    check('helper: no arrastra el modo oscuro', str_contains($helper, 'withLightTheme'));
    check('helper: respeta los estilos en línea del servidor', str_contains($helper, 'dst.style.getPropertyValue(prop)'));

    $footer = (string)@file_get_contents($root . '/public_html/views/layout/footer.php');
    check('layout: carga el helper', str_contains($footer, 'js/report-doc.js'));

    $aiReport = (string)@file_get_contents($root . '/public_html/modules/cve/views/ai_report.php');
    check('vista CVE: botón copiar', str_contains($aiReport, 'data-rd-action="copy-rich"'));
    check('vista CVE: botón .html', str_contains($aiReport, 'data-rd-action="download-html"'));
    check('vista CVE: botón .md', str_contains($aiReport, 'data-rd-action="download-md"'));
    check('vista CVE: botón texto', str_contains($aiReport, 'data-rd-action="copy-plain"'));
    check('vista CVE: conserva Imprimir / PDF', str_contains($aiReport, 'Imprimir / PDF'));

    $workspace = (string)@file_get_contents($root . '/public_html/modules/cve/views/index.php');
    check('workspace CVE: botón copiar', str_contains($workspace, 'id="ai-copy-btn"'));
    check('workspace CVE: botón .html', str_contains($workspace, 'id="ai-copy-html-btn"'));
    check('workspace CVE: botón .md', str_contains($workspace, 'id="ai-copy-md-btn"'));

    $group = (string)@file_get_contents($root . '/public_html/modules/exposed_report/views/group.php');
    check('exposed: usa el helper para copiar', str_contains($group, "ReportDoc.copyRich('exposed-plan-sheet'"));
    check('exposed: usa el helper para .html', str_contains($group, "ReportDoc.downloadHtml('exposed-plan-sheet'"));
    check('exposed: sin el inliner antiguo', !str_contains($group, 'function applyStyles'));

    $rem = (string)@file_get_contents($root . '/public_html/modules/remediation/views/reports.php');
    check('remediación: usa el helper para copiar', str_contains($rem, "ReportDoc.copyRich('rem-report-sheet'"));
    check('remediación: botón .html', str_contains($rem, 'remDownloadHtml()'));
    check('remediación: botón .md', str_contains($rem, 'remDownloadMd()'));
    check('remediación: el Markdown sigue disponible', str_contains($rem, 'id="rem-report-md"'));

    // ---------------------------------------------------------------
    // 4. Documentos generados en servidor
    // ---------------------------------------------------------------
    $dossierSrc = (string)@file_get_contents($root . '/public_html/includes/exposed_report_dossier.php');
    check('dossier: KPIs marcadas como métricas', str_contains($dossierSrc, '<table data-rd-stack="metrics"'));
    check('dossier: tarjeta marcada como bloques', str_contains($dossierSrc, 'data-rd-stack="blocks"'));

    $remHtml = RemediationReport::renderHtml(
        ['org_name' => 'Mi organización', 'periodo' => '2026-11', 'estado' => 'borrador'],
        [[
            'cve_id'   => 'CVE-2024-8522',
            'severity' => 'Critical',
            'cvss'     => 9.8,
            'epss'     => 0.5,
            'machines' => 3,
            'estado'   => 'en_curso',
            'due_at'   => '2026-12-01',
            'product'  => 'SQL Server',
        ]],
        [
            'created' => 2, 'closed' => 1, 'open' => 1, 'mttr' => 4.5,
            'sla_pct' => 80, 'sla_on_time' => 4, 'sla_total' => 5,
            'delays' => ['retraso' => ['days' => 2], 'bloqueo' => ['days' => 1]],
            'mttr_by_severity' => [],
        ]
    );
    check('remediación: la tira de KPIs se marca como métricas', str_contains($remHtml, 'data-rd-stack="metrics"'));
    check('remediación: la tabla de CVEs sigue siendo una tabla', str_contains($remHtml, '<thead>') && str_contains($remHtml, 'CVE-2024-8522'));
    check('remediación: las KPIs siguen a la vista', str_contains($remHtml, 'Críticos') && str_contains($remHtml, 'Equipos'));
} catch (Throwable $e) {
    check('excepción inesperada: ' . $e->getMessage(), false, $e->getFile() . ':' . $e->getLine());
}

echo PHP_EOL . ($total - $fail) . '/' . $total . ' OK' . PHP_EOL;
exit($fail === 0 ? 0 : 1);
