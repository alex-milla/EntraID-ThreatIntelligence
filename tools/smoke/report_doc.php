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
        'kev'            => true,
        'kev_added'      => '2025-06-09',
        'kev_due'        => '2025-06-30',
        'kev_action'     => 'Apply mitigations per vendor instructions.',
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
    $reportWordHtml = CveReportAi::renderWordHtml($report, $items, $defender);

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
    check('cuerpo: tarjetas con caja marcadas', substr_count($html, 'data-rd-card') >= 4);
    check('cuerpo: el chip duplicado del CVE no viaja', substr_count($html, 'data-rd-drop') === 1);
    check('cuerpo: el CVSS lleva color y nivel', str_contains($html, 'data-rd-color="#dc2626" data-rd-level="crítico"'));
    check('cuerpo: el EPSS lleva color y nivel', str_contains($html, 'data-rd-level="muy alta"'));

    // ---------------------------------------------------------------
    // 2 bis. Documento generado en servidor para Word
    // ---------------------------------------------------------------
    check('word: el documento viaja en un template', str_contains($html, 'id="cve-report-word"'));
    check('word: sin colores oklch', !str_contains($reportWordHtml, 'oklch'));
    check('word: sin text-transform (Word lo ignora)', !str_contains($reportWordHtml, 'text-transform'));
    check('word: la cifra del CVSS usa <font color>', str_contains($reportWordHtml, '<font color="#dc2626"><b>10.0</b></font>'));
    check('word: el EPSS lleva su color', str_contains($reportWordHtml, '<font color="#dc2626"><b>62,88 %</b></font>'));
    check('word: badges en celdas con fondo hex', str_contains($reportWordHtml, 'background-color:#fee2e2')
        && str_contains($reportWordHtml, 'CRÍTICO'));
    check('word: el panel de CISA es una caja con fondo', str_contains($reportWordHtml, 'background-color:#fef2f2'));
    check('word: sin sangría horizontal heredada', preg_match('/<div style="[^"]*(padding|margin)-(left|right)/', $reportWordHtml) === 0);
    check('word: sin width en los contenedores de texto', !preg_match('/<p style="[^"]*width:/', $reportWordHtml));
    check('word: cifras sin barras ni glifos de bloque', !str_contains($reportWordHtml, '█') && !str_contains($reportWordHtml, '░'));

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
    check('helper: ya no dibuja barras en el documento', !str_contains($helper, 'buildBar') && !str_contains($helper, '\u2588'));
    check('helper: el color de la cifra va al final del estilo', str_contains($helper, 'El color siempre el último'));
    check('helper: no emite display en el estilo de la cifra', !str_contains($helper, "parts.push('display:inline')"));
    check('helper: cae al copiado heredado si la escritura falla', str_contains($helper, 'return legacyCopyRich(html);'));
    check('helper: usa el documento de Word del servidor', str_contains($helper, "rootId + '-word'") && str_contains($helper, 'data-rd-html'));
    check('helper: exporta sin sangría heredada', str_contains($helper, 'function stripHorizontalPadding'));
    check('helper: tarjetas como tabla de una celda', str_contains($helper, 'function cardToTable'));
    check('helper: detecta el badge numérico', str_contains($helper, 'function isNumberBadge'));
    check('helper: bordes por lado para Word', str_contains($helper, 'function borderShorthand'));
    check('helper: descarta lo marcado con data-rd-drop', str_contains($helper, "'[data-rd-drop]'"));
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
    check('vista CVE: usa el documento de Word', str_contains($aiReport, 'data-rd-html="cve-report-word"'));
    check('vista CVE: conserva Imprimir / PDF', str_contains($aiReport, 'Imprimir / PDF'));

    $workspace = (string)@file_get_contents($root . '/public_html/modules/cve/views/index.php');
    $moduleSrc = (string)@file_get_contents($root . '/public_html/modules/cve/module.php');
    check('workspace CVE: botón copiar', str_contains($workspace, 'id="ai-copy-btn"'));
    check('workspace CVE: botón .html', str_contains($workspace, 'id="ai-copy-html-btn"'));
    check('workspace CVE: botón .md', str_contains($workspace, 'id="ai-copy-md-btn"'));
    check('workspace CVE: usa el documento de Word', str_contains($workspace, 'data-rd-html="cve-report-word"'));
    check('workspace CVE: botón de Remediación siempre visible', str_contains($workspace, 'id="ai-remediation-btn"')
        && !preg_match('/id="ai-remediation-btn"[^>]*class="[^"]*\bhidden\b/', $workspace));
    check('workspace CVE: modal avisa sin selección', str_contains($workspace, 'function resetNotice')
        && str_contains($workspace, 'Marca el checkbox del CVE dentro del documento'));
    check('workspace CVE: opción enviar todos los CVEs', str_contains($workspace, 'ai-remediation-all-wrap')
        && str_contains($workspace, 'sendAll'));
    check('workspace CVE: botón con estilo de acción', preg_match('/id="ai-remediation-btn"[^>]*class="[^"]*border-line-strong/', $workspace) === 1
        && !preg_match('/id="ai-remediation-btn"[^>]*class="[^"]*bg-brand-600/', $workspace));
    check('handler: acepta el envío del informe entero', str_contains($moduleSrc, "!empty(\$input['all'])"));
    $bodySrc = (string)@file_get_contents($root . '/public_html/modules/cve/views/_ai_report_body.php');
    check('cuerpo: el checkbox nombra Remediación', str_contains($bodySrc, 'enviar a grupo o a Remediación'));

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
    check('dossier: la celda de métrica lleva el tono', str_contains($dossierSrc, 'data-rd-color='));

    $dossier = ExposedReportDossier::build(
        ['id' => 1, 'name' => 'Grupo de prueba'],
        [[
            'cve_id'           => 'CVE-2024-8522',
            'severity'         => 'critical',
            'cvss'             => 9.8,
            'epss'             => 0.62,
            'is_kev'           => 1,
            'exposed_machines' => 12,
            'age_days'         => 30,
            'first_detected_at' => '2026-10-01',
            'description'      => 'Prueba de tono.',
            'software_labels'  => 'SQL Server',
            'tvm_status'       => 'New',
        ]],
        []
    );
    $dossierHtml = (string)($dossier['html'] ?? '');
    check('dossier: el CVSS lleva color y nivel', str_contains($dossierHtml, 'data-rd-color="#dc2626" data-rd-level="crítico"'));
    check('dossier: el EPSS lleva color y nivel', str_contains($dossierHtml, 'data-rd-level="muy alta"'));

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
