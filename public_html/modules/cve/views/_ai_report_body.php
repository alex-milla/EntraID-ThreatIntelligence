<?php
/**
 * Parcial: cuerpo del informe de CVE con IA.
 * Lo usan la página completa (ai_report.php) y el panel derecho del workspace.
 *
 * Variables: $report, $items, $aiText, $sections, $isAdmin (opcional).
 */

$report = is_array($report ?? null) ? $report : null;
$items = is_array($items ?? null) ? $items : [];
$aiText = (string)($aiText ?? '');
$sections = is_array($sections ?? null) ? $sections : [];
$defender = is_array($defender ?? null) ? $defender : null;
$isAdmin = !empty($isAdmin);
$perItemMode = !empty($perItemMode);
$interactive = !empty($interactive);
$reportTags = is_array($report['tags_array'] ?? null) ? $report['tags_array'] : [];
$itemGroups = is_array($report['item_groups'] ?? null) ? $report['item_groups'] : [];

$bodyStatus = (string)($report['status'] ?? 'pending');
$bodyError = trim((string)($report['ai_error'] ?? ''));
$bodyProcessing = in_array($bodyStatus, ['pending', 'running'], true);
$bodyNoAi = !empty($report['no_ai']);
$totalItems = (int)($report['total_items'] ?? count($items));
$processedItems = (int)($report['processed_items'] ?? 0);
$progressPct = $totalItems > 0 ? max(0, min(100, (int)round($processedItems * 100 / $totalItems))) : 0;
$progressText = $totalItems > 0
    ? 'Analizando CVE ' . max(1, min($processedItems + 1, $totalItems)) . ' de ' . $totalItems . '…'
    : 'La IA está redactando el análisis. Esta página se actualizará sola cuando termine.';

$bodyStatusLabels = [
    'pending'  => 'En cola',
    'running'  => 'Generando',
    'done'     => '',
    'error'    => 'Error de IA',
    'canceled' => 'Cancelado',
];
$bodyStatusClasses = [
    'pending'  => 'bg-gray-100 text-gray-600',
    'running'  => 'bg-blue-100 text-blue-700',
    'done'     => 'bg-green-100 text-green-700',
    'error'    => 'bg-red-100 text-red-700',
    'canceled' => 'bg-amber-100 text-amber-700',
];

$severityLabels = [
    'Critical' => 'CRÍTICO',
    'High'     => 'ALTO',
    'Medium'   => 'MEDIO',
    'Low'      => 'BAJO',
    'None'     => 'NINGUNO',
];
$severityClasses = [
    'Critical' => 'bg-red-100 text-red-700 border-red-200',
    'High'     => 'bg-orange-100 text-orange-700 border-orange-200',
    'Medium'   => 'bg-amber-100 text-amber-700 border-amber-200',
    'Low'      => 'bg-green-100 text-green-700 border-green-200',
    'None'     => 'bg-gray-100 text-gray-600 border-gray-200',
];
$severityBars = [
    'Critical' => 'bg-red-500',
    'High'     => 'bg-orange-500',
    'Medium'   => 'bg-amber-500',
    'Low'      => 'bg-green-500',
    'None'     => 'bg-gray-300',
];
$priorityClasses = [
    'A+' => 'bg-red-600 text-white',
    'A'  => 'bg-red-500 text-white',
    'B'  => 'bg-amber-500 text-white',
    'C'  => 'bg-blue-500 text-white',
    'D'  => 'bg-emerald-500 text-white',
];
$priorityOrder = ['A+' => 5, 'A' => 4, 'B' => 3, 'C' => 2, 'D' => 1];

$kevCount = 0;
$maxCvss = null;
$maxPriority = null;
foreach ($items as $item) {
    if (!empty($item['kev'])) {
        $kevCount++;
    }
    if (isset($item['cvss']) && $item['cvss'] !== null) {
        $maxCvss = $maxCvss === null ? (float)$item['cvss'] : max($maxCvss, (float)$item['cvss']);
    }
    $priority = (string)($item['priority'] ?? '');
    if ($priority !== '' && ($maxPriority === null || ($priorityOrder[$priority] ?? 0) > ($priorityOrder[$maxPriority] ?? 0))) {
        $maxPriority = $priority;
    }
}

$cveIds = [];
foreach ($items as $item) {
    if (!empty($item['cve_id'])) {
        $cveIds[] = (string)$item['cve_id'];
    }
}

$linkLabel = static function (string $url): string {
    $host = (string)parse_url($url, PHP_URL_HOST);
    $path = trim((string)parse_url($url, PHP_URL_PATH), '/');
    $label = $host !== '' ? $host : $url;
    if ($host === 'github.com' || $host === 'www.github.com') {
        return $path !== '' ? $path : $label;
    }
    if ($path !== '') {
        $label .= '/' . truncate($path, 48);
    }
    return $label;
};

$exposureLabel = static function (string $value): string {
    $map = [
        'critical' => 'Crítica',
        'high'     => 'Alta',
        'medium'   => 'Media',
        'low'      => 'Baja',
        'none'     => 'Ninguna',
        'unknown'  => 'Desconocida',
    ];
    $key = strtolower(trim($value));
    return $map[$key] ?? $value;
};
?>
<div class="ai-report-body" data-report-id="<?= (int)($report['id'] ?? 0) ?>" data-status="<?= e($bodyStatus) ?>" data-group-id="<?= (int)($report['group_id'] ?? 0) ?>">

    <?php if ($bodyProcessing): ?>
        <div class="mb-5 px-4 py-3 rounded-lg text-sm bg-blue-50 text-blue-700 flex items-start justify-between gap-3 flex-wrap no-print" id="ai-processing-banner">
            <div class="flex items-start gap-3 min-w-0 flex-1">
                <svg class="w-4 h-4 animate-spin shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"/></svg>
                <div class="min-w-0 flex-1">
                    <span id="ai-processing-text"><?= e($progressText) ?></span>
                    <div class="mt-2 h-1.5 w-full max-w-xs rounded-full bg-blue-100 overflow-hidden">
                        <div id="ai-processing-bar" class="h-full bg-blue-600 transition-all" style="width: <?= $progressPct ?>%"></div>
                    </div>
                </div>
            </div>
            <?php if ($isAdmin): ?>
                <div class="flex items-center gap-2 shrink-0">
                    <button type="button" onclick="runCveAiReport()"
                            class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium rounded-lg transition-colors">
                        Ejecutar ahora
                    </button>
                    <button type="button" onclick="cancelCveAiReport()"
                            class="px-3 py-1.5 border border-blue-200 text-blue-700 text-xs font-medium rounded-lg hover:bg-blue-100 transition-colors">
                        Cancelar
                    </button>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php if ($bodyStatus === 'error' && $bodyError !== ''): ?>
        <div class="mb-5 px-4 py-3 rounded-lg text-sm bg-red-50 text-red-700 flex items-start justify-between gap-3 flex-wrap no-print">
            <div class="min-w-0">
                <p class="font-semibold">La evaluación con IA no se pudo completar</p>
                <p class="text-xs mt-1 break-words"><?= e($bodyError) ?></p>
            </div>
            <?php if ($isAdmin): ?>
                <button type="button" onclick="retryCveAiReport()"
                        class="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs font-medium rounded-lg transition-colors shrink-0">
                    Reintentar
                </button>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php if ($bodyStatus === 'canceled'): ?>
        <div class="mb-5 px-4 py-3 rounded-lg text-sm bg-amber-50 text-amber-700 flex items-start justify-between gap-3 flex-wrap no-print">
            <div class="min-w-0">
                <p class="font-semibold">Informe cancelado</p>
                <p class="text-xs mt-1">Puedes reintentarlo cuando quieras; se volverá a encolar y ejecutar.</p>
            </div>
            <?php if ($isAdmin): ?>
                <button type="button" onclick="retryCveAiReport()"
                        class="px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white text-xs font-medium rounded-lg transition-colors shrink-0">
                    Reintentar
                </button>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <article class="report-doc bg-white text-gray-900 rounded-xl border border-gray-200 shadow-sm">
        <header class="px-7 pt-7 pb-5 border-b border-gray-200">
            <p class="text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-400">Informe de vulnerabilidad</p>
            <h1 class="text-2xl font-bold mt-1 break-words">
                <?php if (count($items) === 1): ?>
                    <?= e((string)$items[0]['cve_id']) ?>
                <?php elseif (count($items) > 1): ?>
                    <?= count($items) ?> vulnerabilidades analizadas
                <?php else: ?>
                    <?= e((string)($report['title'] ?? 'Informe CVE')) ?>
                <?php endif; ?>
            </h1>

            <?php if ($cveIds !== []): ?>
                <div class="flex items-center gap-1.5 flex-wrap mt-3">
                    <?php foreach ($cveIds as $cveId): ?>
                        <a href="https://nvd.nist.gov/vuln/detail/<?= e(rawurlencode($cveId)) ?>"
                           target="_blank" rel="noopener noreferrer"
                           class="px-2 py-0.5 rounded-md bg-gray-100 text-[11px] font-mono text-gray-700 hover:bg-gray-200">
                            <?= e($cveId) ?>
                        </a>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <?php if ($reportTags !== []): ?>
                <div class="flex items-center gap-1.5 flex-wrap mt-2">
                    <span class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Tags</span>
                    <?php foreach ($reportTags as $tag): ?>
                        <span class="report-badge inline-flex px-2 py-0.5 rounded-full border border-brand-200 bg-brand-50 text-[10px] font-medium text-brand-700">
                            #<?= e($tag) ?>
                        </span>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <?php if ($itemGroups !== []): ?>
                <p class="text-[11px] text-gray-500 mt-2">Grupos: <?= e(implode(' · ', $itemGroups)) ?></p>
            <?php endif; ?>

            <div class="flex items-center gap-2 flex-wrap mt-4 text-xs text-gray-500">
                <?php if ($bodyStatus !== 'done' && ($bodyStatusLabels[$bodyStatus] ?? '') !== ''): ?>
                    <span class="px-2 py-0.5 rounded-full text-[10px] font-medium <?= $bodyStatusClasses[$bodyStatus] ?? 'bg-gray-100 text-gray-600' ?>">
                        <?= e($bodyStatusLabels[$bodyStatus] ?? $bodyStatus) ?>
                    </span>
                <?php endif; ?>
                <?php if (!empty($report['ai_model'])): ?>
                    <span>Modelo: <?= e((string)$report['ai_model']) ?></span>
                <?php endif; ?>
                <?php if (!empty($report['ai_duration_ms'])): ?>
                    <span>· <?= e(number_format((int)$report['ai_duration_ms'] / 1000, 1, ',', '.')) ?> s</span>
                <?php endif; ?>
                <?php $revision = max(1, (int)($report['revision'] ?? 1)); ?>
                <?php if ($revision > 1): ?>
                    <span>· v<?= $revision ?> · actualizado <?= e(format_db_date((string)($report['updated_at'] ?? $report['created_at'] ?? ''), 'd/m/Y H:i')) ?></span>
                <?php else: ?>
                    <span>· generado <?= e(format_db_date((string)($report['created_at'] ?? ''), 'd/m/Y H:i')) ?></span>
                <?php endif; ?>
                <?php if (!empty($report['group_name'])): ?>
                    <span>· <?= (string)($report['group_kind'] ?? '') === 'company' ? 'empresa' : 'grupo' ?>: <?= e((string)$report['group_name']) ?></span>
                <?php endif; ?>
            </div>
        </header>

        <?php if ($items !== []): ?>
            <div class="report-summary grid grid-cols-2 sm:grid-cols-4 border-b border-gray-200 divide-x divide-gray-200">
                <div class="px-5 py-4">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">CVEs</p>
                    <p class="text-xl font-bold mt-0.5"><?= count($items) ?></p>
                </div>
                <div class="px-5 py-4">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">En CISA KEV</p>
                    <p class="text-xl font-bold mt-0.5 <?= $kevCount > 0 ? 'text-red-600' : '' ?>"><?= $kevCount ?></p>
                </div>
                <div class="px-5 py-4">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">CVSS máximo</p>
                    <p class="text-xl font-bold mt-0.5"><?= $maxCvss !== null ? e(number_format($maxCvss, 1, '.', '')) : '—' ?></p>
                </div>
                <div class="px-5 py-4">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Prioridad máxima</p>
                    <p class="text-xl font-bold mt-0.5"><?= $maxPriority !== null ? e($maxPriority) : '—' ?></p>
                </div>
            </div>
        <?php endif; ?>

        <div class="px-7 py-6 space-y-8">
            <?php if ($items === []): ?>
                <div class="py-8 text-center">
                    <h2 class="text-sm font-semibold">Sin datos del catálogo</h2>
                    <p class="text-sm text-gray-500 mt-2">
                        El informe no tiene datos asociados. Vuelve a generarlo desde la pestaña Informes.
                    </p>
                </div>
            <?php endif; ?>

            <?php foreach ($items as $index => $item): ?>
                <?php
                $cveId = (string)($item['cve_id'] ?? '');
                $severity = (string)($item['severity'] ?? '');
                $severityBar = $severityBars[$severity] ?? $severityBars['None'];
                $cvss = isset($item['cvss']) && $item['cvss'] !== null ? (float)$item['cvss'] : null;
                $epss = isset($item['epss']) && $item['epss'] !== null ? (float)$item['epss'] : null;
                $epssPct = $epss !== null ? max(0, min(100, $epss * 100)) : 0;
                $priority = (string)($item['priority'] ?? '');
                $vector = (string)($item['vector'] ?? '');
                $published = (string)($item['published_at'] ?? '');
                $descriptionEs = CveReportAi::cleanTranslatedText((string)($item['description_es'] ?? ''));
                $description = $descriptionEs !== '' ? $descriptionEs : trim((string)($item['description'] ?? ''));
                $descriptionLang = $descriptionEs !== '' ? 'es' : 'en';
                $github = is_array($item['github'] ?? null) ? $item['github'] : [];
                $exploits = is_array($item['exploits'] ?? null) ? $item['exploits'] : [];
                $exploitItems = is_array($exploits['items'] ?? null) ? $exploits['items'] : [];
                $references = is_array($item['references'] ?? null) ? $item['references'] : [];
                $isKev = !empty($item['kev']);
                $kevActionEs = CveReportAi::cleanTranslatedText((string)($item['kev_action_es'] ?? ''));
                $kevAction = $kevActionEs !== '' ? $kevActionEs : trim((string)($item['kev_action'] ?? ''));
                $nvdUrl = (string)($item['nvd_url'] ?? '');
                if (!preg_match('#^https?://#i', $nvdUrl)) {
                    $nvdUrl = 'https://nvd.nist.gov/vuln/detail/' . rawurlencode($cveId);
                }
                $packetStormUrl = 'https://packetstormsecurity.com/search/?q=' . rawurlencode($cveId);
                $exposure = ($defender !== null && isset($defender['cves'][$cveId]) && is_array($defender['cves'][$cveId]))
                    ? $defender['cves'][$cveId]
                    : null;
                $itemId = (int)($item['item_id'] ?? 0);
                $itemTags = is_array($item['tags'] ?? null) ? $item['tags'] : [];
                $itemGroup = (string)($item['group_name'] ?? '');
                $itemGroupKind = (string)($item['group_kind'] ?? '');
                $itemAiStatus = (string)($item['ai_status'] ?? '');
                $itemSections = is_array($item['ai_sections'] ?? null) ? $item['ai_sections'] : [];
                $itemAiError = trim((string)($item['ai_error'] ?? ''));
                $itemAiModel = (string)($item['ai_model'] ?? '');
                ?>
                <section class="report-cve border-l-4 <?= $severity === 'Critical' ? 'border-red-500' : ($severity === 'High' ? 'border-orange-500' : ($severity === 'Medium' ? 'border-amber-500' : ($severity === 'Low' ? 'border-green-500' : 'border-gray-300'))) ?> pl-5" id="cve-<?= e($cveId) ?>">
                    <?php if ($interactive && $isAdmin && $itemId > 0): ?>
                        <label class="no-print inline-flex items-center gap-1.5 mb-2 text-[10px] font-medium text-gray-400 cursor-pointer">
                            <input type="checkbox" class="ai-cve-check rounded border-gray-300 text-brand-500 focus:ring-brand-500"
                                   data-item-id="<?= $itemId ?>"
                                   data-cve-id="<?= e($cveId) ?>"
                                   data-tags="<?= e(json_encode($itemTags, JSON_UNESCAPED_UNICODE)) ?>">
                            Seleccionar para etiquetar o enviar a grupo
                        </label>
                    <?php endif; ?>

                    <?php if ($itemTags !== [] || $itemGroup !== ''): ?>
                        <div class="flex items-center gap-1.5 flex-wrap mb-2">
                            <?php foreach ($itemTags as $tag): ?>
                                <span class="report-badge inline-flex px-2 py-0.5 rounded-full border border-brand-200 bg-brand-50 text-[10px] font-medium text-brand-700">
                                    #<?= e($tag) ?>
                                </span>
                            <?php endforeach; ?>
                            <?php if ($itemGroup !== ''): ?>
                                <span class="text-[10px] text-gray-500"><?= $itemGroupKind === 'company' ? 'Empresa' : 'Grupo' ?>: <strong><?= e($itemGroup) ?></strong></span>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>

                    <div class="flex items-start justify-between gap-3 flex-wrap">
                        <div class="min-w-0">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Vulnerabilidad</p>
                            <h2 class="text-xl font-bold mt-0.5 font-mono"><?= e($cveId) ?></h2>
                        </div>
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="report-badge px-2.5 py-1 rounded-md border text-[11px] font-semibold <?= $severityClasses[$severity] ?? $severityClasses['None'] ?>">
                                <?= e($severityLabels[$severity] ?? ($severity !== '' ? strtoupper($severity) : 'SIN DATOS')) ?>
                            </span>
                            <?php if ($priority !== ''): ?>
                                <span class="report-badge px-2.5 py-1 rounded-md text-[11px] font-semibold <?= $priorityClasses[$priority] ?? 'bg-gray-200 text-gray-700' ?>">
                                    Prioridad <?= e($priority) ?>
                                </span>
                            <?php endif; ?>
                            <a href="<?= e($nvdUrl) ?>" target="_blank" rel="noopener noreferrer"
                               class="px-2.5 py-1 rounded-md border border-gray-200 text-[11px] font-medium text-gray-600 hover:bg-gray-50">
                                NVD <span class="print-hide">↗</span>
                            </a>
                            <span class="print-url"><?= e($nvdUrl) ?></span>
                        </div>
                    </div>

                    <dl class="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5 pb-5 border-b border-gray-100">
                        <div>
                            <dt class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">CVSS</dt>
                            <dd class="text-3xl font-bold mt-0.5 leading-none"><?= $cvss !== null ? e(number_format($cvss, 1, '.', '')) : '—' ?></dd>
                            <span class="report-meter block mt-1 h-1 rounded-full <?= $severityBar ?>" style="width: <?= $cvss !== null ? e(number_format(min(100, $cvss * 10), 0, '.', '')) : 0 ?>%"></span>
                        </div>
                        <div>
                            <dt class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">EPSS</dt>
                            <dd class="mt-1">
                                <span class="text-sm font-semibold"><?= $epss !== null ? e(number_format($epssPct, 2, ',', '')) . ' %' : '—' ?></span>
                                <span class="report-meter block mt-1 h-1.5 rounded-full bg-gray-100 overflow-hidden">
                                    <span class="block h-full rounded-full bg-amber-500" style="width: <?= e(number_format($epssPct, 1, '.', '')) ?>%"></span>
                                </span>
                            </dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">CISA KEV</dt>
                            <dd class="mt-0.5">
                                <?php if ($isKev): ?>
                                    <span class="inline-flex px-2 py-0.5 rounded-md bg-red-100 text-red-700 text-[11px] font-semibold">Sí</span>
                                    <?php if (!empty($item['kev_added'])): ?>
                                        <span class="block text-[10px] text-gray-500 mt-1">Añadido <?= e((string)$item['kev_added']) ?></span>
                                    <?php endif; ?>
                                <?php else: ?>
                                    <span class="inline-flex px-2 py-0.5 rounded-md bg-gray-100 text-gray-600 text-[11px] font-semibold">No</span>
                                <?php endif; ?>
                            </dd>
                        </div>
                        <div>
                            <dt class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Publicado</dt>
                            <dd class="text-sm font-semibold mt-0.5"><?= e($published !== '' ? $published : '—') ?></dd>
                        </div>
                    </dl>

                    <?php if ($vector !== ''): ?>
                        <p class="mt-4 text-[11px] font-mono text-gray-500 break-all"><?= e($vector) ?></p>
                    <?php endif; ?>

                    <?php if ($description !== ''): ?>
                        <div class="mt-4">
                            <div class="flex items-center gap-2">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Descripción</p>
                                <span class="text-[10px] text-gray-400">
                                    <?= $descriptionLang === 'es' ? 'catálogo local' : 'original (inglés)' ?>
                                </span>
                            </div>
                            <p class="text-sm leading-relaxed text-gray-600 mt-1"><?= e($description) ?></p>
                        </div>
                    <?php endif; ?>

                    <?php if ($isKev && (!empty($item['kev_action']) || !empty($item['kev_due']) || strcasecmp((string)($item['kev_ransomware'] ?? ''), 'Known') === 0)): ?>
                        <div class="report-kev-action mt-4 px-4 py-3 rounded-lg bg-red-50 border border-red-100">
                            <div class="flex items-center gap-2 flex-wrap">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-red-500">Acción requerida (CISA)</p>
                                <?php if ($kevActionEs === '' && $kevAction !== ''): ?>
                                    <span class="text-[10px] text-red-400">original (inglés)</span>
                                <?php endif; ?>
                            </div>
                            <?php if ($kevAction !== ''): ?>
                                <p class="text-sm text-red-800 mt-1"><?= e($kevAction) ?></p>
                            <?php endif; ?>
                            <p class="text-[11px] text-red-700 mt-1">
                                <?php if (!empty($item['kev_due'])): ?>Vence el <?= e((string)$item['kev_due']) ?>. <?php endif; ?>
                                <?php if (strcasecmp((string)($item['kev_ransomware'] ?? ''), 'Known') === 0): ?>Ransomware conocido.<?php endif; ?>
                            </p>
                        </div>
                    <?php endif; ?>

                    <?php if ($exposure !== null): ?>
                        <div class="report-exposure mt-5 rounded-lg border border-blue-100 bg-blue-50/60 p-4">
                            <div class="flex items-center justify-between gap-2 flex-wrap">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-blue-600">Exposición en tu entorno · Defender</p>
                                <span class="text-[10px] text-gray-400">Foto: <?= e(format_db_date((string)($defender['generated_at'] ?? ''), 'd/m/Y H:i')) ?></span>
                            </div>
                            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-3 text-xs">
                                <div>
                                    <p class="text-gray-500">Equipos afectados</p>
                                    <p class="text-lg font-bold"><?= (int)($exposure['machine_total'] ?? 0) ?></p>
                                </div>
                                <div>
                                    <p class="text-gray-500">Expuestos (Defender)</p>
                                    <p class="text-lg font-bold"><?= (int)($exposure['exposed_machines'] ?? 0) ?></p>
                                </div>
                                <div>
                                    <p class="text-gray-500">Exploit público</p>
                                    <p class="text-sm font-semibold <?= !empty($exposure['public_exploit']) ? 'text-red-600' : 'text-gray-600' ?>">
                                        <?= !empty($exposure['public_exploit']) ? 'Sí' : 'No' ?>
                                    </p>
                                </div>
                                <div>
                                    <p class="text-gray-500">Exploit verificado</p>
                                    <p class="text-sm font-semibold <?= !empty($exposure['exploit_verified']) ? 'text-red-600' : 'text-gray-600' ?>">
                                        <?= !empty($exposure['exploit_verified']) ? 'Sí' : 'No' ?>
                                    </p>
                                </div>
                            </div>
                            <?php if (!empty($exposure['products'])): ?>
                                <p class="text-xs mt-3">
                                    <span class="text-gray-500">Productos:</span>
                                    <?= e(implode(' · ', array_slice((array)$exposure['products'], 0, 6))) ?>
                                </p>
                            <?php endif; ?>
                            <?php if (!empty($exposure['tenants'])): ?>
                                <p class="text-xs mt-1">
                                    <span class="text-gray-500">Tenants:</span>
                                    <?= e(implode(' · ', (array)$exposure['tenants'])) ?>
                                </p>
                            <?php endif; ?>
                            <?php if (!empty($exposure['machines'])): ?>
                                <div class="mt-3 overflow-x-auto">
                                    <table class="w-full text-xs">
                                        <thead>
                                            <tr class="text-[10px] uppercase text-gray-400 border-b border-blue-100">
                                                <th class="text-left py-1.5 pr-3">Equipo</th>
                                                <th class="text-left py-1.5 pr-3">SO</th>
                                                <th class="text-left py-1.5 pr-3">Exposición</th>
                                                <th class="text-left py-1.5 pr-3">Riesgo</th>
                                                <th class="text-left py-1.5 pr-3">Visto</th>
                                                <th class="text-left py-1.5">Tenant</th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-blue-50">
                                            <?php foreach ($exposure['machines'] as $machine): ?>
                                                <tr>
                                                    <td class="py-1.5 pr-3 font-medium text-gray-700"><?= e((string)($machine['name'] ?? '—')) ?></td>
                                                    <td class="py-1.5 pr-3 text-gray-600"><?= e((string)($machine['os'] ?? '—')) ?></td>
                                                    <td class="py-1.5 pr-3 text-gray-600"><?= e($exposureLabel((string)($machine['exposure'] ?? '—'))) ?></td>
                                                    <td class="py-1.5 pr-3 text-gray-600"><?= e($exposureLabel((string)($machine['risk'] ?? '—'))) ?></td>
                                                    <td class="py-1.5 pr-3 text-gray-500 whitespace-nowrap"><?= e(format_db_date((string)($machine['last_seen'] ?? ''), 'd/m/Y H:i')) ?></td>
                                                    <td class="py-1.5 text-gray-600"><?= e((string)($machine['tenant'] ?? '—')) ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                    <?php if ((int)($exposure['machine_total'] ?? 0) > count($exposure['machines'])): ?>
                                        <p class="text-[11px] text-gray-400 mt-1">… y <?= (int)$exposure['machine_total'] - count($exposure['machines']) ?> equipos más.</p>
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
                        <div class="report-links-card rounded-lg border border-gray-200 p-4">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">
                                Exploits públicos (<?= count($exploitItems) ?>)
                            </p>
                            <?php if ($exploitItems === [] && $github === []): ?>
                                <p class="text-sm text-gray-500 mt-2">Sin exploits en las fuentes consultadas (GitHub PoC, Nuclei).</p>
                            <?php else: ?>
                                <?php if ($exploitItems !== []): ?>
                                    <ul class="mt-2 space-y-2">
                                        <?php foreach (array_slice($exploitItems, 0, 12) as $exploit): ?>
                                            <?php
                                            $exploitSource = (string)($exploit['source_label'] ?? $exploit['source'] ?? 'Exploit');
                                            $exploitUrl = (string)($exploit['url'] ?? '');
                                            $exploitTitle = trim((string)($exploit['title'] ?? ''));
                                            $exploitDate = trim((string)($exploit['published_at'] ?? ''));
                                            ?>
                                            <li>
                                                <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">
                                                    <?= e($exploitSource) ?>
                                                    <?php if ($exploitDate !== ''): ?>
                                                        · <?= e(format_db_date($exploitDate, 'd/m/Y')) ?>
                                                    <?php endif; ?>
                                                </p>
                                                <?php if ($exploitTitle !== '' && $exploitTitle !== $exploitUrl): ?>
                                                    <p class="text-xs text-gray-600 mt-0.5"><?= e(truncate($exploitTitle, 140)) ?></p>
                                                <?php endif; ?>
                                                <a href="<?= e($exploitUrl) ?>" target="_blank" rel="noopener noreferrer"
                                                   class="text-sm text-brand-600 hover:underline break-all">
                                                    <?= e($linkLabel($exploitUrl)) ?> <span class="print-hide">↗</span>
                                                </a>
                                                <span class="print-url"><?= e($exploitUrl) ?></span>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                    <?php if (count($exploitItems) > 12): ?>
                                        <p class="text-[11px] text-gray-400 mt-1">… y <?= count($exploitItems) - 12 ?> más</p>
                                    <?php endif; ?>
                                <?php endif; ?>

                                <?php if ($github !== []): ?>
                                    <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400 mt-3">
                                        Referencias GitHub (sin verificar) (<?= count($github) ?>)
                                    </p>
                                    <ul class="mt-1 space-y-1">
                                        <?php foreach (array_slice($github, 0, 6) as $url): ?>
                                            <li>
                                                <a href="<?= e((string)$url) ?>" target="_blank" rel="noopener noreferrer"
                                                   class="text-xs text-gray-500 hover:underline break-all">
                                                    <?= e($linkLabel((string)$url)) ?> <span class="print-hide">↗</span>
                                                </a>
                                                <span class="print-url"><?= e((string)$url) ?></span>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                    <?php if (count($github) > 6): ?>
                                        <p class="text-[11px] text-gray-400 mt-1">… y <?= count($github) - 6 ?> más</p>
                                    <?php endif; ?>
                                <?php endif; ?>
                            <?php endif; ?>
                            <a href="<?= e($packetStormUrl) ?>"
                               target="_blank" rel="noopener noreferrer"
                               class="inline-block mt-3 text-[11px] font-medium text-gray-500 hover:text-gray-800">
                                Buscar en PacketStorm <span class="print-hide">↗</span>
                            </a>
                            <span class="print-url"><?= e($packetStormUrl) ?></span>
                        </div>

                        <div class="report-links-card rounded-lg border border-gray-200 p-4">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">
                                Referencias (<?= count($references) ?>)
                            </p>
                            <?php if ($references === []): ?>
                                <p class="text-sm text-gray-500 mt-2">Sin referencias adicionales.</p>
                            <?php else: ?>
                                <ul class="mt-2 space-y-1.5">
                                    <?php foreach (array_slice($references, 0, 12) as $url): ?>
                                        <li>
                                            <a href="<?= e((string)$url) ?>" target="_blank" rel="noopener noreferrer"
                                               title="<?= e((string)$url) ?>"
                                               class="text-sm text-brand-600 hover:underline break-all">
                                                <?= e($linkLabel((string)$url)) ?> <span class="print-hide">↗</span>
                                            </a>
                                            <span class="print-url"><?= e((string)$url) ?></span>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                                <?php if (count($references) > 12): ?>
                                    <p class="text-[11px] text-gray-400 mt-1">… y <?= count($references) - 12 ?> más</p>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>

                    <?php if ($itemAiStatus === 'error'): ?>
                        <div class="mt-5 px-4 py-3 rounded-lg bg-red-50 border border-red-100 text-xs text-red-700">
                            <strong>Análisis IA no disponible:</strong>
                            <?= e($itemAiError !== '' ? $itemAiError : 'Error desconocido.') ?>
                            <?php if ($interactive && $isAdmin && $itemId > 0): ?>
                                <button type="button" data-retry-item="<?= $itemId ?>" class="retry-ai-item no-print ml-2 underline">
                                    Reintentar
                                </button>
                            <?php endif; ?>
                        </div>
                    <?php elseif ($itemSections !== []): ?>
                        <div class="report-ai report-ai-cve mt-5 pt-4 border-t border-gray-100">
                            <div class="flex items-center gap-2 flex-wrap">
                                <h3 class="text-sm font-semibold">Análisis con IA</h3>
                                <?php if ($itemAiModel !== ''): ?>
                                    <span class="text-[10px] text-gray-400"><?= e($itemAiModel) ?></span>
                                <?php endif; ?>
                            </div>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                                <?php foreach ($itemSections as $sectionIndex => $itemSection): ?>
                                    <div class="report-ai-block rounded-lg border border-gray-200 p-3">
                                        <h4 class="text-xs font-semibold flex items-center gap-2">
                                            <span class="inline-flex items-center justify-center w-4 h-4 rounded-full bg-gray-900 text-white text-[9px] font-bold">
                                                <?= (int)$sectionIndex + 1 ?>
                                            </span>
                                            <?= e((string)($itemSection['title'] ?? 'Análisis')) ?>
                                        </h4>
                                        <?php if (!empty($itemSection['bullets'])): ?>
                                            <ul class="mt-2 space-y-1 text-xs leading-relaxed text-gray-600 list-disc pl-4">
                                                <?php foreach ($itemSection['bullets'] as $bullet): ?>
                                                    <li><?= e((string)$bullet) ?></li>
                                                <?php endforeach; ?>
                                            </ul>
                                        <?php endif; ?>
                                        <?php foreach (($itemSection['paragraphs'] ?? []) as $paragraph): ?>
                                            <p class="mt-2 text-xs leading-relaxed text-gray-600"><?= e((string)$paragraph) ?></p>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    <?php elseif (in_array($itemAiStatus, ['pending', 'running'], true)): ?>
                        <p class="no-print mt-4 text-xs text-blue-600">Análisis de IA pendiente para este CVE…</p>
                    <?php endif; ?>
                </section>

                <?php if ($index < count($items) - 1): ?>
                    <hr class="border-gray-100">
                <?php endif; ?>
            <?php endforeach; ?>

            <?php if ($bodyNoAi): ?>
                <div class="rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-600">
                    Informe generado en <strong>modo solo datos</strong>: no se solicitó análisis a la IA.
                </div>
            <?php elseif ($sections !== []): ?>
                <section class="report-ai pt-2">
                    <div class="flex items-center gap-2">
                        <h2 class="text-base font-semibold">Análisis con IA</h2>
                        <span class="text-[10px] px-2 py-0.5 rounded-full bg-gray-100 text-gray-500">Generado automáticamente</span>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                        <?php foreach ($sections as $i => $section): ?>
                            <div class="report-ai-block rounded-lg border border-gray-200 p-4">
                                <h3 class="text-sm font-semibold flex items-center gap-2">
                                    <span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-gray-900 text-white text-[10px] font-bold">
                                        <?= (int)$i + 1 ?>
                                    </span>
                                    <?= e((string)$section['title']) ?>
                                </h3>
                                <?php if (!empty($section['bullets'])): ?>
                                    <ul class="mt-2.5 space-y-1.5 text-sm leading-relaxed text-gray-600 list-disc pl-5">
                                        <?php foreach ($section['bullets'] as $bullet): ?>
                                            <li><?= e((string)$bullet) ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php endif; ?>
                                <?php foreach (($section['paragraphs'] ?? []) as $paragraph): ?>
                                    <p class="mt-2.5 text-sm leading-relaxed text-gray-600"><?= e((string)$paragraph) ?></p>
                                <?php endforeach; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </section>
            <?php elseif ($aiText !== ''): ?>
                <section class="report-ai pt-2">
                    <h2 class="text-base font-semibold">Análisis con IA</h2>
                    <p class="mt-2 text-sm leading-relaxed text-gray-600 whitespace-pre-line"><?= e($aiText) ?></p>
                </section>
            <?php endif; ?>
        </div>

        <footer class="px-7 py-5 border-t border-gray-200 text-[11px] leading-relaxed text-gray-400">
            <p>Fuentes: NVD · CISA KEV · EPSS · GitHub PoC · Nuclei · Exploit-DB · Metasploit. Prioridad calculada con la fórmula de SploitScan (KEV, CVSS, EPSS y exploits públicos).</p>
            <p class="mt-1">La evaluación de riesgo es una estimación generada por IA; verifica siempre la información antes de tomar decisiones.</p>
        </footer>
    </article>

    <style>
        @media print {
            @page { size: A4 portrait; margin: 16mm 14mm 18mm; }

            .report-doc {
                border: 0 !important;
                border-radius: 0 !important;
                box-shadow: none !important;
                background: #fff !important;
                font-size: 9.8pt;
                line-height: 1.45;
            }
            .report-doc,
            .report-doc p,
            .report-doc li,
            .report-doc h1,
            .report-doc h2,
            .report-doc h3,
            .report-doc dt,
            .report-doc dd,
            .report-doc td,
            .report-doc th,
            .report-doc a { color: #111 !important; }
            .report-doc .text-gray-400,
            .report-doc .text-gray-500,
            .report-doc .text-gray-600 { color: #555 !important; }
            .report-doc .text-red-500, .report-doc .text-red-600,
            .report-doc .text-red-700, .report-doc .text-red-800,
            .report-doc .text-amber-500, .report-doc .text-amber-600,
            .report-doc .text-orange-500, .report-doc .text-orange-700,
            .report-doc .text-blue-600 { color: #111 !important; }
            .report-doc .bg-red-50, .report-doc .bg-red-100,
            .report-doc .bg-blue-50, .report-doc .bg-gray-50,
            .report-doc .bg-gray-100, .report-doc .bg-amber-100,
            .report-doc .bg-orange-100, .report-doc .bg-green-100 { background: #fff !important; }
            .report-doc a { text-decoration: none !important; }

            .print-url {
                display: block !important;
                font-size: 7.5pt !important;
                color: #555 !important;
                word-break: break-all;
                margin-top: 0.5mm;
            }
            .print-hide { display: none !important; }

            /* Cabecera del documento */
            .report-doc > header {
                padding: 0 0 5mm !important;
                border-bottom: 1.5pt solid #111 !important;
                margin-bottom: 5mm;
            }
            .report-doc > header p:first-child {
                font-size: 8pt !important;
                letter-spacing: .16em !important;
                color: #555 !important;
            }
            .report-doc > header h1 {
                font-size: 20pt !important;
                line-height: 1.15 !important;
                margin: 1.5mm 0 2mm !important;
            }
            .report-doc > header a {
                border: 0 !important;
                background: #fff !important;
                padding: 0 3mm 0 0 !important;
                font-size: 9pt !important;
            }

            /* Resumen como tabla */
            .report-summary {
                display: table !important;
                width: 100% !important;
                border-collapse: collapse !important;
                border-top: 0.5pt solid #999 !important;
                border-bottom: 0.5pt solid #999 !important;
                margin-bottom: 6mm;
            }
            .report-summary > div {
                display: table-cell !important;
                width: 25%;
                padding: 3mm !important;
                border: 0.5pt solid #bbb !important;
                vertical-align: top;
            }
            .report-summary p { font-size: 8pt !important; letter-spacing: .06em; }
            .report-summary p + p { font-size: 15pt !important; font-weight: 700 !important; }

            /* CVE */
            .report-cve {
                border-left: 0 !important;
                padding-left: 0 !important;
                margin: 0 0 7mm !important;
                break-inside: auto !important;
                page-break-inside: auto !important;
            }
            .report-cve h2 { font-size: 15pt !important; }
            .report-badge {
                background: #fff !important;
                border: 0.8pt solid #333 !important;
                border-radius: 2pt !important;
                padding: 1mm 2mm !important;
                font-size: 8pt !important;
                font-weight: 700 !important;
            }

            /* Métricas */
            .report-cve dl {
                display: table !important;
                width: 100% !important;
                border-collapse: collapse !important;
                margin-top: 4mm !important;
                padding: 0 !important;
                border: 0 !important;
            }
            .report-cve dl > div {
                display: table-cell !important;
                width: 25%;
                padding: 2.5mm !important;
                border: 0.5pt solid #bbb !important;
                vertical-align: top;
            }
            .report-cve dl dt { font-size: 7.5pt !important; letter-spacing: .06em; color: #555 !important; }
            .report-cve dl dd { font-size: 13pt !important; font-weight: 700 !important; }
            .report-meter { display: none !important; }

            .report-cve p { font-size: 9.5pt !important; }
            .report-cve > p.font-mono { font-size: 8pt !important; color: #444 !important; margin-top: 2mm !important; }

            /* Acción CISA */
            .report-kev-action {
                background: #f7f7f7 !important;
                border: 0.5pt solid #999 !important;
                border-left: 2.5pt solid #111 !important;
                border-radius: 0 !important;
                padding: 3mm 4mm !important;
                margin-top: 4mm !important;
            }
            .report-kev-action p { font-size: 9pt !important; }

            /* Exposición de Defender */
            .report-exposure {
                background: #fff !important;
                border: 0.5pt solid #999 !important;
                border-radius: 0 !important;
                padding: 3mm 4mm !important;
                margin-top: 4mm !important;
            }
            .report-exposure p { font-size: 8.5pt !important; }
            .report-exposure table { width: 100% !important; border-collapse: collapse !important; }
            .report-exposure th,
            .report-exposure td {
                border: 0.5pt solid #ccc !important;
                padding: 1.2mm 2mm !important;
                font-size: 8pt !important;
            }
            .report-exposure th { background: #f2f2f2 !important; }

            /* Enlaces */
            .report-cve .grid { display: block !important; }
            .report-links-card {
                border: 0 !important;
                border-top: 0.5pt solid #999 !important;
                border-radius: 0 !important;
                padding: 3mm 0 0 !important;
                margin-top: 4mm !important;
            }
            .report-links-card ul { margin-top: 1.5mm !important; }
            .report-links-card li { margin: 1.5mm 0 !important; }
            .report-links-card a { font-size: 8.5pt !important; }

            /* Análisis de IA */
            .report-ai .grid { display: block !important; }
            .report-ai-block {
                border: 0 !important;
                border-top: 0.5pt solid #999 !important;
                border-radius: 0 !important;
                padding: 3mm 0 !important;
                margin: 0 !important;
                break-inside: avoid !important;
                page-break-inside: avoid !important;
            }
            .report-ai-block h3 { font-size: 10pt !important; }
            .report-ai-block h4 { font-size: 9.5pt !important; }
            .report-ai-block li { font-size: 9pt !important; }
            .report-ai-block p { font-size: 9pt !important; }
            .report-ai-block span.bg-gray-900 {
                background: #fff !important;
                color: #111 !important;
                border: 0.5pt solid #111 !important;
            }

            /* Saltos y pie */
            .report-cve + hr + .report-cve { break-before: page !important; page-break-before: always !important; }
            .report-cve + hr { display: none !important; }
            h1, h2, h3 { break-after: avoid !important; page-break-after: avoid !important; }
            tr { break-inside: avoid !important; page-break-inside: avoid !important; }
            details > p { display: block !important; }
            .report-doc > footer {
                border-top: 0.5pt solid #999 !important;
                padding: 3mm 0 0 !important;
                font-size: 7.5pt !important;
                color: #555 !important;
            }
        }
        .print-url { display: none; }
    </style>
</div>
