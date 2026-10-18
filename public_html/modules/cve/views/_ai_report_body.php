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
$isAdmin = !empty($isAdmin);

$bodyStatus = (string)($report['status'] ?? 'pending');
$bodyError = trim((string)($report['ai_error'] ?? ''));
$bodyProcessing = in_array($bodyStatus, ['pending', 'running'], true);
$bodyNoAi = !empty($report['no_ai']);

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
?>
<div class="ai-report-body" data-report-id="<?= (int)($report['id'] ?? 0) ?>" data-status="<?= e($bodyStatus) ?>" data-group-id="<?= (int)($report['group_id'] ?? 0) ?>">

    <?php if ($bodyProcessing): ?>
        <div class="mb-5 px-4 py-3 rounded-lg text-sm bg-blue-50 text-blue-700 flex items-start justify-between gap-3 flex-wrap no-print" id="ai-processing-banner">
            <div class="flex items-center gap-3 min-w-0">
                <svg class="w-4 h-4 animate-spin shrink-0" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"/></svg>
                <span id="ai-processing-text">La IA está redactando la evaluación de riesgo. Esta página se actualizará sola cuando termine.</span>
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
                    <span>· grupo: <?= e((string)$report['group_name']) ?></span>
                <?php endif; ?>
            </div>
        </header>

        <?php if ($items !== []): ?>
            <div class="grid grid-cols-2 sm:grid-cols-4 border-b border-gray-200 divide-x divide-gray-200">
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
                $descriptionEs = trim((string)($item['description_es'] ?? ''));
                $description = $descriptionEs !== '' ? $descriptionEs : trim((string)($item['description'] ?? ''));
                $descriptionLang = $descriptionEs !== '' ? 'es' : 'en';
                $github = is_array($item['github'] ?? null) ? $item['github'] : [];
                $references = is_array($item['references'] ?? null) ? $item['references'] : [];
                $isKev = !empty($item['kev']);
                $nvdUrl = (string)($item['nvd_url'] ?? '');
                if (!preg_match('#^https?://#i', $nvdUrl)) {
                    $nvdUrl = 'https://nvd.nist.gov/vuln/detail/' . rawurlencode($cveId);
                }
                ?>
                <section class="report-cve border-l-4 <?= $severity === 'Critical' ? 'border-red-500' : ($severity === 'High' ? 'border-orange-500' : ($severity === 'Medium' ? 'border-amber-500' : ($severity === 'Low' ? 'border-green-500' : 'border-gray-300'))) ?> pl-5" id="cve-<?= e($cveId) ?>">
                    <div class="flex items-start justify-between gap-3 flex-wrap">
                        <div class="min-w-0">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Vulnerabilidad</p>
                            <h2 class="text-xl font-bold mt-0.5 font-mono"><?= e($cveId) ?></h2>
                        </div>
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="px-2.5 py-1 rounded-md border text-[11px] font-semibold <?= $severityClasses[$severity] ?? $severityClasses['None'] ?>">
                                <?= e($severityLabels[$severity] ?? ($severity !== '' ? strtoupper($severity) : 'SIN DATOS')) ?>
                            </span>
                            <?php if ($priority !== ''): ?>
                                <span class="px-2.5 py-1 rounded-md text-[11px] font-semibold <?= $priorityClasses[$priority] ?? 'bg-gray-200 text-gray-700' ?>">
                                    Prioridad <?= e($priority) ?>
                                </span>
                            <?php endif; ?>
                            <a href="<?= e($nvdUrl) ?>" target="_blank" rel="noopener noreferrer"
                               class="px-2.5 py-1 rounded-md border border-gray-200 text-[11px] font-medium text-gray-600 hover:bg-gray-50">
                                NVD ↗
                            </a>
                        </div>
                    </div>

                    <dl class="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5 pb-5 border-b border-gray-100">
                        <div>
                            <dt class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">CVSS</dt>
                            <dd class="text-3xl font-bold mt-0.5 leading-none"><?= $cvss !== null ? e(number_format($cvss, 1, '.', '')) : '—' ?></dd>
                            <span class="block mt-1 h-1 rounded-full <?= $severityBar ?>" style="width: <?= $cvss !== null ? e(number_format(min(100, $cvss * 10), 0, '.', '')) : 0 ?>%"></span>
                        </div>
                        <div>
                            <dt class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">EPSS</dt>
                            <dd class="mt-1">
                                <span class="text-sm font-semibold"><?= $epss !== null ? e(number_format($epssPct, 2, ',', '')) . ' %' : '—' ?></span>
                                <span class="block mt-1 h-1.5 rounded-full bg-gray-100 overflow-hidden">
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
                        <div class="mt-4 px-4 py-3 rounded-lg bg-red-50 border border-red-100">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-red-500">Acción requerida (CISA)</p>
                            <?php if (!empty($item['kev_action'])): ?>
                                <p class="text-sm text-red-800 mt-1"><?= e((string)$item['kev_action']) ?></p>
                            <?php endif; ?>
                            <p class="text-[11px] text-red-700 mt-1">
                                <?php if (!empty($item['kev_due'])): ?>Vence el <?= e((string)$item['kev_due']) ?>. <?php endif; ?>
                                <?php if (strcasecmp((string)($item['kev_ransomware'] ?? ''), 'Known') === 0): ?>Ransomware conocido.<?php endif; ?>
                            </p>
                        </div>
                    <?php endif; ?>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
                        <div class="rounded-lg border border-gray-200 p-4">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">
                                Exploits públicos (<?= count($github) ?>)
                            </p>
                            <?php if ($github === []): ?>
                                <p class="text-sm text-gray-500 mt-2">Sin exploits conocidos en el catálogo local.</p>
                            <?php else: ?>
                                <ul class="mt-2 space-y-1.5">
                                    <?php foreach (array_slice($github, 0, 12) as $url): ?>
                                        <li>
                                            <a href="<?= e((string)$url) ?>" target="_blank" rel="noopener noreferrer"
                                               class="text-sm text-brand-600 hover:underline break-all">
                                                <?= e($linkLabel((string)$url)) ?> ↗
                                            </a>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                                <?php if (count($github) > 12): ?>
                                    <p class="text-[11px] text-gray-400 mt-1">… y <?= count($github) - 12 ?> más</p>
                                <?php endif; ?>
                            <?php endif; ?>
                            <a href="https://packetstormsecurity.com/search/?q=<?= e(rawurlencode($cveId)) ?>"
                               target="_blank" rel="noopener noreferrer"
                               class="inline-block mt-3 text-[11px] font-medium text-gray-500 hover:text-gray-800">
                                Buscar en PacketStorm ↗
                            </a>
                        </div>

                        <div class="rounded-lg border border-gray-200 p-4">
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
                                                <?= e($linkLabel((string)$url)) ?> ↗
                                            </a>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                                <?php if (count($references) > 12): ?>
                                    <p class="text-[11px] text-gray-400 mt-1">… y <?= count($references) - 12 ?> más</p>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>
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
            <p>Fuentes: NVD · CISA KEV · EPSS. Prioridad calculada con la fórmula de SploitScan (KEV, CVSS, EPSS y exploits públicos).</p>
            <p class="mt-1">La evaluación de riesgo es una estimación generada por IA; verifica siempre la información antes de tomar decisiones.</p>
        </footer>
    </article>

    <style>
        @media print {
            @page { margin: 14mm; }
            .report-doc {
                border: 0 !important;
                border-radius: 0 !important;
                box-shadow: none !important;
                background: #fff !important;
            }
            .report-doc a { color: #111 !important; text-decoration: none !important; }
            .report-cve { break-inside: avoid; page-break-inside: avoid; }
            .report-cve + hr + .report-cve { break-before: page; page-break-before: always; }
            .report-ai-block { break-inside: avoid; page-break-inside: avoid; }
            details > p { display: block !important; }
        }
    </style>
</div>
