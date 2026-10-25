<?php
/**
 * Parcial: análisis de prioridad de parcheo por empresa/grupo.
 * Variables: $groupAnalysis, $selectedGroup, $selectedGroupName, $selectedGroupIsCompany, $assignedCves, $isAdmin.
 */

$assignedCves = is_array($assignedCves ?? null) ? $assignedCves : [];
if ($assignedCves === []) {
    return;
}

$groupAnalysis = is_array($groupAnalysis ?? null) ? $groupAnalysis : null;
$currentCveIds = [];
foreach ($assignedCves as $assignedCve) {
    $cveId = strtoupper((string)($assignedCve['cve_id'] ?? ''));
    if ($cveId !== '') {
        $currentCveIds[$cveId] = true;
    }
}
$currentCveIds = array_keys($currentCveIds);
sort($currentCveIds);

$analysisCveIds = is_array($groupAnalysis['cve_ids_array'] ?? null)
    ? array_values(array_map('strval', $groupAnalysis['cve_ids_array']))
    : [];
sort($analysisCveIds);
$analysisStale = $groupAnalysis !== null && $analysisCveIds !== $currentCveIds;
$analysisText = $groupAnalysis !== null ? (string)($groupAnalysis['content_text'] ?? '') : '';
// El texto es la fuente de verdad: se normaliza y renderiza en cada carga.
// Así se reparan análisis antiguos guardados como bloque de código.
$analysisHtml = '';
if ($analysisText !== '') {
    $analysisHtml = function_exists('render_ai_markdown')
        ? render_ai_markdown($analysisText)
        : render_markdown($analysisText);
} elseif ($groupAnalysis !== null) {
    $analysisHtml = (string)($groupAnalysis['content_html'] ?? '');
}
$analysisCount = $groupAnalysis !== null ? (int)($groupAnalysis['cve_count'] ?? 0) : 0;
$analysisModel = $groupAnalysis !== null ? (string)($groupAnalysis['model'] ?? '') : '';
$analysisDate = $groupAnalysis !== null ? (string)($groupAnalysis['generated_at'] ?? '') : '';
$currentCount = count($currentCveIds);
$analysisShort = $groupAnalysis !== null && $analysisCount > 0 && $analysisCount < $currentCount;
$missingCves = [];
if ($groupAnalysis !== null && $analysisText !== '' && !$analysisShort) {
    foreach ($currentCveIds as $cveId) {
        if (preg_match('/\b' . preg_quote($cveId, '/') . '\b/i', $analysisText) !== 1) {
            $missingCves[] = $cveId;
        }
    }
}
$groupKindLabel = $selectedGroupIsCompany ? 'empresa' : 'grupo de aplicaciones';
?>

<style>
    .cve-priority-content h1,
    .cve-priority-content h2,
    .cve-priority-content h3 {
        font-weight: 600;
        margin: 1rem 0 .35rem;
        color: inherit;
    }
    .cve-priority-content h1 { font-size: 1rem; }
    .cve-priority-content h2 { font-size: .875rem; }
    .cve-priority-content h3 { font-size: .8125rem; }
    .cve-priority-content p { margin: .4rem 0; }
    .cve-priority-content ul,
    .cve-priority-content ol { margin: .4rem 0 .6rem 1.1rem; }
    .cve-priority-content ul { list-style: disc; }
    .cve-priority-content ol { list-style: decimal; }
    .cve-priority-content li { margin: .15rem 0; }
    .cve-priority-content table { width: 100%; border-collapse: collapse; margin: .6rem 0; font-size: .75rem; }
    .cve-priority-content th,
    .cve-priority-content td { border: 1px solid rgba(148, 163, 184, .35); padding: .35rem .5rem; text-align: left; vertical-align: top; }
    .cve-priority-content th { background: rgba(148, 163, 184, .12); font-weight: 600; }
    .cve-priority-content code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .75rem; }

    @page { margin: 12mm; }

    @media print {
        body { background: #fff !important; }
        body * { visibility: hidden !important; }
        #cve-priority-print,
        #cve-priority-print * { visibility: visible !important; }
        #cve-priority-print {
            position: absolute;
            left: 0;
            top: 0;
            width: 100%;
            margin: 0 !important;
            border: 0 !important;
            border-radius: 0 !important;
            box-shadow: none !important;
            background: #fff !important;
            color: #000 !important;
        }
        #cve-priority-print .no-print { display: none !important; }
        #cve-priority-print #cve-priority-body { display: block !important; }
        #cve-priority-print .cve-priority-content {
            color: #000 !important;
            font-size: 10pt;
            line-height: 1.45;
        }
        #cve-priority-print .cve-priority-content h1,
        #cve-priority-print .cve-priority-content h2,
        #cve-priority-print .cve-priority-content h3 {
            color: #000 !important;
            break-after: avoid;
            page-break-after: avoid;
        }
        #cve-priority-print .cve-priority-content table { font-size: 9pt; }
        #cve-priority-print .cve-priority-content th,
        #cve-priority-print .cve-priority-content td {
            border: 1px solid #555 !important;
            color: #000 !important;
        }
        #cve-priority-print .cve-priority-content th { background: #eee !important; }
        #cve-priority-print .cve-priority-content tr {
            break-inside: avoid;
            page-break-inside: avoid;
        }
        #cve-priority-print .cve-priority-content thead { display: table-header-group; }
        #cve-priority-print .cve-priority-content a { color: #000 !important; text-decoration: underline; }
    }
</style>

<div id="cve-priority-print" class="cve-priority-card card overflow-hidden mt-4">
    <div class="px-5 py-4 border-b border-line flex items-start justify-between gap-3 flex-wrap">
        <div class="flex items-start gap-2">
            <button type="button" id="cve-priority-toggle"
                    onclick="cveToggleCard('cve-priority-body', this)"
                    aria-expanded="false" aria-controls="cve-priority-body"
                    title="Mostrar u ocultar el informe de prioridad"
                    class="no-print mt-0.5 inline-flex items-center justify-center w-7 h-7 rounded-lg border border-line text-ink-muted hover:text-brand-600 hover:bg-muted transition-colors">
                <i class="material-icons icon-16 transition-transform" aria-hidden="true">chevron_right</i>
            </button>
            <div>
                <div class="flex items-center gap-2 flex-wrap">
                    <h2 class="text-sm font-semibold">Prioridad de parcheo (IA)</h2>
                    <?php if ($groupAnalysis !== null && ($analysisShort || $analysisStale)): ?>
                        <span class="dark:bg-amber-900/30 dark:text-amber-300 status-pending">Desactualizado</span>
                    <?php endif; ?>
                    <?php if ($missingCves !== []): ?>
                        <span class="dark:bg-red-900/30 dark:text-red-300 status-failed">Cobertura incompleta</span>
                    <?php endif; ?>
                </div>
                <?php if ($groupAnalysis !== null): ?>
                    <p class="text-xs text-ink-muted mt-1">
                        <?= e($analysisDate !== '' ? format_db_date($analysisDate, 'd/m/Y H:i') : '—') ?>
                        · <?= (int)$analysisCount ?> <?= $analysisCount === 1 ? 'CVE' : 'CVEs' ?><?php if ($analysisShort): ?> de <?= (int)$currentCount ?><?php endif; ?>
                        <?php if ($analysisModel !== ''): ?> · <?= e($analysisModel) ?><?php endif; ?>
                    </p>
                <?php else: ?>
                    <p class="text-xs text-ink-muted mt-1">
                        Análisis del <?= e($groupKindLabel) ?> «<?= e($selectedGroupName) ?>» usando solo sus CVEs asignados.
                    </p>
                <?php endif; ?>
            </div>
        </div>
        <div class="flex items-center gap-2 no-print">
            <?php if ($groupAnalysis !== null): ?>
                <button type="button" onclick="window.print()"
                        class="px-3 py-1.5 border border-line-strong text-ink hover:bg-muted text-xs font-medium rounded-lg transition-colors">
                    Imprimir
                </button>
            <?php endif; ?>
            <?php if ($isAdmin): ?>
                <button type="button" onclick="cvePriorityOpen(<?= (int)$selectedGroup ?>)"
                        class="<?= $groupAnalysis !== null ? 'px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-muted-dark' : 'px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white' ?> text-xs font-medium rounded-lg transition-colors">
                    <?= $groupAnalysis !== null ? 'Recalcular' : 'Generar análisis' ?>
                </button>
            <?php endif; ?>
        </div>
    </div>

    <div id="cve-priority-body" class="hidden">
    <?php if ($analysisShort): ?>
        <div class="px-5 py-2 bg-warning-bg border-b border-warning-border text-[11px] text-warning">
            Este análisis cubre <?= (int)$analysisCount ?> de <?= (int)$currentCount ?> CVEs. Recalcula para analizarlos todos.
        </div>
    <?php elseif ($analysisStale): ?>
        <div class="px-5 py-2 bg-warning-bg border-b border-warning-border text-[11px] text-warning">
            El listado de CVEs asignados ha cambiado desde este análisis. Recalcula para actualizarlo.
        </div>
    <?php endif; ?>
    <?php if ($missingCves !== []): ?>
        <div class="px-5 py-2 bg-danger-bg border-b border-danger-border text-[11px] text-danger">
            La IA no mencionó <?= count($missingCves) ?> de los <?= (int)$currentCount ?> CVEs:
            <?= e(implode(', ', array_slice($missingCves, 0, 8))) ?><?= count($missingCves) > 8 ? '…' : '' ?>.
            Recalcula o revisa el informe.
        </div>
    <?php endif; ?>

    <?php if ($groupAnalysis === null): ?>
        <div class="px-5 py-8 text-center">
            <p class="text-sm text-ink-muted">Todavía no hay un análisis de prioridad para este <?= e($groupKindLabel) ?>.</p>
            <p class="text-xs text-ink-soft mt-1">Se usarán únicamente los CVEs asignados a «<?= e($selectedGroupName) ?>».</p>
        </div>
    <?php elseif ($analysisHtml !== ''): ?>
        <div class="cve-priority-content px-5 py-4 text-sm leading-relaxed text-ink-muted">
            <?= $analysisHtml ?>
        </div>
    <?php elseif ($analysisText !== ''): ?>
        <pre class="px-5 py-4 text-xs whitespace-pre-wrap text-ink-muted"><?= e($analysisText) ?></pre>
    <?php else: ?>
        <div class="px-5 py-6 text-sm text-ink-muted">El análisis está vacío.</div>
    <?php endif; ?>
    </div><!-- /#cve-priority-body -->
</div>
