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
$analysisHtml = $groupAnalysis !== null ? (string)($groupAnalysis['content_html'] ?? '') : '';
$analysisText = $groupAnalysis !== null ? (string)($groupAnalysis['content_text'] ?? '') : '';
$analysisCount = $groupAnalysis !== null ? (int)($groupAnalysis['cve_count'] ?? 0) : 0;
$analysisModel = $groupAnalysis !== null ? (string)($groupAnalysis['model'] ?? '') : '';
$analysisDate = $groupAnalysis !== null ? (string)($groupAnalysis['generated_at'] ?? '') : '';
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
</style>

<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden mt-4">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-start justify-between gap-3 flex-wrap">
        <div>
            <h2 class="text-sm font-semibold">Prioridad de parcheo (IA)</h2>
            <?php if ($groupAnalysis !== null): ?>
                <p class="text-xs text-gray-500 mt-1">
                    <?= e($analysisDate !== '' ? format_db_date($analysisDate, 'd/m/Y H:i') : '—') ?>
                    · <?= (int)$analysisCount ?> <?= $analysisCount === 1 ? 'CVE' : 'CVEs' ?>
                    <?php if ($analysisModel !== ''): ?> · <?= e($analysisModel) ?><?php endif; ?>
                </p>
            <?php else: ?>
                <p class="text-xs text-gray-500 mt-1">
                    Análisis del <?= e($groupKindLabel) ?> «<?= e($selectedGroupName) ?>» usando solo sus CVEs asignados.
                </p>
            <?php endif; ?>
        </div>
        <?php if ($isAdmin): ?>
            <button type="button" onclick="cvePriorityOpen(<?= (int)$selectedGroup ?>)"
                    class="<?= $groupAnalysis !== null ? 'px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-muted-dark' : 'px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white' ?> text-xs font-medium rounded-lg transition-colors">
                <?= $groupAnalysis !== null ? 'Recalcular' : 'Generar análisis' ?>
            </button>
        <?php endif; ?>
    </div>

    <?php if ($analysisStale): ?>
        <div class="px-5 py-2 bg-amber-50 dark:bg-amber-900/20 border-b border-amber-200 dark:border-amber-800 text-[11px] text-amber-700 dark:text-amber-300">
            El listado de CVEs asignados ha cambiado desde este análisis. Recalcula para actualizarlo.
        </div>
    <?php endif; ?>

    <?php if ($groupAnalysis === null): ?>
        <div class="px-5 py-8 text-center">
            <p class="text-sm text-gray-500">Todavía no hay un análisis de prioridad para este <?= e($groupKindLabel) ?>.</p>
            <p class="text-xs text-gray-400 mt-1">Se usarán únicamente los CVEs asignados a «<?= e($selectedGroupName) ?>».</p>
        </div>
    <?php elseif ($analysisHtml !== ''): ?>
        <div class="cve-priority-content px-5 py-4 text-sm leading-relaxed text-gray-600 dark:text-gray-300">
            <?= $analysisHtml ?>
        </div>
    <?php elseif ($analysisText !== ''): ?>
        <pre class="px-5 py-4 text-xs whitespace-pre-wrap text-gray-600 dark:text-gray-300"><?= e($analysisText) ?></pre>
    <?php else: ?>
        <div class="px-5 py-6 text-sm text-gray-500">El análisis está vacío.</div>
    <?php endif; ?>
</div>
