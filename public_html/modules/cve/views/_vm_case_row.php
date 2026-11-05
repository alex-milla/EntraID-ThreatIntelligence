<?php
/**
 * Parcial: fila de un caso en la cola de seguimiento (v0.3.23).
 *
 * Variables heredadas de vm.php: $caseRow, $today, $caseUrl, $isAdmin,
 * $vmPlanKeys, $vmLatestImportCves, $priorityClasses, $statusClasses,
 * $deadlineLabels, $deadlineClasses, $statusLabels, $sourceLabels, $fmtDate.
 */

$rowId = (int)$caseRow['id'];
$rowStatus = (string)$caseRow['status'];
$rowPriority = (string)($caseRow['priority'] ?? '');
$rowDeadline = VmCases::deadlineState(
    (string)($caseRow['due_date'] ?? ''),
    $rowStatus,
    (string)($caseRow['accepted_until'] ?? ''),
    $today
);
$rowSource = (string)($caseRow['source'] ?? 'defender-tvm');
$panelUrl = base_url('modules/cve/vm/' . $rowId . '/panel');

$productSource = (string)($caseRow['related_software'] ?? '');
if (trim($productSource) === '') {
    $productSource = (string)($caseRow['catalog_products'] ?? '');
}
if (trim($productSource) === '') {
    $productSource = (string)($caseRow['finding_products'] ?? '');
}
$productLabels = [];
foreach (preg_split('/[;,]+/', $productSource) ?: [] as $pair) {
    $pair = trim($pair);
    if ($pair !== '' && !in_array($pair, $productLabels, true)) {
        $productLabels[] = $pair;
    }
}

$isAbsent = !empty($vmLatestImportCves)
    && !isset($vmLatestImportCves[strtoupper((string)$caseRow['cve_id'])])
    && !VmCases::isClosed($rowStatus);
?>
<tr class="hover:bg-muted/50">
    <td class="px-3 py-2 align-top">
        <?php if (!empty($isAdmin)): ?>
            <input type="checkbox" name="case_ids[]" value="<?= $rowId ?>"
                   form="vm-bulk-form" data-vm-case-check
                   class="accent-brand-500" aria-label="Seleccionar <?= e((string)$caseRow['cve_id']) ?>">
        <?php endif; ?>
    </td>
    <td class="px-3 py-2">
        <a href="<?= base_url('modules/cve/detail/' . urlencode((string)$caseRow['cve_id']) . '/panel') ?>"
           data-vm-panel data-vm-title="<?= e((string)$caseRow['cve_id']) ?>"
           class="font-mono font-medium text-brand-600 dark:text-brand-300 hover:underline">
            <?= e((string)$caseRow['cve_id']) ?>
        </a>
        <?php if (!empty($caseRow['kev_id'])): ?>
            <span class="ml-1 inline-flex px-1 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 text-[9px] font-semibold">KEV</span>
        <?php endif; ?>
        <span class="ml-1 inline-flex px-1 py-0.5 rounded text-[9px] <?= $rowSource === 'catalog' ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' : 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' ?>"
              title="<?= e($sourceLabels[$rowSource] ?? $rowSource) ?>">
            <?= $rowSource === 'catalog' ? 'Mis CVE' : 'TVM' ?>
        </span>
        <?php if (isset($vmPlanKeys[(int)$caseRow['group_id'] . '|' . strtoupper((string)$caseRow['cve_id'])])): ?>
            <span class="ml-1 inline-flex px-1 py-0.5 rounded text-[9px] bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300"
                  data-vm-plan-badge title="Tiene plan de remediación guardado">Plan</span>
        <?php endif; ?>
        <?php if ($isAbsent): ?>
            <span class="ml-1 inline-flex px-1 py-0.5 rounded text-[9px] bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300"
                  title="No aparece en la última importación de Defender; no se cierra automáticamente">Ausente</span>
        <?php endif; ?>
    </td>
    <td class="px-3 py-2 max-w-[220px]">
        <?php if ($productLabels === []): ?>
            <span class="text-ink-soft">—</span>
        <?php else: ?>
            <div class="flex flex-wrap gap-1" title="<?= e(implode(' · ', $productLabels)) ?>">
                <?php foreach (array_slice($productLabels, 0, 2) as $label): ?>
                    <span class="inline-flex px-1.5 py-0.5 rounded bg-muted text-[10px] text-ink-muted font-mono"><?= e($label) ?></span>
                <?php endforeach; ?>
                <?php if (count($productLabels) > 2): ?>
                    <span class="inline-flex px-1.5 py-0.5 rounded bg-muted text-[10px] text-ink-soft">+<?= count($productLabels) - 2 ?></span>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </td>
    <td class="px-3 py-2 max-w-[150px] truncate" title="<?= e((string)($caseRow['company_name'] ?? '')) ?>">
        <?= e((string)($caseRow['company_name'] ?? '—')) ?>
    </td>
    <td class="px-3 py-2">
        <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $priorityClasses[$rowPriority] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300' ?>">
            <?= e(VmCases::priorityLabel($rowPriority)) ?>
        </span>
    </td>
    <td class="px-3 py-2">
        <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium <?= $statusClasses[$rowStatus] ?? '' ?>">
            <?= e($statusLabels[$rowStatus] ?? $rowStatus) ?>
        </span>
    </td>
    <td class="px-3 py-2 whitespace-nowrap">
        <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium <?= $deadlineClasses[$rowDeadline] ?? '' ?>">
            <?= e($deadlineLabels[$rowDeadline] ?? $rowDeadline) ?>
        </span>
        <span class="block text-[10px] text-ink-soft"><?= e($fmtDate((string)($caseRow['due_date'] ?? ''))) ?></span>
    </td>
    <td class="px-3 py-2"><?= e((string)($caseRow['assignee_name'] ?? '—')) ?></td>
    <td class="px-3 py-2 whitespace-nowrap"><?= e($fmtDate((string)($caseRow['last_seen_at'] ?? ''))) ?></td>
    <td class="px-3 py-2 text-right">
        <a href="<?= e($caseUrl($rowId)) ?>"
           data-vm-panel data-vm-title="Caso <?= e((string)$caseRow['cve_id']) ?>"
           data-vm-url="<?= e($panelUrl) ?>"
           class="text-brand-600 dark:text-brand-300 hover:underline">Ver</a>
    </td>
</tr>
