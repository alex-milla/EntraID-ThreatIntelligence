<?php
/**
 * Vista: métricas de remediación.
 * Variables compartidas: $org, $stats, $statusLabels, $severityLabels, $severityClasses.
 */

$mttr = $stats['mttr_days'];
$totalOpen = (int)$stats['open'];
$overdue = (int)$stats['overdue'];
$overduePct = $totalOpen > 0 ? round($overdue * 100 / $totalOpen) : 0;
?>
<div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-5">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
        <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Abiertas</p>
        <p class="text-3xl font-bold mt-1"><?= $totalOpen ?></p>
        <p class="text-[11px] text-gray-500 mt-1">Abiertas + en curso en <?= e((string)$org['name']) ?></p>
    </div>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
        <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Vencidas</p>
        <p class="text-3xl font-bold mt-1 <?= $overdue > 0 ? 'text-red-500' : '' ?>"><?= $overdue ?></p>
        <p class="text-[11px] text-gray-500 mt-1"><?= $overduePct ?> % de las abiertas</p>
    </div>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
        <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">KEV abiertas</p>
        <p class="text-3xl font-bold mt-1 <?= (int)$stats['kev_open'] > 0 ? 'text-orange-500' : '' ?>"><?= (int)$stats['kev_open'] ?></p>
        <p class="text-[11px] text-gray-500 mt-1">Explotadas conocidas (CISA)</p>
    </div>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
        <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">MTTR</p>
        <p class="text-3xl font-bold mt-1"><?= $mttr !== null ? e(number_format($mttr, 1, ',', '')) : '—' ?></p>
        <p class="text-[11px] text-gray-500 mt-1"><?= $mttr !== null ? 'días de media hasta resolver' : 'sin tareas resueltas' ?></p>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-sm font-semibold">Tareas por estado</h2>
            <p class="text-[11px] text-gray-500 mt-0.5">Total histórico: <?= (int)$stats['total'] ?></p>
        </div>
        <table class="w-full text-xs">
            <thead>
                <tr class="text-[10px] uppercase text-gray-400 border-b border-gray-200 dark:border-gray-700">
                    <th class="text-left px-4 py-2">Estado</th>
                    <th class="text-right px-4 py-2">Tareas</th>
                    <th class="text-right px-4 py-2">%</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
                <?php foreach ($statusLabels as $key => $label): ?>
                    <?php $count = (int)($stats['counts'][$key] ?? 0); ?>
                    <tr>
                        <td class="px-4 py-2">
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $statusClasses[$key] ?? 'bg-gray-100 text-gray-600' ?>">
                                <?= e($label) ?>
                            </span>
                        </td>
                        <td class="px-4 py-2 text-right font-medium"><?= $count ?></td>
                        <td class="px-4 py-2 text-right text-gray-500">
                            <?= (int)$stats['total'] > 0 ? round($count * 100 / (int)$stats['total']) : 0 ?> %
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-sm font-semibold">Abiertas por severidad</h2>
            <p class="text-[11px] text-gray-500 mt-0.5">Solo tareas abiertas o en curso</p>
        </div>
        <?php if (($stats['by_severity'] ?? []) === []): ?>
            <p class="px-4 py-6 text-xs text-gray-500 text-center">Sin tareas abiertas.</p>
        <?php else: ?>
            <table class="w-full text-xs">
                <thead>
                    <tr class="text-[10px] uppercase text-gray-400 border-b border-gray-200 dark:border-gray-700">
                        <th class="text-left px-4 py-2">Severidad</th>
                        <th class="text-right px-4 py-2">Tareas</th>
                        <th class="text-right px-4 py-2">%</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
                    <?php foreach ($stats['by_severity'] as $row): ?>
                        <?php $severity = (string)($row['severity'] ?? ''); ?>
                        <tr>
                            <td class="px-4 py-2">
                                <?php if ($severity !== ''): ?>
                                    <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $severityClasses[$severity] ?? 'bg-gray-100 text-gray-600' ?>">
                                        <?= e($severityLabels[$severity] ?? $severity) ?>
                                    </span>
                                <?php else: ?>
                                    <span class="text-gray-400">Sin severidad</span>
                                <?php endif; ?>
                            </td>
                            <td class="px-4 py-2 text-right font-medium"><?= (int)$row['c'] ?></td>
                            <td class="px-4 py-2 text-right text-gray-500">
                                <?= $totalOpen > 0 ? round((int)$row['c'] * 100 / $totalOpen) : 0 ?> %
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
