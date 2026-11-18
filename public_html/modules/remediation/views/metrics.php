<?php
/**
 * Vista: métricas de remediación.
 * Variables compartidas: $org, $stats, $statusLabels, $severityLabels, $severityClasses.
 */

$mttr = $stats['mttr_days'];
$totalOpen = (int)$stats['open'];
$overdue = (int)$stats['overdue'];
$overduePct = $totalOpen > 0 ? round($overdue * 100 / $totalOpen) : 0;
$serviceMetrics = is_array($serviceMetrics ?? null) ? $serviceMetrics : [];
$servicePeriod = (string)($servicePeriod ?? date('Y-m'));
$svc = array_merge([
    'period' => $servicePeriod, 'created' => 0, 'closed' => 0, 'open' => 0,
    'mttr' => null, 'mttr_by_severity' => [], 'sla_total' => 0, 'sla_on_time' => 0,
    'sla_pct' => 0, 'delays' => ['retraso' => ['count' => 0, 'days' => 0], 'bloqueo' => ['count' => 0, 'days' => 0]],
    'delay_total_days' => 0, 'risks' => [], 'risks_expiring' => 0,
], $serviceMetrics);
$modUrl = base_url('modules/remediation');
?>
<div class="card p-4 mb-5">
    <div class="flex items-end justify-between gap-3 flex-wrap">
        <div>
            <h2 class="text-sm font-semibold m-0">Informe de servicio</h2>
            <p class="text-[11px] text-ink-muted mt-1 mb-0">
                Calculado del periodo, sin capturas manuales. La foto del mes se puede publicar en la pestaña Informes.
            </p>
        </div>
        <form method="GET" action="<?= e($modUrl) ?>" class="flex items-end gap-2">
            <input type="hidden" name="tab" value="metrics">
            <input type="hidden" name="org" value="<?= (int)$selectedOrgId ?>">
            <label class="block">
                <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Periodo</span>
                <input type="month" name="period" value="<?= e((string)$svc['period']) ?>"
                       class="px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
            </label>
            <button type="submit" class="px-3 py-1.5 bg-gray-900 hover:bg-black text-white text-xs font-medium rounded-lg">Ver</button>
        </form>
    </div>

    <div class="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3 mt-4 text-xs">
        <div><p class="text-ink-soft m-0">Creadas</p><p class="text-xl font-bold m-0 mt-0.5"><?= (int)$svc['created'] ?></p></div>
        <div><p class="text-ink-soft m-0">Cerradas</p><p class="text-xl font-bold m-0 mt-0.5"><?= (int)$svc['closed'] ?></p></div>
        <div><p class="text-ink-soft m-0">Abiertas al cierre</p><p class="text-xl font-bold m-0 mt-0.5"><?= (int)$svc['open'] ?></p></div>
        <div>
            <p class="text-ink-soft m-0">Cumplimiento SLA</p>
            <p class="text-xl font-bold m-0 mt-0.5 <?= (int)$svc['sla_pct'] < 80 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400' ?>">
                <?= (int)$svc['sla_pct'] ?> %
            </p>
            <p class="text-[10px] text-ink-soft m-0"><?= (int)$svc['sla_on_time'] ?>/<?= (int)$svc['sla_total'] ?> en plazo</p>
        </div>
        <div>
            <p class="text-ink-soft m-0">MTTR</p>
            <p class="text-xl font-bold m-0 mt-0.5"><?= $svc['mttr'] !== null ? e(number_format((float)$svc['mttr'], 1, ',', '')) : '—' ?></p>
            <p class="text-[10px] text-ink-soft m-0">días</p>
        </div>
        <div>
            <p class="text-ink-soft m-0">Retrasos + bloqueos</p>
            <p class="text-xl font-bold m-0 mt-0.5 <?= (int)$svc['delay_total_days'] > 0 ? 'text-amber-600 dark:text-amber-400' : '' ?>">
                <?= (int)$svc['delay_total_days'] ?> d
            </p>
            <p class="text-[10px] text-ink-soft m-0">
                <?= (int)($svc['delays']['retraso']['count'] ?? 0) ?> + <?= (int)($svc['delays']['bloqueo']['count'] ?? 0) ?> entradas
            </p>
        </div>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
    <div class="card overflow-hidden">
        <div class="px-4 py-3 border-b border-line">
            <h2 class="text-sm font-semibold m-0">MTTR por severidad</h2>
            <p class="text-[11px] text-ink-muted m-0 mt-0.5">Cerradas en <?= e((string)$svc['period']) ?></p>
        </div>
        <?php if (($svc['mttr_by_severity'] ?? []) === []): ?>
            <p class="px-4 py-6 text-xs text-ink-muted text-center m-0">Sin cierres en el periodo.</p>
        <?php else: ?>
            <table class="data-table w-full text-xs">
                <thead>
                    <tr class="text-[10px] uppercase text-ink-soft border-b border-line">
                        <th class="text-left px-4 py-2">Severidad</th>
                        <th class="text-right px-4 py-2">Cerradas</th>
                        <th class="text-right px-4 py-2">Días</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-line-subtle">
                    <?php foreach ($svc['mttr_by_severity'] as $row): ?>
                        <tr>
                            <td class="px-4 py-2"><?= e((string)$row['severity']) ?></td>
                            <td class="px-4 py-2 text-right"><?= (int)$row['count'] ?></td>
                            <td class="px-4 py-2 text-right font-mono">
                                <?= $row['days'] !== null ? e(number_format((float)$row['days'], 1, ',', '')) : '—' ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <div class="card overflow-hidden">
        <div class="px-4 py-3 border-b border-line flex items-center justify-between">
            <div>
                <h2 class="text-sm font-semibold m-0">Riesgos aceptados vigentes</h2>
                <p class="text-[11px] text-ink-muted m-0 mt-0.5">
                    <?= (int)($svc['risks_expiring'] ?? 0) ?> caducan en ≤7 días
                </p>
            </div>
        </div>
        <?php if (($svc['risks'] ?? []) === []): ?>
            <p class="px-4 py-6 text-xs text-ink-muted text-center m-0">Sin aceptaciones vigentes.</p>
        <?php else: ?>
            <div class="max-h-64 overflow-y-auto">
                <table class="data-table w-full text-xs">
                    <thead>
                        <tr class="text-[10px] uppercase text-ink-soft border-b border-line">
                            <th class="text-left px-4 py-2">CVE</th>
                            <th class="text-left px-4 py-2">Caducidad</th>
                            <th class="text-right px-4 py-2">Días</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-line-subtle">
                        <?php foreach ($svc['risks'] as $risk): ?>
                            <tr>
                                <td class="px-4 py-2 font-mono"><?= e((string)$risk['cve_id']) ?></td>
                                <td class="px-4 py-2"><?= e((string)$risk['caducidad']) ?></td>
                                <td class="px-4 py-2 text-right <?= (int)$risk['days_left'] <= 7 ? 'text-amber-600 dark:text-amber-400 font-semibold' : '' ?>">
                                    <?= (int)$risk['days_left'] ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>
<div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-5">
    <div class="card p-4">
        <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft">Abiertas</p>
        <p class="text-3xl font-bold mt-1"><?= $totalOpen ?></p>
        <p class="text-[11px] text-ink-muted mt-1">Abiertas + en curso en <?= e((string)$org['name']) ?></p>
    </div>
    <div class="card p-4">
        <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft">Vencidas</p>
        <p class="text-3xl font-bold mt-1 <?= $overdue > 0 ? 'text-red-500' : '' ?>"><?= $overdue ?></p>
        <p class="text-[11px] text-ink-muted mt-1"><?= $overduePct ?> % de las abiertas</p>
    </div>
    <div class="card p-4">
        <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft">KEV abiertas</p>
        <p class="text-3xl font-bold mt-1 <?= (int)$stats['kev_open'] > 0 ? 'text-orange-500' : '' ?>"><?= (int)$stats['kev_open'] ?></p>
        <p class="text-[11px] text-ink-muted mt-1">Explotadas conocidas (CISA)</p>
    </div>
    <div class="card p-4">
        <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft">MTTR</p>
        <p class="text-3xl font-bold mt-1"><?= $mttr !== null ? e(number_format($mttr, 1, ',', '')) : '—' ?></p>
        <p class="text-[11px] text-ink-muted mt-1"><?= $mttr !== null ? 'días de media hasta resolver' : 'sin tareas resueltas' ?></p>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
    <div class="card overflow-hidden">
        <div class="px-4 py-3 border-b border-line">
            <h2 class="text-sm font-semibold">Tareas por estado</h2>
            <p class="text-[11px] text-ink-muted mt-0.5">Total histórico: <?= (int)$stats['total'] ?></p>
        </div>
        <table class="data-table w-full text-xs">
            <thead>
                <tr class="text-[10px] uppercase text-ink-soft border-b border-line">
                    <th class="text-left px-4 py-2">Estado</th>
                    <th class="text-right px-4 py-2">Tareas</th>
                    <th class="text-right px-4 py-2">%</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-line-subtle">
                <?php foreach ($statusLabels as $key => $label): ?>
                    <?php $count = (int)($stats['counts'][$key] ?? 0); ?>
                    <tr>
                        <td class="px-4 py-2">
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $statusClasses[$key] ?? 'bg-gray-100 text-gray-600' ?>">
                                <?= e($label) ?>
                            </span>
                        </td>
                        <td class="px-4 py-2 text-right font-medium"><?= $count ?></td>
                        <td class="px-4 py-2 text-right text-ink-muted">
                            <?= (int)$stats['total'] > 0 ? round($count * 100 / (int)$stats['total']) : 0 ?> %
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <div class="card overflow-hidden">
        <div class="px-4 py-3 border-b border-line">
            <h2 class="text-sm font-semibold">Abiertas por severidad</h2>
            <p class="text-[11px] text-ink-muted mt-0.5">Solo tareas abiertas o en curso</p>
        </div>
        <?php if (($stats['by_severity'] ?? []) === []): ?>
            <p class="px-4 py-6 text-xs text-ink-muted text-center">Sin tareas abiertas.</p>
        <?php else: ?>
            <table class="data-table w-full text-xs">
                <thead>
                    <tr class="text-[10px] uppercase text-ink-soft border-b border-line">
                        <th class="text-left px-4 py-2">Severidad</th>
                        <th class="text-right px-4 py-2">Tareas</th>
                        <th class="text-right px-4 py-2">%</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-line-subtle">
                    <?php foreach ($stats['by_severity'] as $row): ?>
                        <?php $severity = (string)($row['severity'] ?? ''); ?>
                        <tr>
                            <td class="px-4 py-2">
                                <?php if ($severity !== ''): ?>
                                    <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $severityClasses[$severity] ?? 'bg-gray-100 text-gray-600' ?>">
                                        <?= e($severityLabels[$severity] ?? $severity) ?>
                                    </span>
                                <?php else: ?>
                                    <span class="text-ink-soft">Sin severidad</span>
                                <?php endif; ?>
                            </td>
                            <td class="px-4 py-2 text-right font-medium"><?= (int)$row['c'] ?></td>
                            <td class="px-4 py-2 text-right text-ink-muted">
                                <?= $totalOpen > 0 ? round((int)$row['c'] * 100 / $totalOpen) : 0 ?> %
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
