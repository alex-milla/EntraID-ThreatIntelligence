<?php
/**
 * Vista: cola de CVEs del tenant (CVE Desk, F1).
 *
 * Variables: $org, $selectedOrgId, $queueRows, $queueCounts, $queueFilters,
 *            $severityLabels, $severityClasses, $modUrl.
 */

$queueRows = is_array($queueRows ?? null) ? $queueRows : [];
$queueCounts = is_array($queueCounts ?? null) ? $queueCounts : ['tenant' => false, 'nuevo' => 0, 'en_informe' => 0, 'total' => 0];
$queueFilters = is_array($queueFilters ?? null) ? $queueFilters : [];
$isTenant = !empty($queueCounts['tenant']);
$state = (string)($queueFilters['state'] ?? '');
$slaText = RemediationSla::textClasses();
$slaBar = RemediationSla::barClasses();
?>

<?php if (!$isTenant): ?>
    <div class="card p-6">
        <h2 class="text-sm font-semibold m-0">La cola necesita un tenant</h2>
        <p class="text-xs text-ink-muted mt-1 max-w-2xl">
            La cola se calcula desde las vulnerabilidades sincronizadas de Defender
            (<code>vulnerabilities</code> + <code>machines</code>), no desde el CSV.
            Vincula esta organización a un tenant con <strong>Editar</strong> (arriba) o usa
            una organización de tipo tenant.
        </p>
    </div>
<?php else: ?>
    <div class="card overflow-hidden">
        <div class="px-4 py-3 border-b border-line flex items-start justify-between gap-3 flex-wrap">
            <div>
                <h2 class="text-sm font-semibold m-0">Cola del tenant</h2>
                <p class="text-[11px] text-ink-muted mt-0.5">
                    <?= (int)$queueCounts['nuevo'] ?> nuevos ·
                    <?= (int)$queueCounts['en_informe'] ?> en informe ·
                    <?= (int)$queueCounts['total'] ?> sin ticket
                </p>
            </div>
            <div class="flex items-center gap-1 text-[11px]">
                <?php
                $pills = [
                    ''           => 'Todos',
                    'nuevo'      => 'Nuevos',
                    'en_informe' => 'En informe',
                ];
                foreach ($pills as $value => $label):
                    $href = $modUrl . '?tab=queue&org=' . $selectedOrgId . ($value !== '' ? '&queue=' . $value : '');
                    ?>
                    <a href="<?= e($href) ?>"
                       class="px-2.5 py-1 rounded-md border <?= $state === $value
                           ? 'bg-brand-500 border-brand-500 text-white'
                           : 'border-line-strong text-ink-muted hover:bg-muted' ?>">
                        <?= e($label) ?>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>

        <form method="GET" action="<?= e($modUrl) ?>" class="px-4 py-3 border-b border-line flex items-end gap-2 flex-wrap no-print">
            <input type="hidden" name="tab" value="queue">
            <input type="hidden" name="org" value="<?= (int)$selectedOrgId ?>">
            <?php if ($state !== ''): ?>
                <input type="hidden" name="queue" value="<?= e($state) ?>">
            <?php endif; ?>
            <label class="block">
                <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Severidad</span>
                <select name="qseverity" class="px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    <option value="">Todas</option>
                    <?php foreach (['CRITICAL' => 'Crítica', 'HIGH' => 'Alta', 'MEDIUM' => 'Media', 'LOW' => 'Baja'] as $key => $label): ?>
                        <option value="<?= e($key) ?>" <?= strtoupper((string)($queueFilters['severity'] ?? '')) === $key ? 'selected' : '' ?>>
                            <?= e($label) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="block flex-1 min-w-[180px]">
                <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Buscar</span>
                <input type="search" name="qq" value="<?= e((string)($queueFilters['q'] ?? '')) ?>"
                       placeholder="CVE o producto"
                       class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-ink text-xs">
            </label>
            <button type="submit" class="px-3 py-1.5 bg-gray-900 hover:bg-black text-white text-xs font-medium rounded-lg">Filtrar</button>
        </form>

        <?php if ($queueRows === []): ?>
            <p class="p-6 text-xs text-ink-muted text-center">
                No hay CVEs en la cola con esos filtros.
                <?php if ((int)$queueCounts['total'] === 0): ?>
                    Todo el tenant tiene ticket: no queda trabajo nuevo.
                <?php endif; ?>
            </p>
        <?php else: ?>
            <div class="overflow-x-auto">
                <table class="data-table w-full text-xs">
                    <thead>
                        <tr class="text-[10px] uppercase text-ink-soft border-b border-line">
                            <th class="text-left px-4 py-2">CVE</th>
                            <th class="text-left px-3 py-2">Severidad</th>
                            <th class="text-right px-3 py-2">CVSS</th>
                            <th class="text-right px-3 py-2">EPSS</th>
                            <th class="text-center px-3 py-2">KEV</th>
                            <th class="text-left px-3 py-2">Publicado</th>
                            <th class="text-right px-3 py-2">Equipos</th>
                            <th class="text-left px-3 py-2 min-w-[140px]">SLA</th>
                            <th class="text-right px-4 py-2">Acciones</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-line-subtle">
                        <?php foreach ($queueRows as $row): ?>
                            <?php
                            $cveId = (string)($row['cve_id'] ?? '');
                            $severity = (string)($row['severity'] ?? '');
                            $sla = is_array($row['sla'] ?? null) ? $row['sla'] : [];
                            $slaState = (string)($sla['state'] ?? 'sin_datos');
                            $slaLabel = (string)($sla['label'] ?? '—');
                            $slaPct = (int)($sla['pct'] ?? 0);
                            $isMarked = (string)($row['state'] ?? '') === 'en_informe';
                            ?>
                            <tr class="hover:bg-muted/40">
                                <td class="px-4 py-2">
                                    <a href="<?= e(base_url('modules/cve/detail/' . urlencode($cveId))) ?>"
                                       class="font-mono font-medium text-brand-600 dark:text-brand-300 hover:underline">
                                        <?= e($cveId) ?>
                                    </a>
                                    <?php if ((string)($row['product_name'] ?? '') !== ''): ?>
                                        <p class="text-[10px] text-ink-soft m-0 mt-0.5 truncate max-w-[220px]">
                                            <?= e((string)$row['product_name']) ?>
                                        </p>
                                    <?php endif; ?>
                                </td>
                                <td class="px-3 py-2">
                                    <?php if ($severity !== ''): ?>
                                        <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $severityClasses[$severity] ?? 'bg-gray-100 text-gray-600' ?>">
                                            <?= e($severityLabels[$severity] ?? $severity) ?>
                                        </span>
                                    <?php else: ?>
                                        <span class="text-ink-soft">sin datos</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-3 py-2 text-right font-mono">
                                    <?= $row['cvss'] !== null ? e(number_format((float)$row['cvss'], 1, '.', '')) : '—' ?>
                                </td>
                                <td class="px-3 py-2 text-right font-mono">
                                    <?= $row['epss'] !== null ? e(number_format((float)$row['epss'] * 100, 2, ',', '')) . ' %' : '—' ?>
                                </td>
                                <td class="px-3 py-2 text-center">
                                    <?php if (!empty($row['kev'])): ?>
                                        <span class="px-1.5 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 text-[10px] font-semibold">KEV</span>
                                    <?php else: ?>
                                        <span class="text-ink-soft">—</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-3 py-2 text-ink-muted whitespace-nowrap">
                                    <?= (string)($row['published_on'] ?? '') !== ''
                                        ? e(format_date((string)$row['published_on'], 'd/m/Y'))
                                        : '—' ?>
                                </td>
                                <td class="px-3 py-2 text-right font-mono"><?= (int)($row['machines'] ?? 0) ?></td>
                                <td class="px-3 py-2">
                                    <p class="m-0 text-[10px] <?= $slaText[$slaState] ?? 'text-ink-muted' ?>">
                                        <?= e($slaLabel) ?>
                                        <?php if (!empty($sla['critical'])): ?>
                                            <span class="ml-1 px-1 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300 text-[9px] font-semibold">activo crítico</span>
                                        <?php endif; ?>
                                    </p>
                                    <div class="mt-1 h-1 w-full rounded-full bg-muted overflow-hidden">
                                        <div class="h-full <?= $slaBar[$slaState] ?? 'bg-gray-300' ?>" style="width: <?= $slaPct ?>%"></div>
                                    </div>
                                </td>
                                <td class="px-4 py-2 text-right whitespace-nowrap">
                                    <a href="<?= e($modUrl . '?tab=tasks&org=' . $selectedOrgId . '&new_cve=' . urlencode($cveId)) ?>"
                                       class="px-2 py-1 rounded bg-brand-500 hover:bg-brand-600 text-white text-[10px] font-semibold">
                                        Crear ticket
                                    </a>
                                    <form method="POST" action="<?= e(base_url('modules/remediation/queue/mark')) ?>" class="inline m-0">
                                        <?= Csrf::field() ?>
                                        <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                                        <input type="hidden" name="cve_id" value="<?= e($cveId) ?>">
                                        <input type="hidden" name="return_state" value="<?= e($state) ?>">
                                        <input type="hidden" name="mark" value="<?= $isMarked ? '0' : '1' ?>">
                                        <button type="submit"
                                                class="ml-1 px-2 py-1 rounded border border-line-strong text-[10px] font-medium text-ink-muted hover:bg-muted"
                                                title="<?= $isMarked ? 'Devolver a la cola' : 'Añadir al informe en borrador' ?>">
                                            <?= $isMarked ? 'Quitar' : 'En informe' ?>
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <p class="px-4 py-2 text-[10px] text-ink-soft border-t border-line m-0">
                Mostrando <?= count($queueRows) ?> de <?= (int)$queueCounts['total'] ?> CVEs sin ticket.
                El SLA empieza la primera vez que la app ve el CVE en el tenant.
            </p>
        <?php endif; ?>
    </div>
<?php endif; ?>
