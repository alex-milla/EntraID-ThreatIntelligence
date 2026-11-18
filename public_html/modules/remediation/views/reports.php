<?php
/**
 * Vista: informes por periodo (CVE Desk, F3).
 *
 * Variables: $org, $selectedOrgId, $modUrl, $reports, $report, $reportItems,
 *            $reportMetrics, $reportHtml, $reportMd, $queueCounts.
 */

$reports = is_array($reports ?? null) ? $reports : [];
$report = is_array($report ?? null) ? $report : null;
$reportItems = is_array($reportItems ?? null) ? $reportItems : [];
$reportHtml = (string)($reportHtml ?? '');
$reportMd = (string)($reportMd ?? '');
$queueCounts = is_array($queueCounts ?? null) ? $queueCounts : [];
$currentPeriod = date('Y-m');
$statusClasses = [
    'borrador'   => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    'publicado'  => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
];
?>
<div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
    <div class="space-y-4">
        <div class="card p-4">
            <h2 class="text-sm font-semibold m-0">Nuevo informe</h2>
            <p class="text-[11px] text-ink-muted mt-1">
                Crea el borrador del periodo. Se copian los CVE marcados «En informe»
                (<?= (int)($queueCounts['en_informe'] ?? 0) ?> ahora mismo).
            </p>
            <form method="POST" action="<?= e(base_url('modules/remediation/reports/create')) ?>" class="mt-3 space-y-2">
                <?= Csrf::field() ?>
                <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                <label class="block">
                    <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Periodo</span>
                    <input type="month" name="periodo" value="<?= e($currentPeriod) ?>" required
                           class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                </label>
                <button type="submit" class="btn w-full justify-center">Crear borrador</button>
            </form>
        </div>

        <div class="card overflow-hidden">
            <div class="px-4 py-3 border-b border-line flex items-center justify-between">
                <h2 class="text-sm font-semibold m-0">Informes</h2>
                <span class="text-[10px] text-ink-soft"><?= count($reports) ?></span>
            </div>
            <?php if ($reports === []): ?>
                <p class="p-5 text-xs text-ink-muted m-0">Todavía no hay informes en esta organización.</p>
            <?php else: ?>
                <div class="divide-y divide-line-subtle max-h-[60vh] overflow-y-auto">
                    <?php foreach ($reports as $row): ?>
                        <?php
                        $rowId = (int)$row['id'];
                        $rowState = (string)($row['estado'] ?? 'borrador');
                        $active = $report !== null && (int)$report['id'] === $rowId;
                        ?>
                        <a href="<?= e($modUrl . '?tab=reports&org=' . $selectedOrgId . '&report=' . $rowId) ?>"
                           class="block px-4 py-3 hover:bg-muted/50 <?= $active ? 'bg-brand-50 dark:bg-brand-950/40' : '' ?>">
                            <div class="flex items-center justify-between gap-2">
                                <span class="font-mono text-xs font-semibold"><?= e((string)$row['periodo']) ?></span>
                                <span class="px-1.5 py-0.5 rounded text-[9px] font-semibold <?= $statusClasses[$rowState] ?? $statusClasses['borrador'] ?>">
                                    <?= $rowState === 'publicado' ? 'Publicado' : 'Borrador' ?>
                                </span>
                            </div>
                            <p class="text-[10px] text-ink-soft m-0 mt-1">
                                <?= (int)($row['item_count'] ?? 0) ?> CVE
                                · <?= e((string)($row['author_name'] ?: $row['author_username'] ?? '')) ?>
                            </p>
                        </a>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <div class="lg:col-span-2">
        <?php if ($report === null): ?>
            <div class="card p-10 text-center">
                <p class="text-sm font-semibold">Ningún informe seleccionado</p>
                <p class="text-xs text-ink-muted mt-1">Crea un borrador o elige uno de la lista.</p>
            </div>
        <?php else: ?>
            <?php
            $isDraft = (string)$report['estado'] === 'borrador';
            $metrics = is_array($reportMetrics ?? null) ? $reportMetrics : [];
            ?>
            <div class="card p-4 mb-4">
                <div class="flex items-start justify-between gap-3 flex-wrap">
                    <div>
                        <h2 class="text-lg font-semibold m-0">
                            Informe de remediación · <span class="font-mono"><?= e((string)$report['periodo']) ?></span>
                        </h2>
                        <p class="text-[11px] text-ink-muted m-0 mt-1">
                            <?= $isDraft ? 'Borrador' : 'Publicado' ?>
                            · <?= count($reportItems) ?> CVE
                            <?php if (!empty($report['published_at'])): ?>
                                · <?= e(format_date((string)$report['published_at'], 'd/m/Y H:i')) ?>
                            <?php endif; ?>
                            · <?= e((string)($report['author_name'] ?: $report['author_username'] ?? '')) ?>
                        </p>
                    </div>
                    <div class="flex items-center gap-2 flex-wrap no-print">
                        <button type="button" class="btn btn-outline" onclick="remCopyMarkdown()">Copiar Markdown</button>
                        <button type="button" class="btn btn-outline" onclick="remCopyRich()">Copiar informe</button>
                        <button type="button" class="btn" onclick="window.print()"><?= icon('print', 16) ?> Imprimir / PDF</button>
                    </div>
                </div>

                <?php if ($isDraft): ?>
                    <div class="mt-4 pt-4 border-t border-line flex items-end gap-2 flex-wrap no-print">
                        <form method="POST" action="<?= e(base_url('modules/remediation/reports/items')) ?>" class="flex items-end gap-2 flex-wrap">
                            <?= Csrf::field() ?>
                            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                            <input type="hidden" name="report_id" value="<?= (int)$report['id'] ?>">
                            <input type="hidden" name="item_action" value="add">
                            <label class="block">
                                <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Añadir CVE</span>
                                <input type="text" name="cve_id" required placeholder="CVE-2026-12345"
                                       class="w-44 px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs font-mono">
                            </label>
                            <button type="submit" class="btn btn-outline">Añadir</button>
                        </form>
                        <form method="POST" action="<?= e(base_url('modules/remediation/reports/publish')) ?>" class="m-0 ml-auto"
                              data-confirm="¿Publicar el informe? La foto quedará congelada y no se podrá editar.">
                            <?= Csrf::field() ?>
                            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                            <input type="hidden" name="report_id" value="<?= (int)$report['id'] ?>">
                            <button type="submit" class="btn">Publicar informe</button>
                        </form>
                    </div>
                <?php endif; ?>
            </div>

            <?php if ($isDraft && $reportItems !== []): ?>
                <div class="card overflow-hidden mb-4 no-print">
                    <div class="px-4 py-2 border-b border-line flex items-center justify-between">
                        <h3 class="text-xs font-semibold m-0">CVE del borrador</h3>
                        <span class="text-[10px] text-ink-soft"><?= count($reportItems) ?></span>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="data-table w-full text-xs">
                            <thead>
                                <tr class="text-[10px] uppercase text-ink-soft border-b border-line">
                                    <th class="text-left px-3 py-2">CVE</th>
                                    <th class="text-left px-3 py-2">Severidad</th>
                                    <th class="text-right px-3 py-2">CVSS</th>
                                    <th class="text-right px-3 py-2">Equipos</th>
                                    <th class="text-left px-3 py-2">Estado</th>
                                    <th class="text-right px-3 py-2"></th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-line-subtle">
                                <?php foreach ($reportItems as $item): ?>
                                    <tr>
                                        <td class="px-3 py-1.5 font-mono"><?= e((string)$item['cve_id']) ?></td>
                                        <td class="px-3 py-1.5"><?= e((string)($item['severity'] ?? '—')) ?></td>
                                        <td class="px-3 py-1.5 text-right font-mono">
                                            <?= $item['cvss'] !== null ? e(number_format((float)$item['cvss'], 1, '.', '')) : '—' ?>
                                        </td>
                                        <td class="px-3 py-1.5 text-right"><?= (int)($item['machines'] ?? 0) ?></td>
                                        <td class="px-3 py-1.5"><?= e((string)($item['estado'] ?? '—')) ?></td>
                                        <td class="px-3 py-1.5 text-right">
                                            <form method="POST" action="<?= e(base_url('modules/remediation/reports/items')) ?>" class="m-0">
                                                <?= Csrf::field() ?>
                                                <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                                                <input type="hidden" name="report_id" value="<?= (int)$report['id'] ?>">
                                                <input type="hidden" name="item_action" value="remove">
                                                <input type="hidden" name="cve_id" value="<?= e((string)$item['cve_id']) ?>">
                                                <button type="submit" class="text-[11px] text-danger hover:underline">Quitar</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php endif; ?>

            <style>
                @media print {
                    body * { visibility: hidden !important; }
                    #rem-report-sheet, #rem-report-sheet * { visibility: visible !important; }
                    #rem-report-sheet {
                        position: absolute; left: 0; top: 0; width: 100%; margin: 0 !important;
                        border: 0 !important; box-shadow: none !important; background: #fff !important;
                        color: #000 !important; font-size: 10pt; line-height: 1.45; padding: 0 !important;
                    }
                }
            </style>
            <div class="card p-5">
                <div id="rem-report-sheet" class="doc-sheet"><?= $reportHtml ?></div>
            </div>
            <pre id="rem-report-md" class="hidden"><?= e($reportMd) ?></pre>
        <?php endif; ?>
    </div>
</div>

<script>
function remCopyMarkdown() {
    var node = document.getElementById('rem-report-md');
    if (!node) { return; }
    var text = node.textContent || '';
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function () {
            if (typeof toast === 'function') { toast('Markdown copiado', 'success'); }
        });
        return;
    }
    var area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(area);
}
function remCopyRich() {
    var sheet = document.getElementById('rem-report-sheet');
    if (!sheet) { return; }
    var html = sheet.innerHTML;
    if (navigator.clipboard && window.ClipboardItem && window.isSecureContext) {
        var item = new ClipboardItem({
            'text/html': new Blob([html], { type: 'text/html' }),
            'text/plain': new Blob([sheet.textContent || ''], { type: 'text/plain' })
        });
        navigator.clipboard.write([item]).then(function () {
            if (typeof toast === 'function') { toast('Informe copiado', 'success'); }
        });
        return;
    }
    remCopyMarkdown();
}
</script>
