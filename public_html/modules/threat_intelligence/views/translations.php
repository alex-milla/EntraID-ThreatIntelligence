<?php
/**
 * Vista: traducciones al español guardadas de Threat Intelligence.
 * Variables: $module, $tenants, $selectedTenant, $rows, $profileCounts
 */
$rows = is_array($rows ?? null) ? $rows : [];
$totalRows = count($rows);
$failedTotal = 0;
foreach ($rows as $r) {
    $failedTotal += (int)($r['failed_chunks'] ?? 0);
}
?>
<?php
$tiActiveTab = 'translations';
require VIEWS_PATH . '/partials/ti_header.php';
?>

<div class="mb-4 flex items-center justify-between gap-3 flex-wrap">
    <p class="text-xs text-ink-soft">
        <span class="text-ink-muted font-medium"><?= number_format($totalRows) ?></span>
        <?= $totalRows === 1 ? 'traducción guardada' : 'traducciones guardadas' ?>
        · se reutilizan hasta que cambie el artículo o pasen 90 días
        <?php if ($failedTotal > 0): ?>
            · <span class="text-amber-600 dark:text-amber-400"><?= (int)$failedTotal ?> bloque(s) sin traducir</span>
        <?php endif; ?>
    </p>
    <a href="<?= e(base_url('modules/threat_intelligence?tenant=' . (int)$selectedTenant)) ?>"
       class="text-xs text-brand-500 hover:underline">Ir a Reports</a>
</div>

<?php if (empty($selectedTenant)): ?>
    <div class="card p-8 text-center">
        <p class="text-sm text-ink-muted">Selecciona un tenant para ver sus traducciones.</p>
    </div>
<?php elseif ($rows === []): ?>
    <div class="card p-8 text-center">
        <p class="text-sm text-ink-muted">Todavía no hay traducciones guardadas de este tenant.</p>
        <p class="text-xs text-ink-soft mt-2">Abre una noticia y pulsa «Traducir al español»: se guarda al terminar y aparece aquí.</p>
    </div>
<?php else: ?>
    <div class="card overflow-hidden">
        <table class="data-table w-full text-sm">
            <thead>
                <tr class="border-b border-line bg-muted text-xs text-ink-muted uppercase">
                    <th class="text-left px-4 py-2">Artículo</th>
                    <th class="text-left px-4 py-2">Publicado</th>
                    <th class="text-left px-4 py-2">Traducido</th>
                    <th class="text-left px-4 py-2">Bloques</th>
                    <th class="text-right px-4 py-2"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-line-subtle">
                <?php foreach ($rows as $r):
                    $artId = (int)($r['article_id'] ?? 0);
                    $chunks = (int)($r['chunks'] ?? 0);
                    $failed = (int)($r['failed_chunks'] ?? 0);
                    $url = base_url('modules/threat_intelligence/article/' . $artId . '?' . http_build_query(['tenant' => (int)$selectedTenant]));
                    ?>
                    <tr class="hover:bg-muted">
                        <td class="px-4 py-2">
                            <a href="<?= e($url) ?>" class="font-medium hover:text-brand-500"><?= e((string)($r['title'] ?? '(sin título)')) ?></a>
                            <?php if (!empty($r['external_id'])): ?>
                                <span class="ml-2 text-[10px] text-ink-soft font-mono"><?= e((string)$r['external_id']) ?></span>
                            <?php endif; ?>
                        </td>
                        <td class="px-4 py-2 text-xs text-ink-muted whitespace-nowrap">
                            <?= e(format_date((string)($r['created_date'] ?? $r['last_updated'] ?? ''))) ?>
                        </td>
                        <td class="px-4 py-2 text-xs text-ink-muted whitespace-nowrap">
                            <?= e(format_db_date((string)($r['translated_at'] ?? ''), 'd/m/Y H:i')) ?>
                        </td>
                        <td class="px-4 py-2 text-xs whitespace-nowrap">
                            <?php if ($failed > 0): ?>
                                <span class="text-amber-600 dark:text-amber-400" title="Bloques que no se pudieron traducir"><?= $chunks - $failed ?>/<?= $chunks ?></span>
                            <?php else: ?>
                                <span class="text-ink-muted"><?= $chunks > 0 ? $chunks . ' bloques' : '—' ?></span>
                            <?php endif; ?>
                        </td>
                        <td class="px-4 py-2 text-right">
                            <a href="<?= e($url) ?>" class="text-xs text-brand-500 hover:underline">Ver traducción</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>
