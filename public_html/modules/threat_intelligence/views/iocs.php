<?php
/**
 * Vista: lista de IOCs de Threat Intelligence (filtros + paginación).
 * Variables: $module, $tenants, $selectedTenant, $filters, $iocs, $types
 */
$rows = $iocs['data'] ?? [];
$totalPages = (int)($iocs['totalPages'] ?? 1);
$page = (int)($iocs['page'] ?? 1);

function ti_q(array $extra, int $tenant, array $filters): string {
    $q = array_merge(['tenant' => $tenant, 'type' => $filters['type'] ?? '', 'search' => $filters['search'] ?? ''], $extra);
    return http_build_query(array_filter($q, fn($v) => $v !== '' && $v !== null));
}
?>
<div class="mb-6">
    <a href="<?= base_url('modules/threat_intelligence?tenant=' . $selectedTenant) ?>" class="text-xs text-brand-500 hover:underline">← Volver a Threat Intel</a>
    <h1 class="text-xl font-semibold mt-2">Indicadores (IOCs)</h1>
    <p class="text-xs text-gray-400 mt-1"><?= number_format((int)($iocs['total'] ?? 0)) ?> IOCs · <?= count($types) ?> tipos</p>
</div>

<!-- Filtros -->
<form method="GET" class="mb-4 flex flex-wrap items-center gap-2">
    <select name="tenant" onchange="this.form.submit()" class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm">
        <?php foreach ($tenants as $t): ?>
            <option value="<?= $t['id'] ?>" <?= (int)$selectedTenant === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
        <?php endforeach; ?>
    </select>
    <select name="type" onchange="this.form.submit()" class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm">
        <option value="">Todos los tipos</option>
        <?php foreach ($types as $ty): ?>
            <option value="<?= e($ty['ioc_type']) ?>" <?= ($filters['type'] ?? '') === $ty['ioc_type'] ? 'selected' : '' ?>><?= e($ty['ioc_type']) ?> (<?= (int)$ty['cnt'] ?>)</option>
        <?php endforeach; ?>
    </select>
    <input type="text" name="search" value="<?= e($filters['search'] ?? '') ?>" placeholder="Buscar valor…"
           class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm w-56">
    <button type="submit" class="px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">Filtrar</button>
    <?php if (($filters['type'] ?? '') !== '' || ($filters['search'] ?? '') !== ''): ?>
        <a href="<?= base_url('modules/threat_intelligence/iocs?tenant=' . $selectedTenant) ?>" class="text-xs text-gray-500 hover:underline">Limpiar</a>
    <?php endif; ?>
</form>

<!-- Exportar -->
<div class="mb-4 flex flex-wrap items-center gap-2">
    <span class="text-xs text-gray-500">Exportar (según filtros):</span>
    <button onclick="exportIocs('txt')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">TXT</button>
    <button onclick="exportIocs('csv')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">CSV</button>
    <button onclick="exportIocs('stix')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">STIX 2.1</button>
    <button onclick="exportIocs('misp')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">MISP</button>
    <span id="export-msg" class="text-xs text-gray-500"></span>
</div>

<!-- Tabla -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <?php if (empty($rows)): ?>
        <p class="px-5 py-8 text-sm text-gray-500 text-center">Sin IOCs para estos filtros.</p>
    <?php else: ?>
        <table class="w-full text-sm">
            <thead>
                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                    <th class="text-left px-4 py-2">Tipo</th>
                    <th class="text-left px-4 py-2">Valor</th>
                    <th class="text-left px-4 py-2">Severidad</th>
                    <th class="text-left px-4 py-2">Descripción</th>
                    <th class="text-right px-4 py-2"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                <?php foreach ($rows as $ioc): ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <td class="px-4 py-2"><span class="font-mono text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-800"><?= e($ioc['ioc_type']) ?></span></td>
                        <td class="px-4 py-2 font-mono text-xs break-all" data-ioc="<?= e($ioc['ioc_value']) ?>"><?= e($ioc['ioc_value']) ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($ioc['severity'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500 max-w-xs truncate"><?= e($ioc['description'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-right">
                            <?php if (!empty($ioc['article_id'])): ?>
                                <a href="<?= base_url('modules/threat_intelligence/article/' . (int)$ioc['article_id']) ?>" class="text-xs text-brand-500 hover:underline">artículo</a>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<!-- Paginación -->
<?php if ($totalPages > 1): ?>
<div class="mt-4 flex items-center justify-center gap-2 text-sm">
    <?php if ($page > 1): ?>
        <a href="?<?= ti_q(['page' => $page - 1], $selectedTenant, $filters) ?>" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">« Anterior</a>
    <?php endif; ?>
    <span class="text-xs text-gray-500">Página <?= $page ?> de <?= $totalPages ?></span>
    <?php if ($page < $totalPages): ?>
        <a href="?<?= ti_q(['page' => $page + 1], $selectedTenant, $filters) ?>" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">Siguiente »</a>
    <?php endif; ?>
</div>
<?php endif; ?>

<script>
function exportIocs(fmt) {
    var el = document.getElementById('export-msg');
    el.textContent = 'Generando…';
    api('POST', '<?= base_url('modules/export') ?>/' + fmt, {
        tenant_id: <?= (int)$selectedTenant ?>,
        filters: { type: '<?= e(addslashes($filters['type'] ?? '')) ?>', search: '<?= e(addslashes($filters['search'] ?? '')) ?>' }
    }).then(function(res) {
        if (res && res.success) { downloadFile(res.content, res.filename, res.mime); el.textContent = 'Exportado (' + (res.count || 0) + ')'; }
        else { el.textContent = 'Error al exportar'; }
    }).catch(function() { el.textContent = 'Error de conexión'; });
}
</script>
