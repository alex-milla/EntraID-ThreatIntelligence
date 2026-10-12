<?php
/**
 * Vista: Intel Profiles (Threat actors y Tools).
 */
$pc = $counts ?? ['actor' => 0, 'tool' => 0, 'other' => 0, 'total' => 0];
$kind = $filters['kind'] ?? '';
$search = $filters['search'] ?? '';
$tab = 'px-3 py-2 text-sm font-medium border-b-2';
$tabOn = 'border-brand-500 text-brand-600 dark:text-brand-300';
$tabOff = 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300';
?>
<div class="mb-6 space-y-3">
    <div class="flex flex-wrap items-center gap-1 border-b border-gray-200 dark:border-gray-700">
        <a href="<?= base_url('modules/threat_intelligence?tenant=' . (int)$selectedTenant) ?>" class="<?= $tab ?> <?= $tabOff ?>">Reports</a>
        <a href="<?= base_url('modules/threat_intelligence/profiles?tenant=' . (int)$selectedTenant . '&kind=actor') ?>" class="<?= $tab ?> <?= $kind === 'actor' ? $tabOn : $tabOff ?>">Threat actors (<?= (int)($pc['actor'] ?? 0) ?>)</a>
        <a href="<?= base_url('modules/threat_intelligence/profiles?tenant=' . (int)$selectedTenant . '&kind=tool') ?>" class="<?= $tab ?> <?= $kind === 'tool' ? $tabOn : $tabOff ?>">Tools (<?= (int)($pc['tool'] ?? 0) ?>)</a>
        <a href="<?= base_url('modules/threat_intelligence/iocs?tenant=' . (int)$selectedTenant) ?>" class="<?= $tab ?> <?= $tabOff ?>">Indicators</a>
    </div>

    <form method="GET" class="flex items-end gap-3 flex-wrap">
        <input type="hidden" name="tenant" value="<?= (int)$selectedTenant ?>">
        <input type="hidden" name="kind" value="<?= e($kind) ?>">
        <div>
            <label class="block text-xs text-gray-500 mb-1">Buscar</label>
            <input type="text" name="search" value="<?= e($search) ?>" placeholder="Nombre, alias…"
                   class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none w-56">
        </div>
        <button type="submit" class="px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-muted-dark text-sm font-medium rounded-lg transition-colors">Filtrar</button>
        <?php if (!empty($selectedTenant)): ?>
            <button type="button" onclick="syncProfiles()" class="px-4 py-2 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-sm font-medium rounded-lg transition-colors">Sincronizar perfiles</button>
            <button type="button" onclick="syncIndicators()" class="px-4 py-2 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-sm font-medium rounded-lg transition-colors">Sincronizar indicadores</button>
        <?php endif; ?>
    </form>
</div>

<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-sm font-semibold">Intel profiles (<?= (int)($profiles['total'] ?? 0) ?>)</h2>
    </div>
    <?php if (empty($profiles['data'])): ?>
        <p class="px-5 py-8 text-sm text-gray-500 text-center">Sin perfiles. Pulsa «Sincronizar perfiles» (o sincroniza el tenant).</p>
    <?php else: ?>
        <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
            <?php foreach ($profiles['data'] as $p): ?>
                <?php
                $aliases = safe_json_decode((string)($p['aliases'] ?? ''), []);
                $aliasesStr = is_array($aliases) ? implode(', ', array_slice(array_map('strval', $aliases), 0, 5)) : '';
                ?>
                <a href="<?= base_url('modules/threat_intelligence/profile/' . (int)$p['id']) ?>" class="block px-5 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                    <div class="flex items-start justify-between gap-3">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($p['title']) ?></p>
                            <p class="text-xs text-gray-400 mt-0.5">
                                <?= e(ucfirst((string)($p['kind'] ?? ''))) ?>
                                <?php if ($aliasesStr !== ''): ?> · <?= e(truncate($aliasesStr, 100)) ?><?php endif; ?>
                                <?php if (!empty($p['first_active'])): ?> · desde <?= e($p['first_active']) ?><?php endif; ?>
                            </p>
                        </div>
                        <?php if (($p['kind'] ?? '') === 'actor'): ?>
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300">actor</span>
                        <?php else: ?>
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300"><?= e((string)($p['kind'] ?? 'tool')) ?></span>
                        <?php endif; ?>
                    </div>
                </a>
            <?php endforeach; ?>
        </div>
        <?php if (($profiles['totalPages'] ?? 1) > 1): ?>
            <div class="px-5 py-3 flex items-center justify-between text-xs text-gray-500 border-t border-gray-100 dark:border-gray-700/50">
                <span>Página <?= (int)$profiles['page'] ?> de <?= (int)$profiles['totalPages'] ?></span>
                <div class="flex gap-2">
                    <?php $qs = http_build_query(array_filter(['tenant' => (int)$selectedTenant, 'kind' => $kind, 'search' => $search])); ?>
                    <?php if (($profiles['page'] ?? 1) > 1): ?><a href="?<?= e($qs) ?>&page=<?= (int)$profiles['page'] - 1 ?>" class="text-brand-500 hover:underline">← Anterior</a><?php endif; ?>
                    <?php if (($profiles['page'] ?? 1) < ($profiles['totalPages'] ?? 1)): ?><a href="?<?= e($qs) ?>&page=<?= (int)$profiles['page'] + 1 ?>" class="text-brand-500 hover:underline">Siguiente →</a><?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<script>
var TI_TENANT = <?= (int)$selectedTenant ?>;
function syncProfiles() {
    toast('Sincronizando perfiles…', 'info');
    api('POST', '<?= base_url('modules/threat_intelligence/sync') ?>/' + TI_TENANT, {})
        .then(function(r) { if (r.success) { toast('Sincronizado: ' + (r.records || 0) + ' registros', 'success'); setTimeout(function(){ location.reload(); }, 1500); } else { toast(r.error || 'Error', 'error'); } })
        .catch(function() { toast('Error de conexión', 'error'); });
}
function syncIndicators() {
    toast('Cosechando indicadores de perfiles…', 'info');
    api('POST', '<?= base_url('modules/threat_intelligence/sync-indicators') ?>/' + TI_TENANT, {})
        .then(function(r) {
            if (r.success) { toast('Perfiles: ' + (r.profiles || 0) + ' · indicadores: ' + (r.indicators || 0) + (r.errors ? ' (' + r.errors + ' con error)' : ''), 'success'); setTimeout(function(){ location.reload(); }, 1800); }
            else { toast(r.error || 'Error', 'error'); }
        })
        .catch(function() { toast('Error de conexión', 'error'); });
}
</script>
