<?php
/**
 * Vista índice del módulo Threat Intelligence.
 */
?>
<div class="mb-6 space-y-3">
    <!-- Pestañas (Reports / Threat actors / Tools / Indicators) -->
    <?php $pc = $profileCounts ?? ['actor' => 0, 'tool' => 0, 'total' => 0]; ?>
    <div class="flex flex-wrap items-center gap-1 border-b border-gray-200 dark:border-gray-700">
        <a href="<?= base_url('modules/threat_intelligence?tenant=' . (int)$selectedTenant) ?>" class="px-3 py-2 text-sm font-medium border-b-2 border-brand-500 text-brand-600 dark:text-brand-300">Reports</a>
        <a href="<?= base_url('modules/threat_intelligence/profiles?tenant=' . (int)$selectedTenant . '&kind=actor') ?>" class="px-3 py-2 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">Threat actors (<?= (int)($pc['actor'] ?? 0) ?>)</a>
        <a href="<?= base_url('modules/threat_intelligence/profiles?tenant=' . (int)$selectedTenant . '&kind=tool') ?>" class="px-3 py-2 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">Tools (<?= (int)($pc['tool'] ?? 0) ?>)</a>
        <a href="<?= base_url('modules/threat_intelligence/iocs?tenant=' . (int)$selectedTenant) ?>" class="px-3 py-2 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">Indicators</a>
    </div>

    <form method="GET" class="flex items-end gap-3 flex-wrap">
        <div>
            <label class="block text-xs text-gray-500 mb-1">Tenant</label>
            <select name="tenant" onchange="this.form.submit()"
                    class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                <?php foreach ($tenants as $t): ?>
                    <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Buscar</label>
            <input type="text" name="q" value="<?= e($q ?? '') ?>" placeholder="APT, Storm-2992, sector…"
                   class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none w-56">
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Tag</label>
            <select name="tag" class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none max-w-[16rem]">
                <option value="">Todas las tags</option>
                <?php foreach (($tagOptions ?? []) as $tg => $cnt): ?>
                    <option value="<?= e($tg) ?>" <?= ($tag ?? '') === $tg ? 'selected' : '' ?>><?= e(truncate((string)$tg, 60)) ?> (<?= (int)$cnt ?>)</option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Sector</label>
            <select name="sector" class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="">Todos los sectores</option>
                <?php foreach (($sectors ?? []) as $sc): ?>
                    <option value="<?= e($sc) ?>" <?= ($sector ?? '') === $sc ? 'selected' : '' ?>><?= e($sc) ?></option>
                <?php endforeach; ?>
            </select>
            <?php if (!empty($mySector)): ?>
                <a href="?<?= e(http_build_query(array_filter(['tenant' => (int)$selectedTenant, 'from' => $dateFrom ?? '', 'to' => $dateTo ?? '', 'sector' => $mySector]))) ?>" class="text-[11px] text-brand-500 hover:underline">→ Mi sector (<?= e($mySector) ?>)</a>
            <?php endif; ?>
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Desde</label>
            <input type="date" name="from" value="<?= e($dateFrom ?? '') ?>"
                   class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Hasta</label>
            <input type="date" name="to" value="<?= e($dateTo ?? '') ?>"
                   class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <button type="submit" class="px-3 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">Filtrar</button>
        <?php if (($q ?? '') !== '' || ($tag ?? '') !== '' || ($sector ?? '') !== '' || ($dateFrom ?? '') !== '' || ($dateTo ?? '') !== ''): ?>
            <a href="?tenant=<?= (int)$selectedTenant ?>" class="text-xs text-gray-500 hover:underline">Limpiar</a>
        <?php endif; ?>
        <?php if (!empty($selectedTenant)): ?>
            <button type="button" onclick="runTiSync()" class="inline-flex items-center gap-2 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                Sincronizar
            </button>
        <?php endif; ?>
    </form>
    <div class="flex items-center gap-3 text-xs">
        <span class="text-gray-400">Rápido:</span>
        <?php foreach ([7 => '7 días', 30 => '30 días', 90 => '90 días'] as $d => $lbl): $f = gmdate('Y-m-d', strtotime($dateTo ?? 'now') - $d * 86400); ?>
            <a href="?<?= e(http_build_query(array_filter(['tenant' => (int)$selectedTenant, 'q' => $q ?? '', 'tag' => $tag ?? '', 'sector' => $sector ?? '', 'from' => $f, 'to' => $dateTo ?? '']))) ?>" class="text-brand-500 hover:underline"><?= $lbl ?></a>
        <?php endforeach; ?>
        <span class="text-gray-400">· máx. 90 días</span>
    </div>
</div>

<?php if (!empty($selectedTenant)): ?>
<!-- Stats de IOCs -->
<?php if (!empty($stats)): ?>
<div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
    <?php foreach ($stats as $s): ?>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-center">
            <p class="text-2xl font-bold text-brand-500"><?= number_format($s['cnt']) ?></p>
            <p class="text-xs text-gray-500 font-mono mt-1"><?= e($s['ioc_type']) ?></p>
        </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<!-- Artículos recientes -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
        <h2 class="text-sm font-semibold">Artículos recientes</h2>
        <a href="<?= base_url('modules/threat_intelligence/iocs?tenant=' . $selectedTenant) ?>" class="text-xs text-brand-500 hover:underline">Ver todos los IOCs</a>
    </div>
    <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
        <?php if (empty($articles['data'])): ?>
            <p class="px-5 py-8 text-sm text-gray-500 text-center">Sin artículos. Sincroniza el tenant para obtener datos.</p>
        <?php else: ?>
            <?php foreach ($articles['data'] as $a): ?>
                <a href="<?= base_url('modules/threat_intelligence/article/' . (int)$a['id'] . '?' . http_build_query(array_filter(['tenant' => (int)$selectedTenant, 'from' => $dateFrom ?? '', 'to' => $dateTo ?? '', 'q' => $q ?? '', 'tag' => $tag ?? '', 'sector' => $sector ?? '']))) ?>" class="block px-5 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                    <div class="flex items-start justify-between gap-3">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($a['title']) ?></p>
                            <p class="text-xs text-gray-400 mt-0.5"><?= format_date($a['last_updated'] ?? $a['created_date']) ?> · <?= (int)$a['ioc_count'] ?> IOCs</p>
                        </div>
                        <span class="text-xs text-gray-400 shrink-0"><?= time_ago($a['fetched_at']) ?> →</span>
                    </div>
                </a>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</div>
<?php else: ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
    <p class="text-sm text-gray-500">Selecciona un tenant para ver los datos de Threat Intelligence.</p>
</div>
<?php endif; ?>

<?php if (!empty($selectedTenant)) { require VIEWS_PATH . '/partials/ti_sync.php'; } ?>
