<?php
/**
 * Vista: Intel Profiles (Threat actors y Tools).
 */
$profileCounts = $counts ?? ['actor' => 0, 'tool' => 0, 'other' => 0, 'total' => 0];
$kind = $filters['kind'] ?? '';
$search = $filters['search'] ?? '';
$facets = $facets ?? ['industries' => [], 'regions' => []];
$selInd = array_values(array_filter(array_map('strval', (array)($filters['industry'] ?? [])), fn($v) => trim($v) !== ''));
$selReg = array_values(array_filter(array_map('strval', (array)($filters['region'] ?? [])), fn($v) => trim($v) !== ''));
$tiActiveTab = ($kind === 'tool') ? 'tool' : 'actor';

// Filtros que se conservan al cambiar de pestaña.
$tiFilterQs = [];
if ($search !== '')  { $tiFilterQs['q'] = $search; }
if (!empty($selInd)) { $tiFilterQs['industry'] = $selInd; }
if (!empty($selReg)) { $tiFilterQs['region'] = $selReg; }

// Alterna un valor de faceta conservando el resto de filtros.
if (!function_exists('ti_toggle_target')) {
    function ti_toggle_target(array $base, string $key, string $val): string
    {
        $sel = array_values(array_filter(array_map('strval', (array)($base[$key] ?? [])), fn($v) => trim($v) !== ''));
        $i = array_search($val, $sel, true);
        if ($i !== false) { unset($sel[$i]); } else { $sel[] = $val; }
        $sel = array_values($sel);
        if ($sel) { $base[$key] = $sel; } else { unset($base[$key]); }
        return http_build_query($base);
    }
}
$facetBase = ['tenant' => (int)$selectedTenant];
if ($kind !== '')    { $facetBase['kind'] = $kind; }
if ($search !== '')  { $facetBase['search'] = $search; }
if (!empty($selInd)) { $facetBase['industry'] = $selInd; }
if (!empty($selReg)) { $facetBase['region'] = $selReg; }
$facetClear = http_build_query(array_filter(['tenant' => (int)$selectedTenant, 'kind' => $kind, 'search' => $search], fn($v) => $v !== '' && $v !== null));

require VIEWS_PATH . '/partials/ti_header.php';
?>
<div class="mb-6 space-y-3">
    <form method="GET" class="flex items-end gap-3 flex-wrap">
        <input type="hidden" name="tenant" value="<?= (int)$selectedTenant ?>">
        <input type="hidden" name="kind" value="<?= e($kind) ?>">
        <?php foreach ($selInd as $v): ?><input type="hidden" name="industry[]" value="<?= e($v) ?>"><?php endforeach; ?>
        <?php foreach ($selReg as $v): ?><input type="hidden" name="region[]" value="<?= e($v) ?>"><?php endforeach; ?>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Buscar</label>
            <input type="text" name="search" value="<?= e($search) ?>" placeholder="Nombre, alias…"
                   class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none w-56">
        </div>
        <button type="submit" class="px-3 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">Filtrar</button>
    </form>

    <?php if (!empty($selectedTenant) && (!empty($facets['industries']) || !empty($facets['regions']))): ?>
    <div class="space-y-2">
        <?php if (!empty($facets['industries'])): ?>
        <div class="flex flex-wrap items-center gap-1.5">
            <span class="text-[11px] text-gray-400 mr-1 shrink-0">Industrias:</span>
            <?php foreach ($facets['industries'] as $name => $cnt): $on = in_array((string)$name, $selInd, true); ?>
                <a href="?<?= e(ti_toggle_target($facetBase, 'industry', (string)$name)) ?>" title="Filtrar por industria" class="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full border <?= $on ? 'bg-brand-500 border-brand-500 text-white' : 'border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800' ?>"><?= e((string)$name) ?> <span class="opacity-70">(<?= (int)$cnt ?>)</span></a>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
        <?php if (!empty($facets['regions'])): ?>
        <div class="flex flex-wrap items-center gap-1.5">
            <span class="text-[11px] text-gray-400 mr-1 shrink-0">Regiones:</span>
            <?php foreach ($facets['regions'] as $name => $cnt): $on = in_array((string)$name, $selReg, true); ?>
                <a href="?<?= e(ti_toggle_target($facetBase, 'region', (string)$name)) ?>" title="Filtrar por región" class="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full border <?= $on ? 'bg-brand-500 border-brand-500 text-white' : 'border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800' ?>"><?= e((string)$name) ?> <span class="opacity-70">(<?= (int)$cnt ?>)</span></a>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
        <?php if (!empty($selInd) || !empty($selReg)): ?>
            <a href="?<?= e($facetClear) ?>" class="inline-block text-xs text-gray-500 hover:underline">Limpiar facetas</a>
        <?php endif; ?>
    </div>
    <?php endif; ?>
</div>

<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-sm font-semibold">Intel profiles (<?= (int)($profiles['total'] ?? 0) ?>)</h2>
    </div>
    <?php if (empty($profiles['data'])): ?>
        <p class="px-5 py-8 text-sm text-gray-500 text-center">Sin perfiles. Pulsa «Sincronizar todo» (arriba de las pestañas) para obtenerlos.</p>
    <?php else: ?>
        <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
            <?php foreach ($profiles['data'] as $p): ?>
                <?php
                $aliases = safe_json_decode((string)($p['aliases'] ?? ''), []);
                $aliasesStr = is_array($aliases) ? implode(', ', array_slice(array_map('strval', $aliases), 0, 5)) : '';
                $inds = safe_json_decode((string)($p['industries'] ?? ''), []);
                ?>
                <a href="<?= base_url('modules/threat_intelligence/profile/' . (int)$p['id']) ?>" class="block px-5 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                    <div class="flex items-start justify-between gap-3">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($p['title']) ?></p>
                            <p class="text-xs text-gray-400 mt-0.5">
                                <?= e(ucfirst((string)($p['kind'] ?? ''))) ?>
                                <?php if ($aliasesStr !== ''): ?> · <?= e(truncate($aliasesStr, 100)) ?><?php endif; ?>
                                <?php if (!empty($p['first_active'])): ?> · desde <?= e(substr((string)$p['first_active'], 0, 10)) ?><?php endif; ?>
                            </p>
                            <?php if (is_array($inds) && $inds): ?>
                                <div class="flex flex-wrap gap-1 mt-1.5">
                                    <?php foreach (array_slice($inds, 0, 5) as $ind): ?><span class="inline-flex px-1.5 py-0.5 text-[10px] rounded-full bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400"><?= e((string)$ind) ?></span><?php endforeach; ?>
                                    <?php if (count($inds) > 5): ?><span class="text-[10px] text-gray-400 self-center">+<?= count($inds) - 5 ?></span><?php endif; ?>
                                </div>
                            <?php endif; ?>
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
                    <?php
                    $qsArr = ['tenant' => (int)$selectedTenant];
                    if ($kind !== '')    { $qsArr['kind'] = $kind; }
                    if ($search !== '')  { $qsArr['search'] = $search; }
                    if (!empty($selInd)) { $qsArr['industry'] = $selInd; }
                    if (!empty($selReg)) { $qsArr['region'] = $selReg; }
                    $qs = http_build_query($qsArr);
                    ?>
                    <?php if (($profiles['page'] ?? 1) > 1): ?><a href="?<?= e($qs) ?>&page=<?= (int)$profiles['page'] - 1 ?>" class="text-brand-500 hover:underline">← Anterior</a><?php endif; ?>
                    <?php if (($profiles['page'] ?? 1) < ($profiles['totalPages'] ?? 1)): ?><a href="?<?= e($qs) ?>&page=<?= (int)$profiles['page'] + 1 ?>" class="text-brand-500 hover:underline">Siguiente →</a><?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<?php if (!empty($selectedTenant)) { require VIEWS_PATH . '/partials/ti_sync.php'; } ?>
