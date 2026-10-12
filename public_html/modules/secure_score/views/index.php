<?php
/**
 * Vista índice del módulo Secure Score.
 */
?>
<div class="mb-6">
    <form method="GET" class="flex items-center gap-3 flex-wrap">
        <label class="text-sm font-medium text-gray-700 dark:text-gray-300">Tenant:</label>
        <select name="tenant" onchange="this.form.submit()"
                class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </form>
</div>

<?php if (!empty($selectedTenant) && !empty($trend['latest'])): ?>
<div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <p class="text-sm text-gray-500">Score actual</p>
        <p class="text-3xl font-bold mt-2 text-brand-500"><?= number_format($trend['latest']['current_score'] ?? 0, 1) ?></p>
    </div>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <p class="text-sm text-gray-500">Score máximo</p>
        <p class="text-3xl font-bold mt-2"><?= number_format($trend['latest']['max_score'] ?? 0, 1) ?></p>
    </div>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <p class="text-sm text-gray-500">Porcentaje</p>
        <p class="text-3xl font-bold mt-2 text-green-500">
            <?= $trend['latest']['max_score'] ? round($trend['latest']['current_score'] * 100 / $trend['latest']['max_score'], 1) : 0 ?>%
        </p>
    </div>
</div>

<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6">
    <h2 class="text-sm font-semibold mb-4">Evolución</h2>
    <?php if (!empty($trend['trend'])): ?>
        <div class="space-y-2">
            <?php foreach (array_slice($trend['trend'], -12) as $point): ?>
                <div class="flex items-center gap-3">
                    <span class="text-xs text-gray-400 w-20 shrink-0 font-mono"><?= e(substr($point['score_date'], 0, 7)) ?></span>
                    <div class="flex-1 bg-gray-100 dark:bg-gray-800 rounded-full h-2 overflow-hidden">
                        <div class="bg-brand-500 h-full rounded-full transition-all" style="width: <?= $point['percentage'] ?? 0 ?>%"></div>
                    </div>
                    <span class="text-xs font-medium w-12 text-right"><?= $point['percentage'] ?? 0 ?>%</span>
                </div>
            <?php endforeach; ?>
        </div>
    <?php else: ?>
        <p class="text-sm text-gray-500">Sin datos históricos. Sincroniza el tenant.</p>
    <?php endif; ?>
</div>
<?php else: ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
    <p class="text-sm text-gray-500">Selecciona un tenant para ver el Secure Score.</p>
</div>
<?php endif; ?>
