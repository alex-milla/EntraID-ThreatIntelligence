<?php
/**
 * Vista genérica de índice de módulo.
 * Cada módulo puede sobrescribir esta vista creando
 * modules/{module_key}/views/index.php
 */
?>

<div class="mb-6">
    <!-- Selector de tenant -->
    <form method="GET" class="flex items-center gap-3">
        <label class="text-sm font-medium text-gray-700 dark:text-gray-300">Tenant:</label>
        <select name="tenant" onchange="this.form.submit()"
                class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>>
                    <?= e($t['name']) ?>
                </option>
            <?php endforeach; ?>
        </select>

        <?php if (!empty($selectedTenant)): ?>
            <button type="button" onclick="syncTenant(<?= (int)$selectedTenant ?>)"
                    class="inline-flex items-center gap-2 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                Sincronizar
            </button>
        <?php endif; ?>
    </form>
</div>

<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6">
    <h2 class="text-lg font-semibold mb-2"><?= e($module->name()) ?></h2>
    <p class="text-sm text-gray-500 mb-4"><?= e($module->description()) ?></p>

    <div class="text-sm text-gray-400">
        <p>Este módulo está activo. Usa la navegación o los endpoints del módulo para interactuar con los datos.</p>
        <p class="mt-2 font-mono text-xs">Módulo: <?= e($module->key()) ?> v<?= e($module->version()) ?></p>
    </div>
</div>

<script>
function syncTenant(tenantId) {
    var btn = event.target.closest('button');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span> Sincronizando...';

    api('POST', '<?= base_url('modules/' . $module->key() . '/sync') ?>/' + tenantId, {})
        .then(function(res) {
            if (res.success) {
                toast('Sincronización completada: ' + (res.records || 0) + ' registros', 'success');
            } else {
                toast('Error: ' + (res.error || 'Error desconocido'), 'error');
            }
        })
        .catch(function(err) { toast('Error de conexión', 'error'); })
        .finally(function() {
            btn.disabled = false;
            btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Sincronizar';
        });
}
</script>
