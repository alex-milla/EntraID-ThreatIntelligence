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
        <label class="text-sm font-medium text-ink">Tenant:</label>
        <select name="tenant" onchange="this.form.submit()"
                class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>>
                    <?= e($t['name']) ?>
                </option>
            <?php endforeach; ?>
        </select>

        <?php if (!empty($selectedTenant)): ?>
            <button type="button" onclick="syncTenant(<?= (int)$selectedTenant ?>)"
                    class="btn btn-small">
                <i class="material-icons icon-16" aria-hidden="true">sync</i>
                Sincronizar
            </button>
        <?php endif; ?>
    </form>
</div>

<div class="card p-6">
    <h2 class="text-lg font-semibold mb-2"><?= e($module->name()) ?></h2>
    <p class="text-sm text-ink-muted mb-4"><?= e($module->description()) ?></p>

    <div class="text-sm text-ink-soft">
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
            btn.innerHTML = '<i class="material-icons icon-16" aria-hidden="true">sync</i> Sincronizar';
        });
}
</script>
