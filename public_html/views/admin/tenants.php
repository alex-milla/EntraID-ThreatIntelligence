<?php
/**
 * Vista: Gestión de tenants.
 */
$pageTitle = 'Gestión de Tenants';
?>

<?php
$flashData = flash();
foreach ($flashData as $type => $msg):
    $colors = match($type) {
        'success' => 'text-green-600 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800',
        'error'   => 'text-red-600 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800',
        default   => 'text-blue-600 bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800',
    };
?>
    <div class="mb-4 px-4 py-3 rounded-lg border text-sm <?= $colors ?>"><?= e($msg) ?></div>
<?php endforeach; ?>

<div class="flex items-center justify-between mb-6">
    <h2 class="text-xl font-bold">Tenants</h2>
    <a href="<?= base_url('admin/tenant/edit') ?>" class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
        Nuevo tenant
    </a>
</div>

<!-- Tabla de tenants -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <table class="w-full">
        <thead>
            <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
                <th class="text-left px-4 py-3 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">Nombre</th>
                <th class="text-left px-4 py-3 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">Tenant ID</th>
                <th class="text-left px-4 py-3 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">Estado</th>
                <th class="text-left px-4 py-3 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">Última sync</th>
                <th class="text-right px-4 py-3 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">Acciones</th>
            </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
            <?php if (empty($tenants)): ?>
                <tr><td colspan="5" class="px-4 py-8 text-sm text-gray-500 text-center">No hay tenants configurados</td></tr>
            <?php else: ?>
                <?php foreach ($tenants as $t): ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                        <td class="px-4 py-3">
                            <p class="text-sm font-medium"><?= e($t['name']) ?></p>
                            <p class="text-xs text-gray-400 font-mono"><?= e($t['slug']) ?></p>
                        </td>
                        <td class="px-4 py-3 text-sm font-mono text-gray-600 dark:text-gray-400"><?= e(truncate($t['tenant_id'], 20)) ?></td>
                        <td class="px-4 py-3">
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $t['is_active'] ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400' ?>">
                                <?= $t['is_active'] ? 'Activo' : 'Inactivo' ?>
                            </span>
                        </td>
                        <td class="px-4 py-3 text-sm text-gray-500"><?= $t['last_sync_at'] ? time_ago($t['last_sync_at']) : '—' ?></td>
                        <td class="px-4 py-3 text-right">
                            <div class="flex items-center justify-end gap-1">
                                <a href="<?= base_url('admin/tenant/edit?id=' . $t['id']) ?>" class="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors" title="Editar">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                                </a>
                                <form method="POST" action="<?= base_url('admin/tenant/toggle') ?>" class="inline">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="id" value="<?= $t['id'] ?>">
                                    <button type="submit" class="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors" title="<?= $t['is_active'] ? 'Desactivar' : 'Activar' ?>">
                                        <?php if ($t['is_active']): ?>
                                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                                        <?php else: ?>
                                            <svg class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                        <?php endif; ?>
                                    </button>
                                </form>
                                <form method="POST" action="<?= base_url('admin/tenant/delete') ?>" class="inline" data-confirm="¿Eliminar este tenant y TODOS sus datos? Esta acción no se puede deshacer." data-confirm-danger>
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="id" value="<?= $t['id'] ?>">
                                    <button type="submit" class="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950 text-gray-400 hover:text-red-600 transition-colors" title="Eliminar">
                                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                                    </button>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
</div>

<!-- Grupos de tenants -->
<?php if (!empty($groups)): ?>
<div class="mt-6">
    <h2 class="text-xl font-bold mb-4">Grupos de tenants</h2>
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <?php foreach ($groups as $g): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-lg bg-brand-100 dark:bg-brand-900 flex items-center justify-center shrink-0">
                        <svg class="w-5 h-5 text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                    </div>
                    <div class="min-w-0">
                        <p class="text-sm font-semibold truncate"><?= e($g['name']) ?></p>
                        <p class="text-xs text-gray-400"><?= $g['tenant_count'] ?> tenants</p>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>
