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
        'success' => 'alert-success',
        'error'   => 'alert-error',
        default   => 'alert-info',
    };
?>
    <div class="alert <?= $colors ?>"><?= e($msg) ?></div>
<?php endforeach; ?>

<div class="flex items-center justify-between mb-6">
    <h2 class="text-xl font-bold">Tenants</h2>
    <a href="<?= base_url('admin/tenant/edit') ?>" class="btn">
        <i class="material-icons icon-16" aria-hidden="true">add</i>
        Nuevo tenant
    </a>
</div>

<!-- Tabla de tenants -->
<div class="card overflow-hidden">
    <table class="data-table w-full">
        <thead>
            <tr class="border-b border-line bg-muted">
                <th class="text-left px-4 py-3 text-xs font-medium text-ink-muted uppercase tracking-wider">Nombre</th>
                <th class="text-left px-4 py-3 text-xs font-medium text-ink-muted uppercase tracking-wider">Tenant ID</th>
                <th class="text-left px-4 py-3 text-xs font-medium text-ink-muted uppercase tracking-wider">Estado</th>
                <th class="text-left px-4 py-3 text-xs font-medium text-ink-muted uppercase tracking-wider">Última sync</th>
                <th class="text-right px-4 py-3 text-xs font-medium text-ink-muted uppercase tracking-wider">Acciones</th>
            </tr>
        </thead>
        <tbody class="divide-y divide-line-subtle">
            <?php if (empty($tenants)): ?>
                <tr><td colspan="5" class="px-4 py-8 text-sm text-ink-muted text-center">No hay tenants configurados</td></tr>
            <?php else: ?>
                <?php foreach ($tenants as $t): ?>
                    <tr class="hover:bg-muted transition-colors">
                        <td class="px-4 py-3">
                            <p class="text-sm font-medium"><?= e($t['name']) ?></p>
                            <p class="text-xs text-ink-soft font-mono"><?= e($t['slug']) ?></p>
                        </td>
                        <td class="px-4 py-3 text-sm font-mono text-ink-muted"><?= e(truncate($t['tenant_id'], 20)) ?></td>
                        <td class="px-4 py-3">
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $t['is_active'] ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400' ?>">
                                <?= $t['is_active'] ? 'Activo' : 'Inactivo' ?>
                            </span>
                        </td>
                        <td class="px-4 py-3 text-sm text-ink-muted"><?= $t['last_sync_at'] ? time_ago($t['last_sync_at']) : '—' ?></td>
                        <td class="px-4 py-3 text-right">
                            <div class="flex items-center justify-end gap-1">
                                <a href="<?= base_url('admin/tenant/edit?id=' . $t['id']) ?>" class="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-ink-muted hover:text-gray-700 dark:hover:text-gray-300 transition-colors" title="Editar">
                                    <i class="material-icons icon-16" aria-hidden="true">edit</i>
                                </a>
                                <form method="POST" action="<?= base_url('admin/tenant/toggle') ?>" class="inline">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="id" value="<?= $t['id'] ?>">
                                    <button type="submit" class="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-ink-muted hover:text-gray-700 dark:hover:text-gray-300 transition-colors" title="<?= $t['is_active'] ? 'Desactivar' : 'Activar' ?>">
                                        <?php if ($t['is_active']): ?>
                                            <i class="material-icons icon-16" aria-hidden="true">block</i>
                                        <?php else: ?>
                                            <i class="material-icons icon-16 text-green-500" aria-hidden="true">check_circle</i>
                                        <?php endif; ?>
                                    </button>
                                </form>
                                <form method="POST" action="<?= base_url('admin/tenant/delete') ?>" class="inline" data-confirm="¿Eliminar este tenant y TODOS sus datos? Esta acción no se puede deshacer." data-confirm-danger>
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="id" value="<?= $t['id'] ?>">
                                    <button type="submit" class="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950 text-ink-soft hover:text-red-600 transition-colors" title="Eliminar">
                                        <i class="material-icons icon-16" aria-hidden="true">delete</i>
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
            <div class="card p-4">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-lg bg-brand-100 dark:bg-brand-900 flex items-center justify-center shrink-0">
                        <i class="material-icons icon-20 text-brand-500" aria-hidden="true">group</i>
                    </div>
                    <div class="min-w-0">
                        <p class="text-sm font-semibold truncate"><?= e($g['name']) ?></p>
                        <p class="text-xs text-ink-soft"><?= $g['tenant_count'] ?> tenants</p>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>
