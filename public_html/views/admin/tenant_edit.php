<?php
/**
 * Vista: Editar/Crear tenant.
 * IMPORTANTE: el client_secret se envía por POST y se cifra en el servidor.
 * Nunca se muestra el secret almacenado.
 */
$pageTitle = $isEdit ? 'Editar Tenant' : 'Nuevo Tenant';
?>

<?php
$flashData = flash();
foreach ($flashData as $type => $msg):
    $colors = match($type) {
        'success' => 'text-green-600 bg-green-50 dark:bg-green-900/20',
        'error'   => 'text-red-600 bg-red-50 dark:bg-red-900/20',
        default   => 'text-blue-600 bg-blue-50 dark:bg-blue-900/20',
    };
?>
    <div class="mb-4 px-4 py-3 rounded-lg text-sm <?= $colors ?>"><?= e($msg) ?></div>
<?php endforeach; ?>

<div class="max-w-2xl">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6">
        <h2 class="text-lg font-semibold mb-6"><?= $isEdit ? 'Editar tenant: ' . e($tenant['name']) : 'Nuevo tenant' ?></h2>

        <form method="POST" action="<?= base_url('admin/tenant/edit' . ($isEdit ? '?id=' . $tenant['id'] : '')) ?>" class="space-y-4">
            <?= Csrf::field() ?>

            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Nombre *</label>
                <input type="text" name="name" required value="<?= e($isEdit ? $tenant['name'] : (old_input('name') ?? '')) ?>"
                       placeholder="Tenant-empresa-Pepito"
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                <p class="text-xs text-gray-400 mt-1">Ej: Tenant-empresa-Pepito, tenants-empresa-Javito</p>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Slug</label>
                <input type="text" name="slug" value="<?= e($isEdit ? $tenant['slug'] : (old_input('slug') ?? '')) ?>"
                       placeholder="Se genera automáticamente"
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none font-mono text-sm">
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Tenant ID (Directory ID) *</label>
                    <input type="text" name="tenant_id" required value="<?= e($isEdit ? $tenant['tenant_id'] : (old_input('tenant_id') ?? '')) ?>"
                           placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                           class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none font-mono text-sm">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Client ID (Application ID) *</label>
                    <input type="text" name="client_id" required value="<?= e($isEdit ? $tenant['client_id'] : (old_input('client_id') ?? '')) ?>"
                           placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                           class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none font-mono text-sm">
                </div>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Client Secret (Value) <?= $isEdit ? '' : '*' ?>
                </label>
                <input type="password" name="client_secret" <?= $isEdit ? '' : 'required' ?> autocomplete="new-password"
                       placeholder="<?= $isEdit ? 'Dejar en blanco para mantener el actual' : 'Pega el Value del secret (no el Secret ID)' ?>"
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none font-mono text-sm">
                <p class="text-xs text-amber-500 mt-1">
                    <svg class="w-3 h-3 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    El secret se cifra con AES-256 antes de almacenarse. Nunca se guarda en texto plano.
                </p>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Permisos de Microsoft Graph</label>
                <div class="space-y-2">
                    <?php
                    $currentPerms = $isEdit ? safe_json_decode($tenant['permissions'], []) : [];
                    foreach (GRAPH_PERMISSIONS as $perm => $desc):
                    ?>
                        <label class="flex items-start gap-3 p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer transition-colors">
                            <input type="checkbox" name="permissions[]" value="<?= e($perm) ?>"
                                   <?= in_array($perm, $currentPerms, true) ? 'checked' : '' ?>
                                   class="mt-0.5 rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                            <div>
                                <p class="text-sm font-mono font-medium"><?= e($perm) ?></p>
                                <p class="text-xs text-gray-500"><?= e($desc) ?></p>
                            </div>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>

            <?php if (!empty($groups)): ?>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Grupos (multitenant)</label>
                <div class="flex flex-wrap gap-2">
                    <?php foreach ($groups as $g): ?>
                        <label class="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors text-sm">
                            <input type="checkbox" name="groups[]" value="<?= $g['id'] ?>"
                                   <?= in_array($g['id'], $tenantGroupIds, true) ? 'checked' : '' ?>
                                   class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                            <?= e($g['name']) ?>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>

            <div class="flex items-center gap-2">
                <input type="checkbox" name="is_active" id="is_active" value="1" <?= (!$isEdit || $tenant['is_active']) ? 'checked' : '' ?>
                       class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                <label for="is_active" class="text-sm text-gray-700 dark:text-gray-300">Tenant activo</label>
            </div>

            <div class="flex gap-3 pt-2">
                <a href="<?= base_url('admin/tenants') ?>" class="flex-1 px-4 py-2 border border-gray-200 dark:border-gray-700 text-center text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                    Cancelar
                </a>
                <button type="submit" class="flex-1 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                    <?= $isEdit ? 'Guardar cambios' : 'Crear tenant' ?>
                </button>
            </div>
        </form>
    </div>
</div>
