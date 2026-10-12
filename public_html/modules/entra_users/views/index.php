<?php
/**
 * Vista: Usuarios Entra ID — búsqueda.
 * Variables: $tenants, $selectedTenant, $q, $users, $error
 */
?>
<div class="mb-6 space-y-3">
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
            <label class="block text-xs text-gray-500 mb-1">Buscar usuario</label>
            <input type="text" name="q" value="<?= e($q ?? '') ?>" placeholder="nombre, usuario@dominio o email"
                   class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none w-72">
        </div>
        <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Buscar</button>
        <?php if (!empty($selectedTenant)): ?>
            <a href="<?= base_url('modules/entra_users/risky?tenant=' . (int)$selectedTenant) ?>" class="inline-flex items-center gap-1.5 px-3 py-2 border border-gray-200 dark:border-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                Usuarios en riesgo
            </a>
        <?php endif; ?>
    </form>
</div>

<?php if (!empty($error)): ?>
    <div class="mb-4 px-4 py-3 rounded-lg text-sm text-red-600 bg-red-50 dark:bg-red-900/20"><?= e($error) ?></div>
<?php endif; ?>

<?php if (($q ?? '') === ''): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
        <p class="text-sm text-gray-500">Escribe un nombre, usuario o email para buscar.</p>
    </div>
<?php elseif (empty($users) && empty($error)): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
        <p class="text-sm text-gray-500">Sin resultados para «<?= e($q) ?>».</p>
    </div>
<?php else: ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table class="w-full text-sm">
            <thead>
                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                    <th class="text-left px-4 py-2">Usuario</th>
                    <th class="text-left px-4 py-2">Departamento</th>
                    <th class="text-left px-4 py-2">Empresa</th>
                    <th class="text-left px-4 py-2">Estado</th>
                    <th class="text-right px-4 py-2"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                <?php foreach ($users as $u): ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <td class="px-4 py-2">
                            <p class="font-medium"><?= e($u['displayName'] ?? '—') ?></p>
                            <p class="text-xs text-gray-400 font-mono"><?= e($u['userPrincipalName'] ?? '') ?></p>
                        </td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($u['department'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($u['companyName'] ?? '—') ?></td>
                        <td class="px-4 py-2">
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= !empty($u['accountEnabled']) ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' ?>">
                                <?= !empty($u['accountEnabled']) ? 'Activo' : 'Deshabilitado' ?>
                            </span>
                        </td>
                        <td class="px-4 py-2 text-right">
                            <a href="<?= base_url('modules/entra_users/user/' . rawurlencode((string)$u['id']) . '?tenant=' . (int)$selectedTenant) ?>" class="text-xs text-brand-500 hover:underline">Ver</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>
