<?php
/**
 * Vista: usuarios en riesgo (Identity Protection).
 * Variables: $tenants, $selectedTenant, $users, $error
 */
?>
<div class="mb-6 space-y-3">
    <div class="flex items-center gap-3">
        <a href="<?= base_url('modules/entra_users?tenant=' . (int)$selectedTenant) ?>" class="text-xs text-brand-500 hover:underline">← Volver</a>
        <h1 class="text-lg font-semibold">Usuarios en riesgo <span class="text-gray-400 font-normal">(Entra ID Identity Protection)</span></h1>
    </div>
    <form method="GET" class="flex items-end gap-3 flex-wrap">
        <div>
            <label class="block text-xs text-gray-500 mb-1">Tenant</label>
            <select name="tenant" onchange="this.form.submit()"
                    class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <?php foreach ($tenants as $t): ?>
                    <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
    </form>
</div>

<?php if (!empty($error)): ?>
    <div class="mb-4 px-4 py-3 rounded-lg text-sm text-red-600 bg-red-50 dark:bg-red-900/20">
        No se pudieron obtener los usuarios en riesgo: <?= e($error) ?><br>
        <span class="text-xs text-gray-500">Requiere el permiso <code>IdentityRiskyUser.Read.All</code> y licencia <strong>Entra ID P2</strong>.</span>
    </div>
<?php endif; ?>

<?php if (empty($error) && empty($users)): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
        <p class="text-sm text-gray-500">No hay usuarios en riesgo ahora mismo.</p>
    </div>
<?php elseif (!empty($users)): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table class="w-full text-sm">
            <thead>
                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                    <th class="text-left px-4 py-2">Usuario</th>
                    <th class="text-left px-4 py-2">Nivel</th>
                    <th class="text-left px-4 py-2">Estado</th>
                    <th class="text-left px-4 py-2">Detalle</th>
                    <th class="text-left px-4 py-2">Actualizado</th>
                    <th class="text-right px-4 py-2"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                <?php foreach ($users as $u): ?>
                    <?php
                    $rl = strtolower((string)($u['riskLevel'] ?? ''));
                    $rlClass = $rl === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                        : ($rl === 'medium' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'
                        : ($rl === 'low' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                        : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'));
                    ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <td class="px-4 py-2">
                            <p class="font-medium"><?= e($u['userDisplayName'] ?? '—') ?></p>
                            <p class="text-xs text-gray-400 font-mono"><?= e($u['userPrincipalName'] ?? '') ?></p>
                        </td>
                        <td class="px-4 py-2"><span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $rlClass ?>"><?= e($u['riskLevel'] ?? '—') ?></span></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($u['riskState'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($u['riskDetail'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= !empty($u['riskLastUpdatedDateTime']) ? format_date($u['riskLastUpdatedDateTime']) : '—' ?></td>
                        <td class="px-4 py-2 text-right">
                            <a href="<?= base_url('modules/entra_users/user/' . rawurlencode((string)($u['id'] ?? '')) . '?tenant=' . (int)$selectedTenant) ?>" class="text-xs text-brand-500 hover:underline">Ver</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>
