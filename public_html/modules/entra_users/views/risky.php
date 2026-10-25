<?php
/**
 * Vista: usuarios en riesgo (Identity Protection).
 * Variables: $tenants, $selectedTenant, $users, $error
 */
?>
<div class="mb-6 space-y-3">
    <div class="flex items-center gap-3">
        <a href="<?= base_url('modules/entra_users?tenant=' . (int)$selectedTenant) ?>" class="text-xs text-brand-500 hover:underline">← Volver</a>
        <h1 class="text-lg font-semibold">Usuarios en riesgo <span class="text-ink-soft font-normal">(Entra ID Identity Protection)</span></h1>
    </div>
    <form method="GET" class="flex items-end gap-3 flex-wrap">
        <div>
            <label class="block text-xs text-ink-muted mb-1">Tenant</label>
            <select name="tenant" onchange="this.form.submit()"
                    class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <?php foreach ($tenants as $t): ?>
                    <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
    </form>
</div>

<?php if (!empty($error)): ?>
    <div class="alert alert-error">
        No se pudieron obtener los usuarios en riesgo: <?= e($error) ?><br>
        <span class="text-xs text-ink-muted">Requiere el permiso <code>IdentityRiskyUser.Read.All</code> y licencia <strong>Entra ID P2</strong>.</span>
    </div>
<?php endif; ?>

<?php if (empty($error) && empty($users)): ?>
    <div class="card p-8 text-center">
        <p class="text-sm text-ink-muted">No hay usuarios en riesgo ahora mismo.</p>
    </div>
<?php elseif (!empty($users)): ?>
    <div class="card overflow-hidden">
        <table class="data-table w-full text-sm">
            <thead>
                <tr class="border-b border-line bg-muted text-xs text-ink-muted uppercase">
                    <th class="text-left px-4 py-2">Usuario</th>
                    <th class="text-left px-4 py-2">Nivel</th>
                    <th class="text-left px-4 py-2">Estado</th>
                    <th class="text-left px-4 py-2">Detalle</th>
                    <th class="text-left px-4 py-2">Actualizado</th>
                    <th class="text-right px-4 py-2"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-line-subtle">
                <?php foreach ($users as $u): ?>
                    <?php
                    $rl = strtolower((string)($u['riskLevel'] ?? ''));
                    $rlClass = $rl === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                        : ($rl === 'medium' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'
                        : ($rl === 'low' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                        : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'));
                    ?>
                    <tr class="hover:bg-muted">
                        <td class="px-4 py-2">
                            <p class="font-medium"><?= e($u['userDisplayName'] ?? '—') ?></p>
                            <p class="text-xs text-ink-soft font-mono"><?= e($u['userPrincipalName'] ?? '') ?></p>
                        </td>
                        <td class="px-4 py-2"><span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $rlClass ?>"><?= e($u['riskLevel'] ?? '—') ?></span></td>
                        <td class="px-4 py-2 text-xs text-ink-muted"><?= e($u['riskState'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-xs text-ink-muted"><?= e($u['riskDetail'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-xs text-ink-muted"><?= !empty($u['riskLastUpdatedDateTime']) ? format_date($u['riskLastUpdatedDateTime']) : '—' ?></td>
                        <td class="px-4 py-2 text-right">
                            <a href="<?= base_url('modules/entra_users/user/' . rawurlencode((string)($u['id'] ?? '')) . '?tenant=' . (int)$selectedTenant) ?>" class="text-xs text-brand-500 hover:underline">Ver</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>
