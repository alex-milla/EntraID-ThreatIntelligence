<?php
/**
 * Vista: Usuarios Entra ID — búsqueda.
 * Variables: $tenants, $selectedTenant, $q, $users, $error
 */
?>
<div class="mb-6 space-y-3">
    <form method="GET" class="flex items-end gap-3 flex-wrap">
        <div>
            <label class="block text-xs text-ink-muted mb-1">Tenant</label>
            <select name="tenant" onchange="this.form.submit()"
                    class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                <?php foreach ($tenants as $t): ?>
                    <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label class="block text-xs text-ink-muted mb-1">Buscar usuario</label>
            <input type="text" name="q" value="<?= e($q ?? '') ?>" placeholder="nombre, usuario@dominio o email"
                   class="px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none w-72">
        </div>
        <button type="submit" class="btn">Buscar</button>
        <?php if (!empty($selectedTenant)): ?>
            <a href="<?= base_url('modules/entra_users/risky?tenant=' . (int)$selectedTenant) ?>" class="inline-flex items-center gap-1.5 px-3 py-2 border border-line text-sm font-medium rounded-lg hover:bg-muted transition-colors">
                <i class="material-icons icon-16" aria-hidden="true">warning</i>
                Usuarios en riesgo
            </a>
        <?php endif; ?>
    </form>
</div>

<?php if (!empty($error)): ?>
    <div class="alert alert-error"><?= e($error) ?></div>
<?php endif; ?>

<?php if (($q ?? '') === ''): ?>
    <div class="card p-8 text-center">
        <p class="text-sm text-ink-muted">Escribe un nombre, usuario o email para buscar.</p>
    </div>
<?php elseif (empty($users) && empty($error)): ?>
    <div class="card p-8 text-center">
        <p class="text-sm text-ink-muted">Sin resultados para «<?= e($q) ?>».</p>
    </div>
<?php else: ?>
    <div class="card overflow-hidden">
        <table class="data-table w-full text-sm">
            <thead>
                <tr class="border-b border-line bg-muted text-xs text-ink-muted uppercase">
                    <th class="text-left px-4 py-2">Usuario</th>
                    <th class="text-left px-4 py-2">Departamento</th>
                    <th class="text-left px-4 py-2">Empresa</th>
                    <th class="text-left px-4 py-2">Estado</th>
                    <th class="text-right px-4 py-2"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-line-subtle">
                <?php foreach ($users as $u): ?>
                    <tr class="hover:bg-muted">
                        <td class="px-4 py-2">
                            <p class="font-medium"><?= e($u['displayName'] ?? '—') ?></p>
                            <p class="text-xs text-ink-soft font-mono"><?= e($u['userPrincipalName'] ?? '') ?></p>
                        </td>
                        <td class="px-4 py-2 text-xs text-ink-muted"><?= e($u['department'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-xs text-ink-muted"><?= e($u['companyName'] ?? '—') ?></td>
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
