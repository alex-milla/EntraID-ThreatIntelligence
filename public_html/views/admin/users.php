<?php
/**
 * Vista: Gestión de usuarios.
 */
$pageTitle = 'Usuarios';
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

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Crear usuario -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6">
        <h2 class="text-lg font-semibold mb-4">Nuevo usuario</h2>
        <form method="POST" action="<?= base_url('admin/user/create') ?>" class="space-y-4" onsubmit="if (this.password.value !== this.password_confirm.value) { alert('La contraseña y su confirmación no coinciden'); return false; }">
            <?= Csrf::field() ?>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Usuario *</label>
                <input type="text" name="username" required class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Email *</label>
                <input type="email" name="email" required class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Nombre</label>
                <input type="text" name="display_name" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Contraseña *</label>
                <input type="password" name="password" required minlength="8" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Repetir contraseña *</label>
                <input type="password" name="password_confirm" required minlength="8" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Rol</label>
                <select name="role" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                    <option value="user">Usuario</option>
                    <option value="admin">Administrador</option>
                </select>
            </div>
            <div class="flex items-center gap-2">
                <input type="checkbox" name="must_change_password" id="mcp" value="1" checked class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                <label for="mcp" class="text-sm text-gray-700 dark:text-gray-300">Debe cambiar contraseña</label>
            </div>
            <button type="submit" class="w-full px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                Crear usuario
            </button>
        </form>
    </div>

    <!-- Lista de usuarios -->
    <div class="lg:col-span-2 bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-sm font-semibold">Usuarios existentes</h2>
        </div>
        <table class="w-full">
            <thead>
                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
                    <th class="text-left px-4 py-3 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase">Usuario</th>
                    <th class="text-left px-4 py-3 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase">Rol</th>
                    <th class="text-left px-4 py-3 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase">Último acceso</th>
                    <th class="text-right px-4 py-3 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase">Acciones</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                <?php foreach ($users as $u): ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <td class="px-4 py-3">
                            <p class="text-sm font-medium"><?= e($u['display_name'] ?: $u['username']) ?></p>
                            <p class="text-xs text-gray-400"><?= e($u['email']) ?></p>
                        </td>
                        <td class="px-4 py-3">
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $u['role'] === 'admin' ? 'bg-brand-100 dark:bg-brand-900 text-brand-700 dark:text-brand-300' : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400' ?>">
                                <?= e($u['role']) ?>
                            </span>
                        </td>
                        <td class="px-4 py-3 text-sm text-gray-500"><?= $u['last_login_at'] ? time_ago($u['last_login_at']) : 'Nunca' ?></td>
                        <td class="px-4 py-3 text-right">
                            <a href="<?= base_url('admin/user/edit?id=' . (int)$u['id']) ?>"
                               class="inline-flex p-1.5 rounded-lg hover:bg-brand-50 dark:hover:bg-brand-950 text-gray-400 hover:text-brand-600 transition-colors"
                               title="Editar usuario">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                            </a>
                            <?php if ($u['id'] !== Auth::id()): ?>
                                <form method="POST" action="<?= base_url('admin/user/delete') ?>" class="inline" onsubmit="return confirm('¿Eliminar este usuario?')">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="id" value="<?= $u['id'] ?>">
                                    <button type="submit" class="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950 text-gray-400 hover:text-red-600 transition-colors">
                                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                                    </button>
                                </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
