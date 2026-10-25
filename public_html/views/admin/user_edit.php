<?php
/**
 * Vista: Editar usuario existente.
 * Variables: $user, $isSelf, $error
 */
$pageTitle = 'Editar usuario';
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
    <div class="flex items-center gap-3 mb-6">
        <a href="<?= base_url('admin/users') ?>" class="p-2 rounded-lg hover:bg-muted-light dark:hover:bg-muted-dark transition-colors" title="Volver">
            <i class="material-icons icon-20" aria-hidden="true">arrow_back</i>
        </a>
        <div>
            <h1 class="text-xl font-semibold">Editar usuario</h1>
            <p class="text-sm text-ink-muted">
                <span class="font-mono"><?= e($user['username']) ?></span>
                <?= $isSelf ? ' · <span class="text-primary">eres tú</span>' : '' ?>
            </p>
        </div>
    </div>

    <div class="card p-6">
        <form method="POST" action="<?= base_url('admin/user/edit?id=' . (int)$user['id']) ?>" class="space-y-4" onsubmit="var p=this.password.value, c=this.password_confirm.value; if (p && p!==c) { toast('La nueva contraseña y su confirmación no coinciden', 'error'); return false; }">
            <?= Csrf::field() ?>

            <div>
                <label class="block text-sm font-medium text-ink mb-1">Usuario *</label>
                <input type="text" name="username" required value="<?= e($user['username']) ?>"
                       pattern="[a-zA-Z0-9._\-]{3,40}" title="3-40 caracteres: letras, números, . _ -"
                       class="w-full px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                <p class="text-xs text-ink-soft mt-1">3-40 caracteres (letras, números, . _ -). Debe ser único.</p>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm font-medium text-ink mb-1">Email *</label>
                    <input type="email" name="email" required value="<?= e($user['email']) ?>"
                           class="w-full px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                </div>
                <div>
                    <label class="block text-sm font-medium text-ink mb-1">Nombre visible</label>
                    <input type="text" name="display_name" value="<?= e($user['display_name'] ?? '') ?>"
                           class="w-full px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                </div>
            </div>

            <div>
                <label class="block text-sm font-medium text-ink mb-1">Rol</label>
                <?php if ($isSelf): ?>
                    <input type="hidden" name="role" value="<?= e($user['role']) ?>">
                    <input type="text" value="<?= e($user['role']) ?>" disabled
                           class="w-full px-3 py-2 rounded-lg border border-line bg-muted text-ink-muted text-sm">
                    <p class="text-xs text-ink-soft mt-1">No puedes cambiar tu propio rol.</p>
                <?php else: ?>
                    <select name="role"
                            class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                        <option value="user" <?= $user['role'] === 'user' ? 'selected' : '' ?>>Usuario</option>
                        <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>Administrador</option>
                    </select>
                <?php endif; ?>
            </div>

            <div class="pt-2 border-t border-line-subtle">
                <p class="text-sm font-semibold mb-3">Contraseña</p>

                <?php if ($isSelf): ?>
                    <div class="mb-4">
                        <label class="block text-sm font-medium text-ink mb-1">Tu contraseña actual *</label>
                        <input type="password" name="current_password" required autocomplete="current-password"
                               class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                        <p class="text-xs text-ink-soft mt-1">Requerida como verificación para editar tus propios datos.</p>
                    </div>
                <?php endif; ?>

                <div class="mb-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-ink mb-1">
                            <?= $isSelf ? 'Nueva contraseña (opcional)' : 'Establecer nueva contraseña (opcional)' ?>
                        </label>
                        <input type="password" name="password" minlength="8" autocomplete="new-password" placeholder="Dejar vacío para mantener la actual"
                               class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-ink mb-1">Repetir nueva contraseña</label>
                        <input type="password" name="password_confirm" minlength="8" autocomplete="new-password" placeholder="Repite la nueva contraseña"
                               class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                    </div>
                </div>
                <?php if (!$isSelf): ?>
                    <p class="text-xs text-ink-soft -mt-2 mb-4">Si la estableces, el usuario deberá cambiarla en su próximo inicio de sesión.</p>
                <?php endif; ?>

                <?php if (!$isSelf): ?>
                    <div class="flex items-center gap-2">
                        <input type="checkbox" name="must_change_password" id="mcp" value="1"
                               <?= !empty($user['must_change_password']) ? 'checked' : '' ?>
                               class="rounded border-line-strong text-brand-500 focus:ring-brand-500">
                        <label for="mcp" class="text-sm text-ink">Debe cambiar su contraseña en el próximo login</label>
                    </div>
                <?php endif; ?>
            </div>

            <div class="flex items-center gap-3 pt-4 border-t border-line-subtle">
                <button type="submit" class="btn">
                    Guardar cambios
                </button>
                <a href="<?= base_url('admin/users') ?>" class="px-4 py-2 bg-muted hover:bg-surface-3 text-ink text-sm font-medium rounded-lg transition-colors">
                    Cancelar
                </a>
            </div>
        </form>
    </div>
</div>
