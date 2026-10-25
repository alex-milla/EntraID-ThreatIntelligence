<?php
/**
 * Vista: Cambio de contraseña obligatorio.
 */
$pageTitle = 'Cambiar contraseña';
?>

<?php
$flashData = flash();
foreach ($flashData as $type => $msg):
    $colors = match($type) {
        'success' => 'text-green-600 bg-green-50 dark:bg-green-900/20',
        'error'   => 'text-red-600 bg-red-50 dark:bg-red-900/20',
        default   => 'text-amber-600 bg-amber-50 dark:bg-amber-900/20',
    };
?>
    <div class="mb-4 px-4 py-3 rounded-lg text-sm <?= $colors ?>"><?= e($msg) ?></div>
<?php endforeach; ?>

<div class="max-w-md mx-auto">
    <div class="card p-6">
        <div class="flex items-center gap-3 mb-6">
            <div class="w-10 h-10 rounded-lg bg-warning-bg flex items-center justify-center">
                <i class="material-icons icon-20 text-warning" aria-hidden="true">warning</i>
            </div>
            <div>
                <h2 class="text-lg font-semibold">Cambio de contraseña requerido</h2>
                <p class="text-sm text-ink-muted">Debes cambiar tu contraseña antes de continuar.</p>
            </div>
        </div>

        <form method="POST" action="<?= base_url('admin/change-password') ?>" class="space-y-4" onsubmit="if (this.new_password.value !== this.new_password_confirm.value) { toast('La nueva contraseña y su confirmación no coinciden', 'error'); return false; }">
            <?= Csrf::field() ?>
            <div>
                <label class="block text-sm font-medium text-ink mb-1">Contraseña actual</label>
                <input type="password" name="current_password" required class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            </div>
            <div>
                <label class="block text-sm font-medium text-ink mb-1">Nueva contraseña</label>
                <input type="password" name="new_password" required minlength="8" class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                <p class="text-xs text-ink-soft mt-1">Mínimo 8 caracteres</p>
            </div>
            <div>
                <label class="block text-sm font-medium text-ink mb-1">Repetir nueva contraseña</label>
                <input type="password" name="new_password_confirm" required minlength="8" class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            </div>
            <button type="submit" class="btn w-full">
                Cambiar contraseña
            </button>
        </form>
    </div>
</div>
