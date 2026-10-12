<?php
/**
 * Vista: Gestión de módulos.
 */
$pageTitle = 'Módulos';
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

<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
    <?php foreach ($allModules as $mod): ?>
        <div class="bg-white dark:bg-surface-dark rounded-xl border <?= $mod['is_active'] ? 'border-brand-300 dark:border-brand-700' : 'border-gray-200 dark:border-gray-700' ?> p-5">
            <div class="flex items-start justify-between gap-3">
                <div class="min-w-0">
                    <h3 class="text-sm font-semibold"><?= e($mod['name']) ?></h3>
                    <p class="text-xs text-gray-400 font-mono mt-0.5"><?= e($mod['module_key']) ?> v<?= e($mod['version']) ?></p>
                </div>
                <span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 <?= $mod['is_active'] ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400' ?>">
                    <?= $mod['is_active'] ? 'Activo' : 'Inactivo' ?>
                </span>
            </div>
            <p class="text-sm text-gray-500 mt-2 line-clamp-2"><?= e($mod['description'] ?? '') ?></p>
            <form method="POST" action="<?= base_url('admin/module/toggle') ?>" class="mt-4">
                <?= Csrf::field() ?>
                <input type="hidden" name="module_key" value="<?= e($mod['module_key']) ?>">
                <input type="hidden" name="action" value="<?= $mod['is_active'] ? 'deactivate' : 'activate' ?>">
                <button type="submit" class="w-full px-4 py-2 text-sm font-medium rounded-lg transition-colors <?= $mod['is_active'] ? 'border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark' : 'bg-brand-500 hover:bg-brand-600 text-white' ?>">
                    <?= $mod['is_active'] ? 'Desactivar' : 'Activar' ?>
                </button>
            </form>
        </div>
    <?php endforeach; ?>
</div>
