<?php
/**
 * Vista: Almacenamiento (BD + disco del hosting + PHP).
 * Variables: $stats, $success, $error
 */
$pageTitle = 'Almacenamiento';
$fb = function ($bytes) {
    $bytes = (float)$bytes;
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($u) - 1) { $bytes /= 1024; $i++; }
    return round($bytes, $i >= 2 ? 1 : 0) . ' ' . $u[$i];
};

$disk = $stats['disk'] ?? ['total' => 0, 'used' => 0, 'free' => 0];
$usedPct = ($disk['total'] > 0) ? round($disk['used'] / $disk['total'] * 100, 1) : 0;
$lowSpace = ($disk['total'] > 0) && ($disk['free'] < max(200 * 1024 * 1024, $disk['total'] * 0.1));
$db = $stats['db'] ?? [];
$tables = $db['tables'] ?? [];
$dirs = $stats['dirs'] ?? [];
$php = $stats['php'] ?? [];
$dbTotal = (int)($db['size'] ?? 0) + (int)($db['wal'] ?? 0) + (int)($db['shm'] ?? 0);
?>
<?php if (!empty($success)): ?><div class="mb-4 px-4 py-3 rounded-lg text-sm text-green-600 bg-green-50 dark:bg-green-900/20"><?= e($success) ?></div><?php endif; ?>
<?php if (!empty($error)): ?><div class="mb-4 px-4 py-3 rounded-lg text-sm text-red-600 bg-red-50 dark:bg-red-900/20"><?= e($error) ?></div><?php endif; ?>

<div class="mb-6 flex items-center justify-between gap-3 flex-wrap">
    <div>
        <h2 class="text-xl font-bold">Almacenamiento</h2>
        <p class="text-xs text-gray-400 mt-1">Ocupación de la base de datos, del disco del hosting y del entorno PHP. Actualizado <?= e(time_ago(gmdate('c', (int)($stats['ts'] ?? time())))) ?>.</p>
    </div>
    <a href="<?= base_url('admin/storage?refresh=1') ?>" class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
        Recalcular
    </a>
</div>

<?php if ($lowSpace): ?>
<div class="mb-6 rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950 px-4 py-3">
    <p class="text-sm text-red-700 dark:text-red-300">⚠️ Poco espacio libre en el disco (<?= e($fb($disk['free'])) ?>). Revisa backups/exportaciones.</p>
</div>
<?php endif; ?>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <!-- Disco -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h3 class="text-sm font-semibold mb-4">Disco (hosting)</h3>
        <?php if (($disk['total'] ?? 0) > 0): ?>
            <div class="h-3 w-full bg-gray-100 dark:bg-gray-800 rounded-full overflow-hidden mb-2">
                <div class="h-full <?= $usedPct >= 90 ? 'bg-red-500' : ($usedPct >= 75 ? 'bg-amber-500' : 'bg-brand-500') ?>" style="width: <?= min(100, $usedPct) ?>%"></div>
            </div>
            <p class="text-xs text-gray-500 mb-4"><?= e($usedPct) ?>% usado</p>
            <dl class="grid grid-cols-3 gap-3 text-sm">
                <div><dt class="text-xs text-gray-500">Total</dt><dd class="font-medium"><?= e($fb($disk['total'])) ?></dd></div>
                <div><dt class="text-xs text-gray-500">Usado</dt><dd class="font-medium"><?= e($fb($disk['used'])) ?></dd></div>
                <div><dt class="text-xs text-gray-500">Libre</dt><dd class="font-medium"><?= e($fb($disk['free'])) ?></dd></div>
            </dl>
        <?php else: ?>
            <p class="text-sm text-gray-500">El hosting no reporta el espacio del disco.</p>
        <?php endif; ?>
    </div>

    <!-- BD -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h3 class="text-sm font-semibold mb-4">Base de datos (SQLite)</h3>
        <p class="text-sm mb-1"><span class="text-gray-500">Tamaño total:</span> <strong><?= e($fb($dbTotal)) ?></strong></p>
        <p class="text-xs text-gray-400 mb-3 font-mono break-all"><?= e($db['path'] ?? '') ?></p>
        <dl class="grid grid-cols-2 gap-3 text-sm">
            <div><dt class="text-xs text-gray-500">BD</dt><dd class="font-medium"><?= e($fb($db['size'] ?? 0)) ?></dd></div>
            <div><dt class="text-xs text-gray-500">WAL</dt><dd class="font-medium"><?= e($fb($db['wal'] ?? 0)) ?></dd></div>
            <div><dt class="text-xs text-gray-500">Tablas</dt><dd class="font-medium"><?= (int)($db['table_count'] ?? 0) ?></dd></div>
            <div><dt class="text-xs text-gray-500">Filas (total)</dt><dd class="font-medium"><?= number_format((int)($db['total_rows'] ?? 0)) ?></dd></div>
            <div><dt class="text-xs text-gray-500">Páginas</dt><dd class="font-medium"><?= number_format((int)($db['page_count'] ?? 0)) ?></dd></div>
            <div><dt class="text-xs text-gray-500">Tamaño página</dt><dd class="font-medium"><?= e($fb($db['page_size'] ?? 0)) ?></dd></div>
        </dl>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <!-- Carpetas -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h3 class="text-sm font-semibold mb-4">Carpetas</h3>
        <div class="divide-y divide-gray-100 dark:divide-gray-700/50 text-sm">
            <?php foreach ($dirs as $label => $size): ?>
                <div class="flex items-center justify-between py-2">
                    <span class="text-gray-600 dark:text-gray-300 font-mono text-xs"><?= e($label) ?></span>
                    <span class="font-medium"><?= e($fb($size)) ?></span>
                </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- PHP -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h3 class="text-sm font-semibold mb-4">Entorno PHP</h3>
        <dl class="grid grid-cols-2 gap-3 text-sm">
            <div><dt class="text-xs text-gray-500">memory_limit</dt><dd class="font-medium"><?= e($php['memory_limit'] ?? '—') ?></dd></div>
            <div><dt class="text-xs text-gray-500">Uso memoria (peak)</dt><dd class="font-medium"><?= e($fb($php['memory_peak'] ?? 0)) ?></dd></div>
            <div><dt class="text-xs text-gray-500">upload_max_filesize</dt><dd class="font-medium"><?= e($php['upload_max_filesize'] ?? '—') ?></dd></div>
            <div><dt class="text-xs text-gray-500">post_max_size</dt><dd class="font-medium"><?= e($php['post_max_size'] ?? '—') ?></dd></div>
            <div><dt class="text-xs text-gray-500">max_execution_time</dt><dd class="font-medium"><?= e($php['max_execution_time'] ?? '—') ?>s</dd></div>
            <div><dt class="text-xs text-gray-500">SAPI</dt><dd class="font-medium font-mono text-xs"><?= e($php['sapi'] ?? '—') ?></dd></div>
            <div><dt class="text-xs text-gray-500">fastcgi_finish_request</dt><dd class="font-medium"><?= !empty($php['fastcgi']) ? 'Sí' : 'No' ?></dd></div>
            <div><dt class="text-xs text-gray-500">Extensiones</dt><dd class="font-medium">
                <?= !empty($php['curl']) ? 'curl ✔' : 'curl ✘' ?> ·
                <?= !empty($php['mbstring']) ? 'mbstring ✔' : 'mbstring ✘' ?> ·
                <?= !empty($php['openssl']) ? 'openssl ✔' : 'openssl ✘' ?>
            </dd></div>
        </dl>
    </div>
</div>

<!-- Tablas -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
        <h3 class="text-sm font-semibold">Tablas (<?= count($tables) ?>)</h3>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-6 max-h-96 overflow-y-auto p-5 text-sm">
        <?php foreach ($tables as $name => $rows): ?>
            <div class="flex items-center justify-between py-1.5 border-b border-gray-50 dark:border-gray-800">
                <span class="font-mono text-xs text-gray-600 dark:text-gray-300 truncate"><?= e($name) ?></span>
                <span class="text-gray-500 shrink-0 ml-2"><?= number_format((int)$rows) ?></span>
            </div>
        <?php endforeach; ?>
    </div>
</div>
