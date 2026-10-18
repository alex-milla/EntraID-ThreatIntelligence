<?php
/**
 * Vista: Logs y diagnóstico del sistema.
 * Variables: $source, $sources, $fileInfo, $level, $channel, $q, $page, $pages,
 *            $total, $entriesPage, $counts, $diag, $llmProfiles, $llmTaskProfile,
 *            $llmConfigured, $jobs, $jobCounts, $success, $error.
 */

$fb = function ($bytes) {
    $bytes = (float)$bytes;
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return round($bytes, $i >= 2 ? 1 : 0) . ' ' . $units[$i];
};

$source = (string)($source ?? 'app');
$level = (string)($level ?? '');
$channel = (string)($channel ?? '');
$q = (string)($q ?? '');
$page = (int)($page ?? 1);
$pages = (int)($pages ?? 1);
$total = (int)($total ?? 0);
$entriesPage = is_array($entriesPage ?? null) ? $entriesPage : [];
$counts = is_array($counts ?? null) ? $counts : ['error' => 0, 'warning' => 0, 'info' => 0];
$diag = is_array($diag ?? null) ? $diag : [];
$jobs = is_array($jobs ?? null) ? $jobs : [];
$jobCounts = is_array($jobCounts ?? null) ? $jobCounts : [];
$llmProfiles = is_array($llmProfiles ?? null) ? $llmProfiles : [];
$sources = is_array($sources ?? null) ? $sources : [];
$fileInfo = is_array($fileInfo ?? null) ? $fileInfo : [];

$link = function (array $over = []) use ($source, $level, $channel, $q, $page): string {
    $params = array_merge([
        'source'  => $source,
        'level'   => $level,
        'channel' => $channel,
        'q'       => $q,
        'page'    => $page,
    ], $over);
    $params = array_filter($params, static fn($v) => $v !== '' && $v !== null && $v !== 0);
    return base_url('admin/logs' . ($params !== [] ? '?' . http_build_query($params) : ''));
};

$levelClasses = [
    'error'   => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'warning' => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    'info'    => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
];
$levelLabels = ['error' => 'Error', 'warning' => 'Aviso', 'info' => 'Info'];
$jobClasses = [
    'pending' => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
    'running' => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    'done'    => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'error'   => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
];
$jobLabels = ['pending' => 'En cola', 'running' => 'Generando', 'done' => 'Listo', 'error' => 'Error'];
$ext = is_array($diag['ext'] ?? null) ? $diag['ext'] : [];
?>

<?php if (!empty($success)): ?><div class="mb-4 px-4 py-3 rounded-lg text-sm text-green-600 bg-green-50 dark:bg-green-900/20"><?= e($success) ?></div><?php endif; ?>
<?php if (!empty($error)): ?><div class="mb-4 px-4 py-3 rounded-lg text-sm text-red-600 bg-red-50 dark:bg-red-900/20"><?= e($error) ?></div><?php endif; ?>

<div class="mb-6 flex items-start justify-between gap-4 flex-wrap">
    <div>
        <h2 class="text-xl font-bold">Logs</h2>
        <p class="text-xs text-gray-400 mt-1">
            Errores PHP, actividad de usuarios y trazas de la aplicación. Se leen como máximo los últimos 1 MB de cada fichero.
        </p>
    </div>
    <div class="flex items-center gap-2 flex-wrap">
        <a href="<?= base_url('admin/logs/download?source=' . rawurlencode($source)) ?>"
           class="px-3 py-2 border border-gray-200 dark:border-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
            Descargar
        </a>
        <form method="POST" action="<?= base_url('admin/logs/clear') ?>" class="inline"
              data-confirm="¿Vaciar este log? El fichero actual se conserva como .1" data-confirm-danger>
            <?= Csrf::field() ?>
            <input type="hidden" name="source" value="<?= e($source) ?>">
            <button type="submit"
                    class="px-3 py-2 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 text-sm font-medium rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors">
                Vaciar
            </button>
        </form>
    </div>
</div>

<!-- Fuentes -->
<div class="flex items-center gap-2 flex-wrap mb-4">
    <?php foreach (($sources ?? []) as $key => $meta): ?>
        <?php $info = $fileInfo[$key] ?? ['size' => 0, 'mtime' => 0, 'exists' => false]; ?>
        <a href="<?= $link(['source' => $key, 'page' => 1]) ?>"
           class="px-3 py-2 rounded-lg text-xs font-medium border transition-colors <?= $source === $key
               ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300 border-brand-200 dark:border-brand-900'
               : 'bg-white dark:bg-surface-dark text-gray-600 dark:text-gray-400 border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark' ?>">
            <?= e($meta['label']) ?>
            <span class="ml-1 text-[10px] text-gray-400">
                <?= $info['exists'] ? e($fb($info['size'])) : 'sin fichero' ?>
            </span>
        </a>
    <?php endforeach; ?>
</div>

<!-- Filtros -->
<form method="GET" action="<?= base_url('admin/logs') ?>" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4 mb-4">
    <input type="hidden" name="source" value="<?= e($source) ?>">
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <label class="block">
            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Nivel</span>
            <select name="level" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="">Todos</option>
                <option value="error" <?= $level === 'error' ? 'selected' : '' ?>>Error</option>
                <option value="warning" <?= $level === 'warning' ? 'selected' : '' ?>>Aviso</option>
                <option value="info" <?= $level === 'info' ? 'selected' : '' ?>>Info</option>
            </select>
        </label>
        <label class="block">
            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Canal</span>
            <input type="text" name="channel" value="<?= e($channel) ?>" placeholder="cve_ai, llm, admin…"
                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
        </label>
        <label class="block lg:col-span-2">
            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Buscar</span>
            <div class="flex gap-2">
                <input type="text" name="q" value="<?= e($q) ?>" placeholder="texto, CVE, mensaje…"
                       class="flex-1 px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <button type="submit" class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">Filtrar</button>
                <a href="<?= $link(['level' => '', 'channel' => '', 'q' => '', 'page' => 1]) ?>"
                   class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Limpiar</a>
            </div>
        </label>
    </div>
</form>

<!-- Resumen -->
<div class="flex items-center justify-between gap-3 flex-wrap mb-3 text-xs text-gray-500">
    <div class="flex items-center gap-2 flex-wrap">
        <span><?= number_format($total) ?> entradas</span>
        <span class="px-2 py-0.5 rounded-full <?= $levelClasses['error'] ?>"><?= number_format((int)($counts['error'] ?? 0)) ?> errores</span>
        <span class="px-2 py-0.5 rounded-full <?= $levelClasses['warning'] ?>"><?= number_format((int)($counts['warning'] ?? 0)) ?> avisos</span>
        <span class="px-2 py-0.5 rounded-full <?= $levelClasses['info'] ?>"><?= number_format((int)($counts['info'] ?? 0)) ?> info</span>
    </div>
    <?php $info = $fileInfo[$source] ?? null; ?>
    <?php if ($info && $info['exists']): ?>
        <span>Actualizado <?= e(format_date(date('c', (int)$info['mtime']), 'd/m/Y H:i')) ?></span>
    <?php endif; ?>
</div>

<!-- Entradas -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden mb-6">
    <?php if ($entriesPage === []): ?>
        <div class="p-8 text-center text-sm text-gray-500">
            No hay entradas que coincidan con los filtros.
        </div>
    <?php else: ?>
        <div class="divide-y divide-gray-100 dark:divide-gray-800">
            <?php foreach ($entriesPage as $entry): ?>
                <?php
                $ctx = $entry['context'];
                $ctxText = '';
                if (is_array($ctx) && $ctx !== []) {
                    $ctxText = (string)json_encode($ctx, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                } elseif (is_string($ctx)) {
                    $ctxText = $ctx;
                }
                $entryLevel = (string)($entry['level'] ?? 'info');
                ?>
                <div class="px-4 py-3">
                    <div class="flex items-start gap-3 flex-wrap">
                        <span class="text-[10px] px-2 py-0.5 rounded-full <?= $levelClasses[$entryLevel] ?? $levelClasses['info'] ?>">
                            <?= e($levelLabels[$entryLevel] ?? $entryLevel) ?>
                        </span>
                        <span class="text-[10px] font-mono text-gray-400">
                            <?= (int)($entry['ts'] ?? 0) > 0 ? e(date('d/m/Y H:i:s', (int)$entry['ts'])) : '—' ?>
                        </span>
                        <span class="text-[10px] px-2 py-0.5 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 font-mono">
                            <?= e((string)($entry['channel'] ?? 'app')) ?>
                        </span>
                    </div>
                    <p class="text-sm mt-2 whitespace-pre-wrap break-words"><?= e((string)($entry['message'] ?? '')) ?></p>
                    <?php if ($ctxText !== ''): ?>
                        <details class="mt-2">
                            <summary class="text-[11px] text-gray-400 cursor-pointer hover:text-gray-600 dark:hover:text-gray-200">Contexto</summary>
                            <pre class="mt-2 p-3 rounded-lg bg-gray-50 dark:bg-gray-900 text-[11px] overflow-x-auto text-gray-600 dark:text-gray-300"><?= e($ctxText) ?></pre>
                        </details>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<?php if ($pages > 1): ?>
    <div class="flex items-center justify-center gap-2 mb-6">
        <?php if ($page > 1): ?>
            <a href="<?= $link(['page' => $page - 1]) ?>" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 rounded-lg text-xs hover:bg-gray-50 dark:hover:bg-muted-dark">Anterior</a>
        <?php endif; ?>
        <span class="text-xs text-gray-500">Página <?= (int)$page ?> de <?= (int)$pages ?></span>
        <?php if ($page < $pages): ?>
            <a href="<?= $link(['page' => $page + 1]) ?>" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 rounded-lg text-xs hover:bg-gray-50 dark:hover:bg-muted-dark">Siguiente</a>
        <?php endif; ?>
    </div>
<?php endif; ?>

<!-- Diagnóstico -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-6">
    <h3 class="text-sm font-semibold mb-4">Diagnóstico del entorno</h3>
    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 text-xs">
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">PHP</p>
            <p class="font-medium mt-0.5"><?= e((string)($diag['php'] ?? '')) ?> · <?= e((string)($diag['sapi'] ?? '')) ?></p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">extensiones</p>
            <p class="font-medium mt-0.5">
                <?php foreach (['curl', 'mbstring', 'openssl', 'sqlite3', 'pdo_sqlite'] as $name): ?>
                    <span class="<?= !empty($ext[$name]) ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400' ?>">
                        <?= $name ?> <?= !empty($ext[$name]) ? '✓' : '✗' ?>
                    </span>
                <?php endforeach; ?>
            </p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">max_execution_time</p>
            <p class="font-medium mt-0.5"><?= e((string)($diag['max_execution_time'] ?? '')) ?> s</p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">memory_limit</p>
            <p class="font-medium mt-0.5"><?= e((string)($diag['memory_limit'] ?? '')) ?></p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">post_max_size</p>
            <p class="font-medium mt-0.5"><?= e((string)($diag['post_max_size'] ?? '')) ?></p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">display_errors / log_errors</p>
            <p class="font-medium mt-0.5"><?= e((string)($diag['display_errors'] ?? '')) ?> / <?= e((string)($diag['log_errors'] ?? '')) ?></p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">APP_DEBUG / rewrite</p>
            <p class="font-medium mt-0.5"><?= !empty($diag['app_debug']) ? 'on' : 'off' ?> / <?= !empty($diag['rewrite']) ? 'sí' : 'no' ?></p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">storage escribible</p>
            <p class="font-medium mt-0.5"><?= !empty($diag['storage_writable']) ? 'sí' : 'NO' ?></p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">disco libre</p>
            <p class="font-medium mt-0.5"><?= e($fb((int)($diag['disk_free'] ?? 0))) ?> / <?= e($fb((int)($diag['disk_total'] ?? 0))) ?></p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">database.sqlite</p>
            <p class="font-medium mt-0.5"><?= e($fb((int)($diag['db_size'] ?? 0))) ?></p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">cve.sqlite</p>
            <p class="font-medium mt-0.5"><?= e($fb((int)($diag['cve_db_size'] ?? 0))) ?></p>
        </div>
        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900">
            <p class="text-gray-500">IA configurada</p>
            <p class="font-medium mt-0.5"><?= $llmConfigured ? 'sí' : 'no' ?> (<?= count($llmProfiles) ?> perfiles)</p>
        </div>
    </div>
</div>

<!-- IA: perfiles e informes -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-6">
    <div class="flex items-start justify-between gap-3 flex-wrap mb-4">
        <div>
            <h3 class="text-sm font-semibold">Informes con IA</h3>
            <p class="text-xs text-gray-400 mt-1">
                Tarea «Informe de CVE con IA»:
                <?php
                $taskName = 'Predeterminado';
                foreach ($llmProfiles as $profile) {
                    if ((int)$profile['id'] === (int)($llmTaskProfile ?? 0)) {
                        $taskName = (string)$profile['name'];
                        break;
                    }
                }
                ?>
                <span class="font-medium text-gray-600 dark:text-gray-300"><?= e($taskName) ?></span>
                · <?= e(implode(' · ', array_map(
                    static fn($k, $v) => $k . ': ' . $v,
                    array_keys($jobCounts),
                    array_values($jobCounts)
                )) ?: 'sin informes') ?>
            </p>
        </div>
        <a href="<?= base_url('admin/apis') ?>" class="text-xs text-brand-600 dark:text-brand-400 hover:underline">Configurar IA</a>
    </div>

    <?php if ($llmProfiles === []): ?>
        <p class="text-xs text-gray-500">No hay perfiles de IA configurados. Añade uno en Admin → APIs.</p>
    <?php else: ?>
        <div class="flex flex-wrap gap-2 mb-4">
            <?php foreach ($llmProfiles as $profile): ?>
                <span class="px-2 py-1 rounded-lg bg-gray-50 dark:bg-gray-900 text-[11px] text-gray-600 dark:text-gray-300">
                    <span class="font-medium"><?= e((string)$profile['name']) ?></span>
                    · <?= e((string)$profile['provider']) ?> · <?= e((string)$profile['model']) ?>
                    <?= !empty($profile['api_key_encrypted']) || (string)$profile['provider'] === 'ollama' ? '· 🔑' : '· sin clave' ?>
                </span>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if ($jobs === []): ?>
        <p class="text-xs text-gray-500">Todavía no se ha generado ningún informe con IA.</p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="w-full text-xs">
                <thead>
                    <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-[10px] text-gray-500 uppercase">
                        <th class="text-left px-3 py-2">Informe</th>
                        <th class="text-left px-3 py-2">Estado</th>
                        <th class="text-left px-3 py-2">Modelo</th>
                        <th class="text-left px-3 py-2">Duración</th>
                        <th class="text-left px-3 py-2">Error</th>
                        <th class="text-left px-3 py-2">Fecha</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
                    <?php foreach ($jobs as $job): ?>
                        <?php $jobStatus = (string)($job['status'] ?? 'pending'); ?>
                        <tr>
                            <td class="px-3 py-2">
                                <a href="<?= base_url('modules/cve/report-ai/' . (int)$job['id']) ?>"
                                   class="text-brand-600 dark:text-brand-400 hover:underline">
                                    #<?= (int)$job['id'] ?> · <?= e(truncate((string)$job['title'], 60)) ?>
                                </a>
                                <?php if (!empty($job['no_ai'])): ?>
                                    <span class="ml-1 text-[10px] text-gray-400">(sin IA)</span>
                                <?php endif; ?>
                            </td>
                            <td class="px-3 py-2">
                                <span class="px-2 py-0.5 rounded-full <?= $jobClasses[$jobStatus] ?? $jobClasses['pending'] ?>">
                                    <?= e($jobLabels[$jobStatus] ?? $jobStatus) ?>
                                </span>
                            </td>
                            <td class="px-3 py-2 text-gray-500"><?= e((string)($job['ai_model'] ?? '—')) ?></td>
                            <td class="px-3 py-2 text-gray-500">
                                <?= !empty($job['ai_duration_ms']) ? e(number_format((int)$job['ai_duration_ms'] / 1000, 1, ',', '.')) . ' s' : '—' ?>
                            </td>
                            <td class="px-3 py-2 text-red-600 dark:text-red-400 max-w-[320px]">
                                <?= e(truncate((string)($job['ai_error'] ?? ''), 140)) ?>
                            </td>
                            <td class="px-3 py-2 text-gray-500 whitespace-nowrap">
                                <?= e(format_date((string)($job['created_at'] ?? ''), 'd/m/Y H:i')) ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<p class="text-[11px] text-gray-400">
    Los ficheros de log están en <code class="font-mono">storage/</code> y no son accesibles por HTTP.
    El log estructurado (<code class="font-mono">app.log</code>) rota automáticamente al superar 2 MB.
</p>
