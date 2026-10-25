<?php
/**
 * Vista — Actualizaciones del sistema (solo admin).
 * Variables esperadas: $installedVersion, $release, $backups, $error, $success
 */
?>

<!-- Estado actual y última release -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
    <div class="card p-5">
        <h2 class="text-sm font-semibold mb-3">Versión instalada</h2>
        <p class="text-3xl font-bold text-primary">v<?= e($installedVersion) ?></p>
        <p class="text-xs text-ink-muted mt-2"><?= is_file(ROOT_PATH . '/VERSION') ? 'Fichero VERSION presente' : 'Sin fichero VERSION (se creará al actualizar)' ?></p>
    </div>

    <div class="card p-5">
        <h2 class="text-sm font-semibold mb-3">Última release en GitHub</h2>
        <?php if ($release['ok']): ?>
            <p class="text-3xl font-bold text-primary">v<?= e($release['version']) ?></p>
            <p class="text-xs text-ink-muted mt-1"><?= e($release['name']) ?></p>
            <?php if ($release['published_at']): ?>
                <p class="text-xs text-ink-muted"><?= e(format_date($release['published_at'])) ?></p>
            <?php endif; ?>
        <?php else: ?>
            <p class="text-sm text-danger"><?= e($release['error']) ?></p>
        <?php endif; ?>
    </div>

    <div class="card p-5 flex flex-col">
        <h2 class="text-sm font-semibold mb-3">Estado</h2>
        <?php if (!$release['ok']): ?>
            <p class="text-sm text-ink-muted">No se pudo consultar GitHub.</p>
        <?php elseif (version_compare($installedVersion, $release['version'], '>=')): ?>
            <p class="text-sm font-medium text-success">Sistema actualizado (v<?= e($installedVersion) ?>).</p>
            <p class="text-xs text-ink-muted mt-1">Puedes forzar una reinstalación si algún fichero está dañado.</p>
        <?php else: ?>
            <p class="text-sm font-medium text-orange-600 dark:text-orange-400">Nueva versión disponible: v<?= e($release['version']) ?></p>
            <p class="text-xs text-ink-muted mt-1">Se creará un backup automático antes de instalar.</p>
        <?php endif; ?>
    </div>
</div>

<!-- Acciones -->
<div class="card p-5 mb-6">
    <h2 class="text-sm font-semibold mb-4">Acciones</h2>
    <div class="flex items-center gap-3 flex-wrap">
        <form method="POST" data-confirm="Se creará un backup antes de instalar. ¿Continuar?">
            <?= Csrf::field() ?>
            <input type="hidden" name="action" value="install">
            <button type="submit"
                    class="btn">
                <?= $release['ok'] && version_compare($installedVersion, $release['version'], '>=') ? 'Reinstalar (forzado)' : 'Instalar actualización' ?>
            </button>
        </form>
        <form method="POST" data-confirm="Reinstalación forzada: sobrescribe TODOS los ficheros de código con la release. ¿Continuar?" data-confirm-danger>
            <?= Csrf::field() ?>
            <input type="hidden" name="action" value="install">
            <input type="hidden" name="force" value="1">
            <button type="submit"
                    class="px-4 py-2 bg-muted hover:bg-surface-3 text-ink text-sm font-medium rounded-lg transition-colors">
                Forzar reinstalación
            </button>
        </form>
    </div>
    <p class="text-xs text-ink-muted mt-3">
        Nunca se tocan: <code>.env</code>, <code>.htaccess</code> raíz, base de datos, logs ni nada dentro de
        <code>storage/cache/</code>, <code>storage/exports/</code> y <code>storage/backups/</code>.
        Los ficheros <code>setup.php</code> y <code>diagnostic.php</code> se eliminan siempre.
    </p>
</div>

<!-- Notas de la release -->
<?php if ($release['ok'] && $release['notes'] !== ''): ?>
    <div class="card p-5 mb-6">
        <details>
            <summary class="text-sm font-semibold cursor-pointer select-none">Notas de la versión v<?= e($release['version']) ?></summary>
            <div class="mt-4 text-sm text-ink-muted whitespace-pre-wrap"><?= e($release['notes']) ?></div>
        </details>
    </div>
<?php endif; ?>

<!-- Backups -->
<div class="card p-5">
    <h2 class="text-sm font-semibold mb-4">Backups del código (<?= count($backups) ?>)</h2>
    <?php if (empty($backups)): ?>
        <p class="text-sm text-ink-muted">Todavía no hay backups. Se crea uno automáticamente antes de cada actualización.</p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="data-table w-full text-sm">
                <thead>
                    <tr class="text-left text-xs text-ink-muted border-b border-line">
                        <th class="py-2 pr-4">Backup</th>
                        <th class="py-2 pr-4">Fecha</th>
                        <th class="py-2 pr-4">Ficheros</th>
                        <th class="py-2">Acción</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($backups as $b): ?>
                        <tr class="border-b border-line-subtle">
                            <td class="py-2 pr-4 font-mono text-xs"><?= e($b['name']) ?></td>
                            <td class="py-2 pr-4"><?= e($b['date']) ?></td>
                            <td class="py-2 pr-4"><?= (int)$b['files'] ?></td>
                            <td class="py-2">
                                <form method="POST" data-confirm="Se creará un backup del estado actual y después se restaurará <?= e($b['name']) ?>. ¿Continuar?" data-confirm-danger>
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="restore">
                                    <input type="hidden" name="backup" value="<?= e($b['name']) ?>">
                                    <button type="submit" class="text-xs px-2 py-1 bg-muted hover:bg-surface-3 rounded transition-colors">
                                        Restaurar
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>
