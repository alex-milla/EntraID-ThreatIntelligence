<?php
/**
 * Vista: CVE — inventario de software (Fase 1).
 * Variables: $isAdmin, $tab, $groups, $software, $stats, $selectedGroup,
 *            $q, $editSoftware, $editGroup, $dbError
 */

$sw = is_array($editSoftware) ? $editSoftware : [];
$swId = (int)($sw['id'] ?? 0);
$showSoftwareForm = $isAdmin && $editSoftware !== null;

$gr = is_array($editGroup) ? $editGroup : [];
$grId = (int)($gr['id'] ?? 0);
$showGroupForm = $isAdmin && $editGroup !== null;

$criticalityLabels = [
    'critical' => 'Crítica',
    'high'     => 'Alta',
    'medium'   => 'Media',
    'low'      => 'Baja',
    'info'     => 'Informativa',
];
$criticalityClasses = [
    'critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'high'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'info'     => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
];

$dbBytes = (int)($stats['db_size'] ?? 0);
$dbSizeLabel = $dbBytes <= 0
    ? '0 KB'
    : ($dbBytes >= 1048576 ? number_format($dbBytes / 1048576, 1) . ' MB' : number_format($dbBytes / 1024, 1) . ' KB');
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

<div class="mb-6 flex items-start justify-between gap-4 flex-wrap">
    <div>
        <h1 class="text-xl font-semibold">CVE</h1>
        <p class="text-sm text-gray-500 mt-1">
            Catálogo público de CVEs e inventario de software. En esta fase se configuran las fuentes y se define
            el software de tus entornos; la descarga NVD llega en la Fase 2.
        </p>
    </div>
    <?php if ($isAdmin): ?>
        <a href="<?= base_url('admin/apis') ?>"
           class="inline-flex items-center gap-2 px-3 py-2 border border-gray-200 dark:border-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
            Configurar fuentes
        </a>
    <?php endif; ?>
</div>

<div class="flex items-center gap-2 mb-5 border-b border-gray-200 dark:border-gray-700">
    <a href="<?= base_url('modules/cve?tab=software') ?>"
       class="px-3 py-2 -mb-px text-sm font-medium border-b-2 <?= $tab === 'software' ? 'border-brand-500 text-brand-600 dark:text-brand-300' : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' ?>">
        Mi software
    </a>
    <a href="<?= base_url('modules/cve?tab=catalog') ?>"
       class="px-3 py-2 -mb-px text-sm font-medium border-b-2 <?= $tab === 'catalog' ? 'border-brand-500 text-brand-600 dark:text-brand-300' : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' ?>">
        Catálogo
    </a>
</div>

<?php if (!empty($dbError)): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-red-200 dark:border-red-800 p-6">
        <h2 class="text-sm font-semibold text-red-600 dark:text-red-400 mb-2">No se pudo abrir la base de datos de CVEs</h2>
        <p class="text-sm text-gray-600 dark:text-gray-300"><?= e($dbError) ?></p>
        <p class="text-xs text-gray-400 mt-3">
            Comprueba que el directorio <code class="font-mono">storage/</code> tenga permisos de escritura.
            La ruta configurada es <code class="font-mono"><?= e(CVE_DB_PATH) ?></code>.
        </p>
    </div>
<?php elseif ($tab === 'catalog'): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
        <div class="w-12 h-12 mx-auto rounded-full bg-brand-50 dark:bg-brand-950 flex items-center justify-center mb-3">
            <svg class="w-6 h-6 text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
        </div>
        <h2 class="text-sm font-semibold mb-1">Catálogo NVD — Fase 2</h2>
        <p class="text-sm text-gray-500 max-w-xl mx-auto">
            La descarga del catálogo público, el cruce con tu inventario y los filtros por CVE se habilitan en la
            siguiente fase. Mientras tanto, puedes configurar la API key de NVD y probar las fuentes en
            <?php if ($isAdmin): ?>
                <a href="<?= base_url('admin/apis') ?>" class="text-brand-600 dark:text-brand-400 hover:underline">Admin → APIs</a>.
            <?php else: ?>
                Admin → APIs.
            <?php endif; ?>
        </p>
        <div class="mt-5 inline-flex items-center gap-4 text-xs text-gray-400">
            <span>Catálogo: <strong class="text-gray-600 dark:text-gray-300"><?= number_format((int)($stats['catalog'] ?? 0)) ?></strong></span>
            <span>KEV: <strong class="text-gray-600 dark:text-gray-300"><?= number_format((int)($stats['kev'] ?? 0)) ?></strong></span>
            <span>EPSS: <strong class="text-gray-600 dark:text-gray-300"><?= number_format((int)($stats['epss'] ?? 0)) ?></strong></span>
        </div>
    </div>
<?php else: ?>

    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">Grupos</p>
            <p class="text-2xl font-bold mt-1"><?= number_format((int)($stats['groups'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">Software</p>
            <p class="text-2xl font-bold mt-1"><?= number_format((int)($stats['software'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">CVEs</p>
            <p class="text-2xl font-bold mt-1"><?= number_format((int)($stats['catalog'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">KEV</p>
            <p class="text-2xl font-bold mt-1 text-red-500"><?= number_format((int)($stats['kev'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">Matches</p>
            <p class="text-2xl font-bold mt-1 text-brand-500"><?= number_format((int)($stats['matches'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">DB CVE</p>
            <p class="text-lg font-bold mt-1"><?= e($dbSizeLabel) ?></p>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Grupos -->
        <div class="space-y-4">
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
                <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between gap-2">
                    <h2 class="text-sm font-semibold">Grupos de aplicaciones</h2>
                    <?php if ($isAdmin): ?>
                        <a href="<?= base_url('modules/cve?tab=software&new_group=1') ?>"
                           class="text-xs text-brand-600 dark:text-brand-400 hover:underline">Nuevo</a>
                    <?php endif; ?>
                </div>
                <?php if (empty($groups)): ?>
                    <p class="px-5 py-6 text-sm text-gray-500">Todavía no hay grupos. Crea uno para organizar tu software.</p>
                <?php else: ?>
                    <div class="py-2">
                        <?php foreach ($groups as $g): ?>
                            <div class="group flex items-center gap-2 pr-3 py-1.5 hover:bg-gray-50 dark:hover:bg-gray-800/50"
                                 style="padding-left: <?= 12 + ((int)$g['depth'] * 18) ?>px">
                                <svg class="w-3.5 h-3.5 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/></svg>
                                <a href="<?= base_url('modules/cve?tab=software&group=' . (int)$g['id']) ?>"
                                   class="text-sm truncate <?= $selectedGroup === (int)$g['id'] ? 'font-semibold text-brand-600 dark:text-brand-300' : 'text-gray-700 dark:text-gray-300' ?>">
                                    <?= e($g['name']) ?>
                                </a>
                                <span class="text-[10px] text-gray-400"><?= (int)($g['software_count'] ?? 0) ?></span>
                                <?php if ($isAdmin): ?>
                                    <span class="ml-auto flex items-center gap-1">
                                        <a href="<?= base_url('modules/cve?tab=software&edit_group=' . (int)$g['id']) ?>" class="p-1 text-gray-400 hover:text-brand-500" title="Editar grupo">
                                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                                        </a>
                                        <form method="POST" action="<?= base_url('modules/cve/groups/delete') ?>" class="inline" data-confirm="¿Eliminar el grupo «<?= e($g['name']) ?>»? El software quedará sin grupo." data-confirm-danger>
                                            <?= Csrf::field() ?>
                                            <input type="hidden" name="id" value="<?= (int)$g['id'] ?>">
                                            <button type="submit" class="p-1 text-gray-400 hover:text-red-500" title="Eliminar grupo">
                                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                                            </button>
                                        </form>
                                    </span>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <?php if ($showGroupForm): ?>
                <form method="POST" action="<?= base_url('modules/cve/groups/save') ?>"
                      class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 space-y-3">
                    <?= Csrf::field() ?>
                    <input type="hidden" name="id" value="<?= $grId ?>">
                    <div class="flex items-center justify-between">
                        <h2 class="text-sm font-semibold"><?= $grId ? 'Editar grupo' : 'Nuevo grupo' ?></h2>
                        <a href="<?= base_url('modules/cve?tab=software') ?>" class="text-xs text-gray-400 hover:underline">Cancelar</a>
                    </div>
                    <div>
                        <label class="block text-xs text-gray-500 mb-1">Nombre</label>
                        <input type="text" name="name" required maxlength="120" value="<?= e($gr['name'] ?? '') ?>"
                               class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <div>
                        <label class="block text-xs text-gray-500 mb-1">Grupo padre</label>
                        <select name="parent_id"
                                class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                            <option value="0">— Raíz —</option>
                            <?php foreach ($groups as $g): ?>
                                <?php if ((int)$g['id'] === $grId) continue; ?>
                                <option value="<?= (int)$g['id'] ?>" <?= (int)($gr['parent_id'] ?? 0) === (int)$g['id'] ? 'selected' : '' ?>>
                                    <?= str_repeat('— ', (int)$g['depth']) . e($g['name']) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs text-gray-500 mb-1">Posición</label>
                        <input type="number" name="position" value="<?= (int)($gr['position'] ?? 0) ?>" min="0" max="9999"
                               class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <button type="submit" class="w-full px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                        Guardar grupo
                    </button>
                </form>
            <?php endif; ?>
        </div>

        <!-- Software -->
        <div class="lg:col-span-2 space-y-4">
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
                <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between gap-3 flex-wrap">
                    <h2 class="text-sm font-semibold">Software identificado</h2>
                    <div class="flex items-center gap-2">
                        <form method="GET" action="<?= base_url('modules/cve') ?>" class="flex items-center gap-2">
                            <input type="hidden" name="tab" value="software">
                            <select name="group" onchange="this.form.submit()"
                                    class="px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                                <option value="0">Todos los grupos</option>
                                <?php foreach ($groups as $g): ?>
                                    <option value="<?= (int)$g['id'] ?>" <?= $selectedGroup === (int)$g['id'] ? 'selected' : '' ?>>
                                        <?= str_repeat('— ', (int)$g['depth']) . e($g['name']) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                            <input type="text" name="q" value="<?= e($q) ?>" placeholder="Buscar software..."
                                   class="w-40 px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                            <button type="submit" class="px-2.5 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs font-medium rounded-lg transition-colors">Filtrar</button>
                        </form>
                        <?php if ($isAdmin): ?>
                            <a href="<?= base_url('modules/cve?tab=software&new_software=1') ?>"
                               class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                                Nuevo software
                            </a>
                        <?php endif; ?>
                    </div>
                </div>

                <?php if (empty($software)): ?>
                    <div class="px-5 py-10 text-center">
                        <p class="text-sm text-gray-500">No hay software en el inventario con estos filtros.</p>
                        <?php if ($isAdmin): ?>
                            <a href="<?= base_url('modules/cve?tab=software&new_software=1') ?>" class="inline-block mt-3 text-sm text-brand-600 dark:text-brand-400 hover:underline">Añadir el primero</a>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <div class="overflow-x-auto">
                        <table class="w-full text-sm">
                            <thead>
                                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                                    <th class="text-left px-4 py-2">Software</th>
                                    <th class="text-left px-4 py-2">Grupo</th>
                                    <th class="text-left px-4 py-2">Versión</th>
                                    <th class="text-left px-4 py-2">Criticidad</th>
                                    <th class="text-left px-4 py-2">CPE</th>
                                    <th class="text-right px-4 py-2"></th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                                <?php foreach ($software as $s): ?>
                                    <?php
                                    $crit = (string)($s['criticality'] ?? 'medium');
                                    $critClass = $criticalityClasses[$crit] ?? $criticalityClasses['medium'];
                                    ?>
                                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                        <td class="px-4 py-3">
                                            <p class="font-medium"><?= e($s['name']) ?></p>
                                            <p class="text-xs text-gray-400">
                                                <?= e(trim(($s['vendor'] ?? '') . ' ' . ($s['product'] ?? ''))) ?: '—' ?>
                                                <?php if (!empty($s['environment'])): ?> · <?= e($s['environment']) ?><?php endif; ?>
                                                <?php if (!empty($s['asset_count'])): ?> · <?= number_format((int)$s['asset_count']) ?> activos<?php endif; ?>
                                            </p>
                                        </td>
                                        <td class="px-4 py-3 text-xs text-gray-500"><?= e($s['group_name'] ?? '—') ?></td>
                                        <td class="px-4 py-3 text-xs font-mono text-gray-500"><?= e(!empty($s['version']) ? $s['version'] : '—') ?></td>
                                        <td class="px-4 py-3">
                                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $critClass ?>"><?= e($criticalityLabels[$crit] ?? $crit) ?></span>
                                        </td>
                                        <td class="px-4 py-3 text-xs font-mono text-gray-400 max-w-[260px] truncate" title="<?= e($s['cpe_name'] ?? '') ?>">
                                            <?= e($s['cpe_name'] ?? '—') ?>
                                        </td>
                                        <td class="px-4 py-3 text-right whitespace-nowrap">
                                            <?php if ($isAdmin): ?>
                                                <a href="<?= base_url('modules/cve?tab=software&edit_software=' . (int)$s['id']) ?>" class="text-xs text-gray-400 hover:text-brand-500 mr-2">Editar</a>
                                                <form method="POST" action="<?= base_url('modules/cve/software/delete') ?>" class="inline" data-confirm="¿Eliminar «<?= e($s['name']) ?>» del inventario?" data-confirm-danger>
                                                    <?= Csrf::field() ?>
                                                    <input type="hidden" name="id" value="<?= (int)$s['id'] ?>">
                                                    <button type="submit" class="text-xs text-gray-400 hover:text-red-500">Eliminar</button>
                                                </form>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>

            <?php if ($showSoftwareForm): ?>
                <?php
                $cpeValue = (string)($sw['cpe_name'] ?? '');
                ?>
                <form method="POST" action="<?= base_url('modules/cve/software/save') ?>"
                      class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 space-y-4">
                    <?= Csrf::field() ?>
                    <input type="hidden" name="id" value="<?= $swId ?>">
                    <div class="flex items-center justify-between">
                        <h2 class="text-lg font-semibold"><?= $swId ? 'Editar software' : 'Nuevo software' ?></h2>
                        <a href="<?= base_url('modules/cve?tab=software') ?>" class="text-sm text-gray-500 hover:underline">Cancelar</a>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs text-gray-500 mb-1">Nombre *</label>
                            <input type="text" name="name" required maxlength="160" value="<?= e($sw['name'] ?? '') ?>"
                                   placeholder="Google Chrome"
                                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        </div>
                        <div>
                            <label class="block text-xs text-gray-500 mb-1">Grupo</label>
                            <select name="group_id"
                                    class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                                <option value="0">— Sin grupo —</option>
                                <?php foreach ($groups as $g): ?>
                                    <option value="<?= (int)$g['id'] ?>" <?= (int)($sw['group_id'] ?? 0) === (int)$g['id'] ? 'selected' : '' ?>>
                                        <?= str_repeat('— ', (int)$g['depth']) . e($g['name']) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="block text-xs text-gray-500 mb-1">Vendor</label>
                            <input type="text" name="vendor" maxlength="120" value="<?= e($sw['vendor'] ?? '') ?>"
                                   placeholder="Google"
                                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        </div>
                        <div>
                            <label class="block text-xs text-gray-500 mb-1">Producto</label>
                            <input type="text" name="product" maxlength="120" value="<?= e($sw['product'] ?? '') ?>"
                                   placeholder="Chrome"
                                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        </div>
                        <div>
                            <label class="block text-xs text-gray-500 mb-1">Versión</label>
                            <input type="text" name="version" maxlength="120" value="<?= e($sw['version'] ?? '') ?>"
                                   placeholder="120.0.6099.109"
                                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:ring-2 focus:ring-brand-500 outline-none">
                        </div>
                        <div>
                            <label class="block text-xs text-gray-500 mb-1">Entorno</label>
                            <input type="text" name="environment" maxlength="120" value="<?= e($sw['environment'] ?? '') ?>"
                                   placeholder="Corporativo / Producción"
                                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        </div>
                        <div>
                            <label class="block text-xs text-gray-500 mb-1">Criticidad</label>
                            <select name="criticality"
                                    class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                                <?php foreach ($criticalityLabels as $val => $label): ?>
                                    <option value="<?= e($val) ?>" <?= (string)($sw['criticality'] ?? 'medium') === $val ? 'selected' : '' ?>><?= e($label) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="block text-xs text-gray-500 mb-1">Nº de activos</label>
                            <input type="number" name="asset_count" min="0" max="1000000" value="<?= e((string)($sw['asset_count'] ?? '')) ?>"
                                   placeholder="0"
                                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs text-gray-500 mb-1">CPE principal</label>
                        <input type="text" name="cpe_name" value="<?= e($cpeValue) ?>"
                               placeholder="cpe:2.3:a:google:chrome"
                               class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:ring-2 focus:ring-brand-500 outline-none">
                        <p class="text-xs text-gray-400 mt-1">
                            Formato NVD: <code class="font-mono">cpe:2.3:a:vendor:product</code>. En la Fase 3 se podrá buscar y añadir varios CPE por software.
                        </p>
                    </div>

                    <div>
                        <label class="block text-xs text-gray-500 mb-1">Notas</label>
                        <textarea name="notes" rows="2"
                                  class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none"><?= e($sw['notes'] ?? '') ?></textarea>
                    </div>

                    <div class="flex items-center gap-3 pt-2 border-t border-gray-100 dark:border-gray-700">
                        <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                            Guardar software
                        </button>
                        <a href="<?= base_url('modules/cve?tab=software') ?>" class="text-sm text-gray-500 hover:underline">Cancelar</a>
                    </div>
                </form>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>
