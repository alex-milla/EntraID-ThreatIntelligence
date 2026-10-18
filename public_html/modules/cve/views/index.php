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
        'warning' => 'text-amber-600 bg-amber-50 dark:bg-amber-900/20',
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
            Catálogo público de CVEs e inventario de software de tus entornos. Actualiza el catálogo de forma
            incremental y sincroniza cada producto desde su CPE.
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
    <a href="<?= base_url('modules/cve?tab=catalog') ?>"
       class="px-3 py-2 -mb-px text-sm font-medium border-b-2 <?= $tab === 'catalog' ? 'border-brand-500 text-brand-600 dark:text-brand-300' : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' ?>">
        Catálogo
    </a>
    <a href="<?= base_url('modules/cve?tab=software') ?>"
       class="px-3 py-2 -mb-px text-sm font-medium border-b-2 <?= $tab === 'software' ? 'border-brand-500 text-brand-600 dark:text-brand-300' : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' ?>">
        Mi software
    </a>
    <a href="<?= base_url('modules/cve?tab=reports') ?>"
       class="px-3 py-2 -mb-px text-sm font-medium border-b-2 <?= $tab === 'reports' ? 'border-brand-500 text-brand-600 dark:text-brand-300' : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' ?>">
        Informes
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
    <?php
    $syncStatus = (string)($syncState['status'] ?? 'idle');
    $syncRunning = in_array($syncStatus, ['queued', 'running'], true);
    $syncProcessed = (int)($syncState['processed'] ?? 0);
    $syncTotal = (int)($syncState['total'] ?? 0);
    $syncPct = $syncTotal > 0 ? min(100, (int)round($syncProcessed / $syncTotal * 100)) : 0;
    $syncMessage = (string)($syncState['message'] ?? '');
    $syncUpdated = (string)($syncState['updated_at'] ?? '');
    $syncAge = 0;
    if ($syncUpdated !== '') {
        $ts = str_contains($syncUpdated, 'T') ? strtotime($syncUpdated) : strtotime($syncUpdated . ' UTC');
        $syncAge = $ts !== false ? max(0, time() - $ts) : 0;
    }
    $showStep = $isAdmin && $syncRunning && ($syncAge > 30 || str_contains($syncMessage, 'No se pudo lanzar'));
    $severityClasses = [
        'Critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
        'High'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
        'Medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
        'Low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    ];
    $baseQuery = array_merge($catalogFilters, ['tab' => 'catalog']);
    ?>

    <div id="cve-sync-box" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-6">
        <div class="flex items-start justify-between gap-4 flex-wrap">
            <div class="min-w-0">
                <div class="flex items-center gap-2">
                    <h2 class="text-sm font-semibold">Catálogo NVD</h2>
                    <span id="cve-sync-status" class="inline-flex px-2 py-0.5 text-[10px] rounded-full <?= $syncRunning ? 'bg-brand-100 text-brand-700 dark:bg-brand-900 dark:text-brand-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300' ?>">
                        <?= $syncRunning ? 'Sincronizando' : e(ucfirst($syncStatus)) ?>
                    </span>
                </div>
                <p id="cve-sync-message" class="text-xs text-gray-500 mt-1">
                    <?= e($syncMessage !== '' ? $syncMessage : 'Listo para descargar el catálogo público.') ?>
                </p>
                <p class="text-xs text-gray-400 mt-1">
                    <?php if (!empty($syncState['last_success_at'])): ?>
                        Última sincronización correcta: <?= e(format_date((string)$syncState['last_success_at'])) ?>.
                    <?php else: ?>
                        Todavía no se ha completado ninguna sincronización.
                    <?php endif; ?>
                    <?php if ($syncRunning && $syncAge > 30): ?>
                        <span class="text-amber-600 dark:text-amber-400">Sin progreso reciente; puedes usar «Continuar».</span>
                    <?php endif; ?>
                </p>
            </div>
            <?php if ($isAdmin): ?>
                <div class="flex items-center gap-2">
                    <button type="button" id="cve-start-btn" onclick="startCveSync('auto')"
                            title="Incremental si ya hay catálogo; primera carga completa si está vacío."
                            class="<?= $syncRunning ? 'hidden' : 'inline-flex' ?> items-center gap-2 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                        Actualizar catálogo
                    </button>
                    <button type="button" id="cve-rebuild-btn" onclick="startCveSync('full')"
                            title="Vuelve a descargar el catálogo completo. Úsalo solo si es necesario."
                            class="<?= $syncRunning ? 'hidden' : 'inline-flex' ?> items-center px-2 py-2 text-xs text-gray-400 hover:text-red-500 transition-colors">
                        Reconstruir
                    </button>
                    <button type="button" id="cve-sources-btn" onclick="startCveSync('kev')"
                            title="Actualiza solo CISA KEV y EPSS."
                            class="<?= $syncRunning ? 'hidden' : 'inline-flex' ?> items-center px-2 py-2 text-xs text-gray-400 hover:text-brand-500 transition-colors">
                        KEV / EPSS
                    </button>
                    <button type="button" id="cve-cancel-btn" onclick="cancelCveSync()"
                            class="<?= $syncRunning ? 'inline-flex' : 'hidden' ?> items-center gap-2 px-3 py-2 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-300 hover:bg-red-100 dark:hover:bg-red-900/40 text-sm font-medium rounded-lg transition-colors">
                        Detener
                    </button>
                    <button type="button" id="cve-step-btn" onclick="stepCveSync()"
                            class="<?= $showStep ? 'inline-flex' : 'hidden' ?> items-center gap-2 px-3 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors"
                            title="Procesa un tramo manualmente si el worker en segundo plano no avanza">
                        Continuar
                    </button>
                </div>
            <?php endif; ?>
        </div>

        <div id="cve-sync-progress-wrap" class="mt-4 <?= $syncRunning ? '' : 'hidden' ?>">
            <div class="h-2 rounded-full bg-gray-100 dark:bg-gray-800 overflow-hidden">
                <div id="cve-sync-progress" class="h-full bg-brand-500 transition-all" style="width: <?= $syncPct ?>%"></div>
            </div>
            <p id="cve-sync-counts" class="text-[11px] text-gray-400 mt-1">
                <?= number_format($syncProcessed) ?><?= $syncTotal > 0 ? ' / ' . number_format($syncTotal) : '' ?> CVEs procesados
            </p>
        </div>
    </div>

    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">CVEs</p>
            <p class="text-2xl font-bold mt-1"><?= number_format((int)($stats['catalog'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">Críticos</p>
            <p class="text-2xl font-bold mt-1 text-red-500"><?= number_format((int)($stats['critical'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">Altos</p>
            <p class="text-2xl font-bold mt-1 text-orange-500"><?= number_format((int)($stats['high'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">KEV</p>
            <p class="text-2xl font-bold mt-1 text-red-500"><?= number_format((int)($stats['kev'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">EPSS ≥ 0,1</p>
            <p class="text-2xl font-bold mt-1 text-amber-500"><?= number_format((int)($stats['epss_high'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">Mis CVEs</p>
            <p class="text-2xl font-bold mt-1 text-brand-500"><?= number_format((int)($stats['matched_cves'] ?? 0)) ?></p>
        </div>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between gap-3 flex-wrap">
            <h2 class="text-sm font-semibold">CVEs (<?= number_format($catalogTotal) ?>)</h2>
            <form method="GET" action="<?= base_url('modules/cve') ?>" class="flex items-center gap-2 flex-wrap">
                <input type="hidden" name="tab" value="catalog">
                <input type="text" name="q" value="<?= e($catalogFilters['q'] ?? '') ?>" placeholder="CVE o descripción"
                       class="w-48 px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <select name="severity"
                        class="px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="">Todas las severidades</option>
                    <?php foreach (['Critical', 'High', 'Medium', 'Low'] as $sev): ?>
                        <option value="<?= e($sev) ?>" <?= ($catalogFilters['severity'] ?? '') === $sev ? 'selected' : '' ?>><?= e($sev) ?></option>
                    <?php endforeach; ?>
                </select>
                <input type="text" name="product" value="<?= e($catalogFilters['product'] ?? '') ?>" placeholder="vendor / producto"
                       class="w-40 px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <select name="group"
                        class="px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="0">Todos los grupos</option>
                    <?php foreach ($groups as $g): ?>
                        <option value="<?= (int)$g['id'] ?>" <?= (int)($catalogFilters['group'] ?? 0) === (int)$g['id'] ? 'selected' : '' ?>>
                            <?= str_repeat('— ', (int)$g['depth']) . e($g['name']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                <select name="software_id"
                        class="px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none max-w-[220px]">
                    <option value="0">Mi software (todos)</option>
                    <?php foreach (($softwareOptions ?? []) as $so): ?>
                        <option value="<?= (int)$so['id'] ?>" <?= (int)($catalogFilters['software_id'] ?? 0) === (int)$so['id'] ? 'selected' : '' ?>>
                            <?= e((string)$so['name']) ?><?= !empty($so['version']) ? ' · ' . e((string)$so['version']) : '' ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                <label class="inline-flex items-center gap-1 text-xs text-gray-600 dark:text-gray-300">
                    <input type="checkbox" name="mine" value="1" <?= !empty($catalogFilters['mine']) ? 'checked' : '' ?> class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                    Solo mis productos
                </label>
                <label class="inline-flex items-center gap-1 text-xs text-gray-600 dark:text-gray-300">
                    <input type="checkbox" name="kev" value="1" <?= !empty($catalogFilters['kev']) ? 'checked' : '' ?> class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                    Solo KEV
                </label>
                <input type="number" name="epss_min" min="0" max="1" step="0.01" value="<?= e((string)($catalogFilters['epss_min'] ?? '')) ?>" placeholder="EPSS ≥"
                       class="w-24 px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <select name="sort"
                        class="px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <?php $sortValue = (string)($catalogFilters['sort'] ?? 'published'); ?>
                    <option value="published" <?= $sortValue === 'published' ? 'selected' : '' ?>>Más recientes</option>
                    <option value="cvss" <?= $sortValue === 'cvss' ? 'selected' : '' ?>>Mayor CVSS</option>
                    <option value="epss" <?= $sortValue === 'epss' ? 'selected' : '' ?>>Mayor EPSS</option>
                    <option value="kev" <?= $sortValue === 'kev' ? 'selected' : '' ?>>KEV primero</option>
                </select>
                <button type="submit" class="px-3 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs font-medium rounded-lg transition-colors">Filtrar</button>
                <?php if (!empty($catalogFilters['q']) || !empty($catalogFilters['severity']) || !empty($catalogFilters['product']) || !empty($catalogFilters['kev']) || (string)($catalogFilters['epss_min'] ?? '') !== '' || (int)($catalogFilters['group'] ?? 0) > 0 || (int)($catalogFilters['software_id'] ?? 0) > 0 || !empty($catalogFilters['mine']) || (string)($catalogFilters['sort'] ?? 'published') !== 'published'): ?>
                    <a href="<?= base_url('modules/cve?tab=catalog') ?>" class="text-xs text-gray-400 hover:underline">Limpiar</a>
                <?php endif; ?>
            </form>
        </div>

        <?php if (empty($catalog)): ?>
            <div class="px-5 py-12 text-center">
                <p class="text-sm text-gray-500">
                    <?= $catalogTotal === 0 ? 'El catálogo está vacío. Configura las fuentes y pulsa «Actualizar catálogo».' : 'No hay CVEs con estos filtros.' ?>
                </p>
                <?php if ($catalogTotal === 0 && $isAdmin): ?>
                    <button type="button" onclick="startCveSync('auto')" class="inline-block mt-3 text-sm text-brand-600 dark:text-brand-400 hover:underline">Descargar catálogo NVD</button>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                            <th class="text-left px-4 py-2">CVE</th>
                            <th class="text-left px-4 py-2">Severidad</th>
                            <th class="text-left px-4 py-2">CVSS</th>
                            <th class="text-left px-4 py-2">EPSS</th>
                            <th class="text-left px-4 py-2">KEV</th>
                            <th class="text-left px-4 py-2">Mis productos</th>
                            <th class="text-left px-4 py-2">Publicado</th>
                            <th class="text-left px-4 py-2">Productos</th>
                            <th class="text-left px-4 py-2">Descripción</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                        <?php foreach ($catalog as $cve): ?>
                            <?php
                            $sev = (string)($cve['severity'] ?? '');
                            $sevClass = $severityClasses[$sev] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300';
                            $products = safe_json_decode($cve['products_json'] ?? '[]', []);
                            $products = is_array($products) ? $products : [];
                            $productLabels = [];
                            foreach (array_slice($products, 0, 3) as $p) {
                                if (is_array($p)) {
                                    $productLabels[] = trim(($p['vendor'] ?? '') . ':' . ($p['product'] ?? ''), ':');
                                }
                            }
                            $extraProducts = max(0, count($products) - 3);
                            ?>
                            <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50 align-top">
                                <td class="px-4 py-3 whitespace-nowrap">
                                    <a href="<?= base_url('modules/cve/detail/' . rawurlencode((string)$cve['cve_id'])) ?>" class="font-mono text-xs font-medium text-brand-600 dark:text-brand-400 hover:underline">
                                        <?= e((string)$cve['cve_id']) ?>
                                    </a>
                                </td>
                                <td class="px-4 py-3">
                                    <span class="inline-flex px-2 py-0.5 text-[10px] rounded-full <?= $sevClass ?>"><?= e($sev !== '' ? $sev : '—') ?></span>
                                </td>
                                <td class="px-4 py-3 text-xs text-gray-500">
                                    <?php
                                    $cvss = $cve['cvss_v3_score'] !== null
                                        ? (float)$cve['cvss_v3_score']
                                        : ($cve['cvss_v2_score'] !== null ? (float)$cve['cvss_v2_score'] : null);
                                    $epssScore = $cve['epss'] !== null ? (float)$cve['epss'] : null;
                                    $epssPercentile = $cve['epss_percentile'] !== null ? (float)$cve['epss_percentile'] : null;
                                    $isKev = !empty($cve['kev_id']);
                                    ?>
                                    <?= $cvss !== null ? e(number_format($cvss, 1)) : '—' ?>
                                </td>
                                <td class="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                                    <?php if ($epssScore !== null): ?>
                                        <span class="font-medium text-gray-700 dark:text-gray-300"><?= e(number_format($epssScore, 3)) ?></span>
                                        <?php if ($epssPercentile !== null): ?><span class="text-gray-400">(<?= e(number_format($epssPercentile, 2)) ?>)</span><?php endif; ?>
                                    <?php else: ?>
                                        —
                                    <?php endif; ?>
                                </td>
                                <td class="px-4 py-3 text-xs whitespace-nowrap">
                                    <?php if ($isKev): ?>
                                        <span class="inline-flex px-2 py-0.5 text-[10px] rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300" title="<?= e((string)($cve['kev_date'] ?? '')) ?>">KEV</span>
                                    <?php else: ?>
                                        <span class="text-gray-400">—</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-4 py-3 text-xs text-gray-500 max-w-[180px]">
                                    <?= e(truncate((string)($cve['matched_software'] ?? ''), 60)) ?: '—' ?>
                                </td>
                                <td class="px-4 py-3 text-xs text-gray-500 whitespace-nowrap"><?= e(format_date($cve['published_at'] ?? null, 'd/m/Y')) ?></td>
                                <td class="px-4 py-3 text-xs text-gray-500">
                                    <?= e(implode(', ', $productLabels)) ?: '—' ?>
                                    <?php if ($extraProducts > 0): ?><span class="text-gray-400"> +<?= $extraProducts ?></span><?php endif; ?>
                                </td>
                                <td class="px-4 py-3 text-xs text-gray-500 max-w-[420px]">
                                    <?= e(truncate((string)($cve['description'] ?? ''), 180)) ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <?php if ($catalogPages > 1): ?>
                <div class="px-5 py-3 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between text-xs text-gray-500">
                    <span>Página <?= (int)$catalogPage ?> de <?= (int)$catalogPages ?></span>
                    <div class="flex items-center gap-2">
                        <?php if ($catalogPage > 1): ?>
                            <a href="<?= base_url('modules/cve?' . http_build_query(array_merge($baseQuery, ['page' => $catalogPage - 1]))) ?>" class="px-2 py-1 rounded border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark">Anterior</a>
                        <?php endif; ?>
                        <?php if ($catalogPage < $catalogPages): ?>
                            <a href="<?= base_url('modules/cve?' . http_build_query(array_merge($baseQuery, ['page' => $catalogPage + 1]))) ?>" class="px-2 py-1 rounded border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark">Siguiente</a>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <?php if ($isAdmin): ?>
    <script>
    (function() {
        var STATUS_URL = '<?= base_url('modules/cve/active') ?>';
        var SYNC_URL = '<?= base_url('modules/cve/sync') ?>';
        var CANCEL_URL = '<?= base_url('modules/cve/cancel') ?>';
        var STEP_URL = '<?= base_url('modules/cve/step') ?>';
        var wasRunning = <?= $syncRunning ? 'true' : 'false' ?>;
        var pollTimer = null;

        function parseDbTime(v) {
            if (!v) return 0;
            if (v.indexOf('T') >= 0) return Date.parse(v);
            return Date.parse(v.replace(' ', 'T') + 'Z');
        }

        window.startCveSync = function(mode) {
            mode = mode || 'auto';
            if (mode === 'full' && !window.confirm('Se reconstruirá el catálogo completo. Puede tardar bastante. ¿Continuar?')) {
                return;
            }
            if (mode === 'kev' && !window.confirm('Se actualizarán solo CISA KEV y EPSS. ¿Continuar?')) {
                return;
            }
            api('POST', SYNC_URL, { mode: mode }).then(function(res) {
                if (!res || !res.success) { toast((res && res.error) ? res.error : 'No se pudo iniciar', 'error'); return; }
                wasRunning = true;
                toast(res.message || 'Sincronización iniciada', res.worker_started ? 'success' : 'info');
                var start = document.getElementById('cve-start-btn');
                var rebuild = document.getElementById('cve-rebuild-btn');
                var sources = document.getElementById('cve-sources-btn');
                var cancel = document.getElementById('cve-cancel-btn');
                var progress = document.getElementById('cve-sync-progress-wrap');
                if (start) start.classList.add('hidden');
                if (rebuild) rebuild.classList.add('hidden');
                if (sources) sources.classList.add('hidden');
                if (cancel) cancel.classList.remove('hidden');
                if (progress) progress.classList.remove('hidden');
                var step = document.getElementById('cve-step-btn');
                if (step && !res.worker_started) step.classList.remove('hidden');
                pollCveSync();
            }).catch(function() { toast('Error de conexión', 'error'); });
        };

        window.cancelCveSync = function() {
            api('POST', CANCEL_URL, {}).then(function(res) {
                toast('Sincronización cancelada', 'success');
                setTimeout(function() { location.reload(); }, 800);
            }).catch(function() { toast('Error de conexión', 'error'); });
        };

        window.stepCveSync = function() {
            var btn = document.getElementById('cve-step-btn');
            if (btn) { btn.disabled = true; btn.textContent = 'Procesando…'; }
            api('POST', STEP_URL, {}).then(function(res) {
                if (!res || !res.success) {
                    toast((res && res.error) ? res.error : 'No se pudo procesar el tramo', 'error');
                }
                pollCveSync();
            }).catch(function() { toast('Error de conexión', 'error'); })
              .finally(function() {
                  if (btn) { btn.disabled = false; btn.textContent = 'Continuar'; }
              });
        };

        function pollCveSync() {
            if (pollTimer) clearTimeout(pollTimer);
            api('GET', STATUS_URL).then(function(res) {
                if (!res || !res.state) return;
                var s = res.state;
                var running = s.status === 'queued' || s.status === 'running';
                var processed = parseInt(s.processed || 0, 10);
                var total = parseInt(s.total || 0, 10);
                var pct = total > 0 ? Math.min(100, Math.round(processed / total * 100)) : 0;
                var bar = document.getElementById('cve-sync-progress');
                var counts = document.getElementById('cve-sync-counts');
                var msg = document.getElementById('cve-sync-message');
                var badge = document.getElementById('cve-sync-status');
                var step = document.getElementById('cve-step-btn');
                var start = document.getElementById('cve-start-btn');
                var rebuild = document.getElementById('cve-rebuild-btn');
                var sources = document.getElementById('cve-sources-btn');
                var cancel = document.getElementById('cve-cancel-btn');
                var progress = document.getElementById('cve-sync-progress-wrap');
                if (bar) bar.style.width = pct + '%';
                if (counts) counts.textContent = processed.toLocaleString('es-ES') + (total > 0 ? ' / ' + total.toLocaleString('es-ES') : '') + ' CVEs procesados';
                if (msg) msg.textContent = s.message || (running ? 'Sincronizando…' : 'Listo.');
                if (badge) badge.textContent = running ? 'Sincronizando' : (s.status || 'idle');
                if (progress) progress.classList.toggle('hidden', !running);
                if (start) start.classList.toggle('hidden', running);
                if (rebuild) rebuild.classList.toggle('hidden', running);
                if (sources) sources.classList.toggle('hidden', running);
                if (cancel) cancel.classList.toggle('hidden', !running);
                if (step) {
                    var updated = parseDbTime(s.updated_at || '');
                    var stale = !updated || (Date.now() - updated) > 30000 || (s.message || '').indexOf('No se pudo lanzar') >= 0;
                    step.classList.toggle('hidden', !(running && stale));
                }
                if (running) {
                    wasRunning = true;
                    pollTimer = setTimeout(pollCveSync, 2500);
                } else if (wasRunning) {
                    wasRunning = false;
                    setTimeout(function() { location.reload(); }, 1200);
                }
            }).catch(function() {
                pollTimer = setTimeout(pollCveSync, 5000);
            });
        }

        if (wasRunning) pollCveSync();
    })();
    </script>
    <?php endif; ?>
<?php elseif ($tab === 'reports'): ?>

    <?php if ($isAdmin): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-6">
        <div class="flex items-start justify-between gap-4 flex-wrap">
            <div>
                <h2 class="text-sm font-semibold">Generar informe preventivo</h2>
                <p class="text-xs text-gray-500 mt-1">
                    Informe de los CVEs que afectan al software identificado, con prioridad KEV &gt; EPSS &gt; CVSS.
                </p>
            </div>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-4">
            <label class="block">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Alcance</span>
                <select id="report-scope" onchange="syncCveReportScope()"
                        class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="all">Todo el inventario</option>
                    <option value="group">Un grupo</option>
                    <option value="software">Un software</option>
                </select>
            </label>
            <label class="block">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Grupo</span>
                <select id="report-group" disabled
                        class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none disabled:opacity-50">
                    <option value="0">—</option>
                    <?php foreach ($groups as $g): ?>
                        <option value="<?= (int)$g['id'] ?>"><?= str_repeat('— ', (int)$g['depth']) . e($g['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="block">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Software</span>
                <select id="report-software" disabled
                        class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none disabled:opacity-50">
                    <option value="0">—</option>
                    <?php foreach (($softwareOptions ?? []) as $so): ?>
                        <option value="<?= (int)$so['id'] ?>">
                            <?= e((string)$so['name']) ?><?= !empty($so['version']) ? ' · ' . e((string)$so['version']) : '' ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="block">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Periodo</span>
                <select id="report-period" onchange="syncCveReportPeriod()"
                        class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="7d">Últimos 7 días</option>
                    <option value="30d" selected>Últimos 30 días</option>
                    <option value="90d">Últimos 90 días</option>
                    <option value="all">Todo el histórico</option>
                </select>
            </label>
            <label class="block">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Severidad</span>
                <select id="report-severity"
                        class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="">Todas</option>
                    <option value="Critical">Crítica</option>
                    <option value="High">Alta</option>
                    <option value="Medium">Media</option>
                    <option value="Low">Baja</option>
                </select>
            </label>
            <label class="block">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">EPSS mínimo</span>
                <input id="report-epss" type="number" min="0" max="1" step="0.01" placeholder="0.10"
                       class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            </label>
            <label class="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-5">
                <input id="report-new" type="checkbox" checked class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                Solo nuevas o recién detectadas
            </label>
            <label class="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-5">
                <input id="report-kev" type="checkbox" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                Solo KEV
            </label>
        </div>

        <div class="mt-4 flex items-center gap-3 flex-wrap">
            <button type="button" onclick="generateCveReport(this)"
                    class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                Generar informe
            </button>
            <span id="report-message" class="text-xs text-gray-500"></span>
        </div>
        <p class="text-[11px] text-gray-400 mt-2">
            Se guardan hasta <?= number_format((int)(defined('CVE_REPORT_MAX_ROWS') ? CVE_REPORT_MAX_ROWS : 5000)) ?> afectaciones por informe.
            Puedes exportar el resultado a CSV o imprimirlo en PDF desde la vista del informe.
        </p>
    </div>
    <?php endif; ?>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-sm font-semibold">Informes generados</h2>
        </div>
        <?php if (empty($reports)): ?>
            <div class="p-8 text-center text-sm text-gray-500">
                Todavía no hay informes.
                <?php if ($isAdmin): ?>Genera el primero con el formulario de arriba.<?php endif; ?>
            </div>
        <?php else: ?>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                            <th class="text-left px-4 py-2">Informe</th>
                            <th class="text-left px-4 py-2">Periodo</th>
                            <th class="text-left px-4 py-2">Resumen</th>
                            <th class="text-left px-4 py-2">Generado</th>
                            <th class="text-right px-4 py-2"></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
                        <?php foreach ($reports as $reportRow): ?>
                            <?php
                            $rowSummary = safe_json_decode($reportRow['summary_json'] ?? '{}', []);
                            if (!is_array($rowSummary)) {
                                $rowSummary = [];
                            }
                            $rowPeriod = !empty($reportRow['period_start'])
                                ? format_date((string)$reportRow['period_start'], 'd/m/Y') . ' — ' . format_date((string)($reportRow['period_end'] ?? ''), 'd/m/Y')
                                : 'Histórico';
                            ?>
                            <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/40">
                                <td class="px-4 py-3">
                                    <a href="<?= base_url('modules/cve/report/' . (int)$reportRow['id']) ?>"
                                       class="font-medium text-brand-600 dark:text-brand-400 hover:underline">
                                        <?= e((string)$reportRow['title']) ?>
                                    </a>
                                </td>
                                <td class="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                                    <?= e($rowPeriod !== '' ? $rowPeriod : '—') ?>
                                </td>
                                <td class="px-4 py-3 text-xs text-gray-500">
                                    <?= number_format((int)($rowSummary['unique_cves'] ?? 0)) ?> CVEs ·
                                    <?= number_format((int)($rowSummary['software_count'] ?? 0)) ?> productos ·
                                    <?= number_format((int)($rowSummary['kev'] ?? 0)) ?> KEV
                                </td>
                                <td class="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                                    <?= e(format_date((string)($reportRow['generated_at'] ?? ''), 'd/m/Y H:i')) ?>
                                </td>
                                <td class="px-4 py-3 text-right whitespace-nowrap">
                                    <a href="<?= base_url('modules/cve/report/' . (int)$reportRow['id']) ?>"
                                       class="text-xs text-brand-600 dark:text-brand-400 hover:underline">Ver</a>
                                    <a href="<?= base_url('modules/cve/report/' . (int)$reportRow['id'] . '/csv') ?>"
                                       class="text-xs text-gray-600 dark:text-gray-300 hover:underline ml-3">CSV</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($isAdmin): ?>
    <script>
    function syncCveReportScope() {
        var scope = document.getElementById('report-scope').value;
        document.getElementById('report-group').disabled = scope !== 'group';
        document.getElementById('report-software').disabled = scope !== 'software';
    }

    function syncCveReportPeriod() {
        var all = document.getElementById('report-period').value === 'all';
        document.getElementById('report-new').disabled = all;
    }

    function generateCveReport(button) {
        var message = document.getElementById('report-message');
        var payload = {
            scope: document.getElementById('report-scope').value,
            group_id: document.getElementById('report-group').value,
            software_id: document.getElementById('report-software').value,
            period: document.getElementById('report-period').value,
            severity: document.getElementById('report-severity').value,
            epss_min: document.getElementById('report-epss').value,
            new_only: document.getElementById('report-new').checked,
            only_kev: document.getElementById('report-kev').checked
        };
        message.textContent = 'Generando informe…';
        message.className = 'text-xs text-gray-500';
        if (button) button.disabled = true;
        api('POST', <?= json_encode(base_url('modules/cve/reports/generate')) ?>, payload).then(function (res) {
            if (!res.success) {
                message.textContent = res.error || 'No se pudo generar el informe.';
                message.className = 'text-xs text-red-500';
                if (button) button.disabled = false;
                return;
            }
            window.location.href = res.url;
        }).catch(function () {
            message.textContent = 'Error de conexión al generar el informe.';
            message.className = 'text-xs text-red-500';
            if (button) button.disabled = false;
        });
    }

    syncCveReportScope();
    syncCveReportPeriod();
    </script>
    <?php endif; ?>

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
            <p class="text-xs text-gray-500">Matches</p>
            <p class="text-2xl font-bold mt-1"><?= number_format((int)($stats['matches'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">KEV míos</p>
            <p class="text-2xl font-bold mt-1 text-red-500"><?= number_format((int)($stats['my_kev'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">EPSS ≥ 0,1 míos</p>
            <p class="text-2xl font-bold mt-1 text-amber-500"><?= number_format((int)($stats['my_epss_high'] ?? 0)) ?></p>
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
                                    <th class="text-left px-4 py-2">CVEs</th>
                                    <th class="text-left px-4 py-2">KEV</th>
                                    <th class="text-left px-4 py-2">EPSS ≥ 0,1</th>
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
                                            <?php if ((int)($s['cpe_count'] ?? 0) > 1): ?>
                                                <span class="text-gray-500"> +<?= (int)$s['cpe_count'] - 1 ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                                            <?= number_format((int)($s['match_count'] ?? 0)) ?>
                                            <?php if ((int)($s['match_count'] ?? 0) > 0): ?>
                                                <a href="<?= base_url('modules/cve?tab=catalog&software_id=' . (int)$s['id']) ?>" class="text-brand-600 dark:text-brand-400 hover:underline ml-1">Ver</a>
                                            <?php endif; ?>
                                        </td>
                                        <td class="px-4 py-3 text-xs font-medium <?= (int)($s['kev_count'] ?? 0) > 0 ? 'text-red-500' : 'text-gray-400' ?>">
                                            <?= number_format((int)($s['kev_count'] ?? 0)) ?>
                                        </td>
                                        <td class="px-4 py-3 text-xs font-medium <?= (int)($s['epss_high_count'] ?? 0) > 0 ? 'text-amber-500' : 'text-gray-400' ?>">
                                            <?= number_format((int)($s['epss_high_count'] ?? 0)) ?>
                                        </td>
                                        <td class="px-4 py-3 text-right whitespace-nowrap">
                                            <?php if ($isAdmin): ?>
                                                <a href="<?= base_url('modules/cve?tab=software&edit_software=' . (int)$s['id']) ?>" class="text-xs text-gray-400 hover:text-brand-500 mr-2">Editar</a>
                                                <?php if ((int)($s['cpe_count'] ?? 0) > 0): ?>
                                                    <form method="POST" action="<?= base_url('modules/cve/software/backfill') ?>" class="inline mr-2">
                                                        <?= Csrf::field() ?>
                                                        <input type="hidden" name="id" value="<?= (int)$s['id'] ?>">
                                                        <button type="submit" class="text-xs text-gray-400 hover:text-brand-500">Sincronizar</button>
                                                    </form>
                                                <?php endif; ?>
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
                $cpeValue = (string)($sw['cpe_list'] ?? $sw['cpe_name'] ?? '');
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
                        <label class="block text-xs text-gray-500 mb-1">CPEs (uno por línea)</label>
                        <textarea name="cpe_list" id="cve-cpe-list" rows="3"
                                  placeholder="cpe:2.3:a:google:chrome&#10;cpe:2.3:a:google:chrome_os"
                                  class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono focus:ring-2 focus:ring-brand-500 outline-none"><?= e($cpeValue) ?></textarea>
                        <div class="flex items-center gap-2 mt-2">
                            <input type="text" id="cve-cpe-query" placeholder="Buscar en NVD: Chrome, Adobe Acrobat…"
                                   class="flex-1 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none"
                                   onkeydown="if (event.key === 'Enter') { event.preventDefault(); cveSearchCpe(); }">
                            <button type="button" onclick="cveSearchCpe()"
                                    class="px-3 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">
                                Buscar CPE
                            </button>
                        </div>
                        <div id="cve-cpe-results" class="mt-2 space-y-1"></div>
                        <p class="text-xs text-gray-400 mt-1">
                            Formato NVD: <code class="font-mono">cpe:2.3:a:vendor:product</code>. Puedes añadir varios CPE; el primero será el principal.
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

    <script>
    (function () {
        var searchUrl = '<?= base_url('modules/cve/cpe-search') ?>';
        var input = document.getElementById('cve-cpe-query');
        var results = document.getElementById('cve-cpe-results');
        var list = document.getElementById('cve-cpe-list');

        function esc(s) {
            var d = document.createElement('div');
            d.textContent = s || '';
            return d.innerHTML;
        }

        function addCpe(cpe) {
            if (!list || !cpe) return;
            var lines = list.value.split(/\r?\n/).map(function (v) { return v.trim(); }).filter(Boolean);
            if (lines.indexOf(cpe) === -1) {
                lines.push(cpe);
                list.value = lines.join('\n');
            }
        }

        window.cveSearchCpe = function () {
            var q = input ? input.value.trim() : '';
            if (!results || q.length < 2) return;
            results.innerHTML = '<p class="text-xs text-gray-400">Buscando en NVD…</p>';
            api('GET', searchUrl + '?q=' + encodeURIComponent(q)).then(function (res) {
                if (!res || !res.success) {
                    results.innerHTML = '<p class="text-xs text-red-500">' + esc((res && res.error) ? res.error : 'Error al buscar CPE.') + '</p>';
                    return;
                }
                var items = res.results || [];
                if (!items.length) {
                    results.innerHTML = '<p class="text-xs text-gray-400">Sin resultados. Puedes escribir el CPE manualmente.</p>';
                    return;
                }
                results.innerHTML = items.map(function (item) {
                    return '<button type="button" class="block w-full text-left px-3 py-2 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark" data-cpe="' + esc(item.cpe) + '">'
                        + '<span class="block text-xs font-medium">' + esc(item.title || item.cpe) + '</span>'
                        + '<span class="block text-[10px] font-mono text-gray-400">' + esc(item.cpe) + '</span>'
                        + '</button>';
                }).join('');
                results.querySelectorAll('button[data-cpe]').forEach(function (btn) {
                    btn.addEventListener('click', function () {
                        addCpe(btn.getAttribute('data-cpe') || '');
                    });
                });
            }).catch(function () {
                results.innerHTML = '<p class="text-xs text-red-500">Error de conexión al buscar CPE.</p>';
            });
        };
    })();
    </script>
<?php endif; ?>
