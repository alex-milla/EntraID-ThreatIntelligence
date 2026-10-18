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

$aiReports = is_array($aiReports ?? null) ? $aiReports : [];
$llmProfiles = is_array($llmProfiles ?? null) ? $llmProfiles : [];
$llmConfigured = !empty($llmConfigured);
$aiStatusLabels = [
    'pending' => 'En cola',
    'running' => 'Generando',
    'done'    => 'Listo',
    'error'   => 'Error IA',
];
$aiStatusClasses = [
    'pending' => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
    'running' => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    'done'    => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'error'   => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
];
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

<div class="no-print mb-6 flex items-start justify-between gap-4 flex-wrap">
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

<?php require __DIR__ . '/_tabs.php'; ?>

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
    $showStep = $isAdmin && $syncRunning && $syncAge > 30;
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
                        <span class="text-amber-600 dark:text-amber-400">Sin progreso reciente; pulsa «Continuar» para retomar la descarga.</span>
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
            <p class="text-[11px] text-gray-400 mt-1">
                La descarga continua se ejecuta en esta pestaña. Si la cierras, se reanuda desde el último CVE al volver.
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
                <label class="block w-full mt-1">
                    <span class="block text-[10px] font-semibold uppercase tracking-wide text-gray-400 mb-1">
                        Pegar CVEs (separados por comas, espacios o líneas; máximo 200)
                    </span>
                    <textarea name="cves" rows="2" maxlength="6000" placeholder="CVE-2024-38063&#10;CVE-2024-21762, CVE-2023-48795"
                              class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs font-mono focus:ring-2 focus:ring-brand-500 outline-none"><?= e((string)($catalogFilters['cves'] ?? '')) ?></textarea>
                    <span class="block text-[10px] text-gray-400 mt-1">Se muestran solo los que estén en el catálogo local y tengan formato CVE-AAAA-NNNN.</span>
                </label>
                <button type="submit" class="px-3 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs font-medium rounded-lg transition-colors">Filtrar / Mostrar</button>
                <?php if (!empty($catalogFilters['q']) || !empty($catalogFilters['severity']) || !empty($catalogFilters['product']) || !empty($catalogFilters['kev']) || (string)($catalogFilters['epss_min'] ?? '') !== '' || (int)($catalogFilters['group'] ?? 0) > 0 || (int)($catalogFilters['software_id'] ?? 0) > 0 || !empty($catalogFilters['mine']) || (string)($catalogFilters['sort'] ?? 'published') !== 'published' || !empty($catalogFilters['cves'])): ?>
                    <a href="<?= base_url('modules/cve?tab=catalog') ?>" class="text-xs text-gray-400 hover:underline">Limpiar</a>
                <?php endif; ?>
            </form>
        </div>

        <?php if (($cvesMissing ?? []) !== []): ?>
            <div class="px-5 py-3 border-b border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 text-xs text-amber-700 dark:text-amber-300">
                <strong>No están en el catálogo local (<?= count($cvesMissing) ?>):</strong>
                <span class="font-mono break-all">
                    <?= e(implode(', ', array_slice($cvesMissing, 0, 20))) ?><?= count($cvesMissing) > 20 ? ' …' : '' ?>
                </span>
                <span class="block mt-1 text-[11px] opacity-80">Sincroniza el catálogo NVD para poder mostrarlos y analizarlos.</span>
            </div>
        <?php endif; ?>

        <?php if ($isAdmin && $catalog !== []): ?>
            <div class="px-5 py-2 border-b border-gray-200 dark:border-gray-700 flex items-center gap-3 flex-wrap bg-gray-50 dark:bg-gray-800/40">
                <span id="catalog-selection-count" class="text-xs font-medium text-gray-600 dark:text-gray-300">0 seleccionados</span>
                <button type="button" id="catalog-send-ai" onclick="catalogSendToAi()" disabled
                        class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-medium rounded-lg transition-colors">
                    Enviar a informe con IA
                </button>
                <span class="text-[11px] text-gray-400">Máximo <?= (int)CveReportAi::MAX_CVES ?> CVEs por informe.</span>
            </div>
        <?php endif; ?>

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
                            <?php if ($isAdmin): ?>
                                <th class="text-left px-3 py-2 w-8">
                                    <input id="catalog-select-all" type="checkbox" title="Seleccionar todos los CVEs de esta página"
                                           class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                                </th>
                            <?php endif; ?>
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
                                <?php if ($isAdmin): ?>
                                    <td class="px-3 py-3 align-top">
                                        <input type="checkbox" class="catalog-cve-check rounded border-gray-300 text-brand-500 focus:ring-brand-500"
                                               data-cve="<?= e((string)$cve['cve_id']) ?>" value="<?= e((string)$cve['cve_id']) ?>"
                                               title="Seleccionar <?= e((string)$cve['cve_id']) ?>">
                                    </td>
                                <?php endif; ?>
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
        var STREAM_URL = '<?= base_url('modules/cve/stream') ?>';
        var CANCEL_URL = '<?= base_url('modules/cve/cancel') ?>';
        var STEP_URL = '<?= base_url('modules/cve/step') ?>';
        var wasRunning = <?= $syncRunning ? 'true' : 'false' ?>;
        var pollTimer = null;
        var streaming = false;
        var stopped = false;
        var streamRetries = 0;
        var lastProcessed = <?= (int)$syncProcessed ?>;
        var rateAt = 0;
        var rateProcessed = 0;
        var rateValue = 0;

        function parseDbTime(v) {
            if (!v) return 0;
            if (v.indexOf('T') >= 0) return Date.parse(v);
            return Date.parse(v.replace(' ', 'T') + 'Z');
        }

        function buildCounts(processed, total, phase) {
            var txt = processed.toLocaleString('es-ES') + (total > 0 ? ' / ' + total.toLocaleString('es-ES') : '') + ' CVEs procesados';
            if (rateValue > 0 && total > processed) {
                var left = (total - processed) / rateValue;
                var mins = Math.max(1, Math.round(left / 60));
                txt += ' · ' + rateValue.toFixed(1) + ' CVE/s · ~' + mins + ' min restantes';
            } else if (phase === 'kev' || phase === 'epss') {
                txt += ' · actualizando ' + phase.toUpperCase();
            }
            return txt;
        }

        function applyState(st) {
            if (!st) return;
            var processed = parseInt(st.processed || 0, 10);
            var total = parseInt(st.total || 0, 10);
            var pct = total > 0 ? Math.min(100, Math.round(processed / total * 100)) : 0;
            var bar = document.getElementById('cve-sync-progress');
            var counts = document.getElementById('cve-sync-counts');
            var msg = document.getElementById('cve-sync-message');
            var badge = document.getElementById('cve-sync-status');
            var progress = document.getElementById('cve-sync-progress-wrap');

            var now = Date.now();
            if (rateAt > 0 && processed > rateProcessed) {
                var dt = (now - rateAt) / 1000;
                if (dt > 0.5) { rateValue = (processed - rateProcessed) / dt; }
            }
            if (processed !== rateProcessed) { rateAt = now; rateProcessed = processed; }
            if (processed > lastProcessed) { lastProcessed = processed; streamRetries = 0; }

            if (bar) bar.style.width = pct + '%';
            if (counts) counts.textContent = buildCounts(processed, total, st.phase || '');
            if (msg && st.message) msg.textContent = st.message;
            if (badge) {
                badge.textContent = (st.status === 'queued' || st.status === 'running' || !st.status)
                    ? 'Sincronizando'
                    : (st.status || 'idle');
            }
            if (progress) progress.classList.remove('hidden');
        }

        function setRunningUi(running) {
            var start = document.getElementById('cve-start-btn');
            var rebuild = document.getElementById('cve-rebuild-btn');
            var sources = document.getElementById('cve-sources-btn');
            var cancel = document.getElementById('cve-cancel-btn');
            var progress = document.getElementById('cve-sync-progress-wrap');
            if (start) start.classList.toggle('hidden', running);
            if (rebuild) rebuild.classList.toggle('hidden', running);
            if (sources) sources.classList.toggle('hidden', running);
            if (cancel) cancel.classList.toggle('hidden', !running);
            if (progress) progress.classList.toggle('hidden', !running);
        }

        function showResumeButton(label) {
            var step = document.getElementById('cve-step-btn');
            if (!step) return;
            step.classList.remove('hidden');
            step.textContent = label || 'Reanudar';
            step.setAttribute('onclick', 'resumeCveSync()');
        }

        function showError(message, errorId) {
            var prefix = errorId ? ('Error #' + errorId + ': ') : 'Error: ';
            toast(prefix + (message || 'La sincronización se detuvo'), 'error');
            var msg = document.getElementById('cve-sync-message');
            if (msg) msg.textContent = prefix + (message || '');
            var badge = document.getElementById('cve-sync-status');
            if (badge) badge.textContent = 'Error';
        }

        window.startCveSync = function(mode) {
            mode = mode || 'auto';
            var message = '';
            if (mode === 'full') {
                message = 'Se reconstruirá el catálogo completo. Puede tardar bastante. ¿Continuar?';
            } else if (mode === 'kev') {
                message = 'Se actualizarán solo CISA KEV y EPSS. ¿Continuar?';
            }

            if (message !== '') {
                appConfirm(message, {
                    title: mode === 'full' ? 'Reconstruir catálogo' : 'Actualizar KEV y EPSS',
                    danger: mode === 'full',
                    confirmText: mode === 'full' ? 'Reconstruir' : 'Actualizar'
                }).then(function(ok) {
                    if (ok) {
                        startCveSyncNow(mode);
                    }
                });
                return;
            }

            startCveSyncNow(mode);
        };

        function startCveSyncNow(mode) {
            api('POST', SYNC_URL, { mode: mode, stream: true }).then(function(res) {
                if (!res || !res.success) {
                    // Si ya había un job activo, lo retomamos en vez de fallar.
                    var err = (res && res.error) ? String(res.error) : '';
                    if (err.indexOf('Ya hay una sincronización') >= 0) {
                        setRunningUi(true);
                        streamLoop();
                        return;
                    }
                    toast(err || 'No se pudo iniciar', 'error');
                    return;
                }
                toast(res.message || 'Sincronización iniciada', 'success');
                setRunningUi(true);
                var step = document.getElementById('cve-step-btn');
                if (step) {
                    step.textContent = 'Continuar';
                    step.setAttribute('onclick', 'stepCveSync()');
                    step.classList.add('hidden');
                }
                stopped = false;
                streamRetries = 0;
                streamLoop();
            }).catch(function() { toast('Error de conexión', 'error'); });
        }

        window.resumeCveSync = function() {
            stopped = false;
            streamRetries = 0;
            window.startCveSync('auto');
        };

        window.cancelCveSync = function() {
            stopped = true;
            api('POST', CANCEL_URL, {}).then(function() {
                toast('Sincronización cancelada', 'success');
                setTimeout(function() { location.reload(); }, 800);
            }).catch(function() { toast('Error de conexión', 'error'); });
        };

        window.stepCveSync = function() {
            var btn = document.getElementById('cve-step-btn');
            if (btn) { btn.disabled = true; btn.textContent = 'Procesando…'; }
            api('POST', STEP_URL, { seconds: 30 }).then(function(res) {
                var r = (res && res.result) ? res.result : {};
                if (r && r.state) { applyState(r.state); }
                if (!res || !res.success) {
                    var err = (res && res.error) || (r && r.error) || '';
                    if (err) {
                        showError(err, (res && res.error_id) || (r && r.error_id) || 0);
                        return;
                    }
                    toast('No se pudo procesar el tramo', 'error');
                    return;
                }
                if (r.done) {
                    toast('Sincronización completada', 'success');
                    setTimeout(function() { location.reload(); }, 900);
                    return;
                }
                streamLoop();
            }).catch(function() { toast('Error de conexión', 'error'); })
              .finally(function() {
                  if (btn) { btn.disabled = false; }
                  var step = document.getElementById('cve-step-btn');
                  if (step && step.textContent === 'Procesando…') step.textContent = 'Continuar';
              });
        };

        function handleEvent(evt) {
            if (!evt || !evt.type) return null;
            if (evt.type === 'start') { applyState(evt.state); return null; }
            if (evt.type === 'progress') {
                applyState({
                    processed: evt.processed,
                    total: evt.total,
                    message: evt.message,
                    phase: evt.phase,
                    status: 'running'
                });
                return null;
            }
            if (evt.type === 'phase') {
                applyState({ processed: evt.processed, total: evt.total, message: evt.message, phase: evt.phase, status: 'running' });
                return null;
            }
            if (evt.type === 'partial') { applyState(evt.state); return 'partial'; }
            if (evt.type === 'done') { applyState(evt.state); return 'done'; }
            if (evt.type === 'idle') {
                applyState(evt.state);
                if (evt.state && evt.state.status === 'error') {
                    showError(evt.state.message || '', 0);
                    return 'error';
                }
                return 'idle';
            }
            if (evt.type === 'error') {
                showError(evt.error || evt.message || '', evt.error_id || 0);
                return 'error';
            }
            return null;
        }

        function streamOnce() {
            return fetch(STREAM_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': getCsrfToken()
                },
                credentials: 'same-origin',
                cache: 'no-store',
                body: '{}'
            }).then(function(res) {
                if (res.status === 401) {
                    window.location.href = (window.APP_URL || '') + '/admin/login';
                    throw new Error('No autorizado');
                }
                if (!res.ok) {
                    throw new Error('HTTP ' + res.status);
                }
                if (!res.body || !res.body.getReader) {
                    return 'fallback';
                }
                var reader = res.body.getReader();
                var decoder = new TextDecoder('utf-8');
                var buffer = '';
                var outcome = 'interrupted';

                function pump() {
                    return reader.read().then(function(r) {
                        if (r.done) { return outcome; }
                        buffer += decoder.decode(r.value, { stream: true });
                        var idx;
                        while ((idx = buffer.indexOf('\n')) >= 0) {
                            var line = buffer.slice(0, idx).trim();
                            buffer = buffer.slice(idx + 1);
                            if (!line) { continue; }
                            var evt;
                            try { evt = JSON.parse(line); } catch (e) { continue; }
                            var result = handleEvent(evt);
                            if (result) {
                                outcome = result;
                                try { reader.cancel(); } catch (e) {}
                                return outcome;
                            }
                        }
                        return pump();
                    });
                }
                return pump();
            });
        }

        function streamLoop() {
            if (stopped) { return; }
            streaming = true;
            streamOnce().then(function(outcome) {
                if (outcome === 'done') {
                    stopped = true;
                    streaming = false;
                    toast('Sincronización completada', 'success');
                    setTimeout(function() { location.reload(); }, 1200);
                    return;
                }
                if (outcome === 'error') { stopped = true; streaming = false; setRunningUi(false); showResumeButton('Reanudar'); return; }
                if (outcome === 'idle') { stopped = true; streaming = false; setTimeout(function() { location.reload(); }, 800); return; }
                if (outcome === 'fallback') { stepFallback(); return; }
                if (outcome === 'partial') {
                    setTimeout(streamLoop, 150);
                    return;
                }
                // Conexión cortada por el hosting: reconectar y seguir desde el cursor.
                streamRetries++;
                if (streamRetries > 6) {
                    streaming = false;
                    toast('La descarga se ha interrumpido. Pulsa «Reanudar» para continuar.', 'error');
                    showResumeButton('Reanudar');
                    return;
                }
                var wait = Math.min(15000, 1000 * Math.pow(2, streamRetries));
                setTimeout(streamLoop, wait);
            }).catch(function() {
                streamRetries++;
                if (streamRetries > 6) {
                    streaming = false;
                    toast('La descarga se ha interrumpido. Pulsa «Reanudar» para continuar.', 'error');
                    showResumeButton('Reanudar');
                    return;
                }
                setTimeout(streamLoop, Math.min(15000, 500 * Math.pow(2, streamRetries)));
            });
        }

        function stepFallback() {
            if (stopped) { return; }
            api('POST', STEP_URL, { seconds: 30 }).then(function(res) {
                var r = (res && res.result) ? res.result : {};
                if (r && r.state) { applyState(r.state); }
                if (!res || !res.success) {
                    var err = (res && res.error) || (r && r.error) || '';
                    if (err) {
                        stopped = true;
                        streaming = false;
                        showError(err, (res && res.error_id) || (r && r.error_id) || 0);
                        showResumeButton('Reanudar');
                        return;
                    }
                }
                if (r.done) {
                    stopped = true;
                    streaming = false;
                    toast('Sincronización completada', 'success');
                    setTimeout(function() { location.reload(); }, 1000);
                    return;
                }
                streamRetries = 0;
                setTimeout(stepFallback, 200);
            }).catch(function() {
                streamRetries++;
                if (streamRetries > 6) {
                    streaming = false;
                    showResumeButton('Reanudar');
                    return;
                }
                setTimeout(stepFallback, Math.min(15000, 1500 * streamRetries));
            });
        }

        function pollCveSync() {
            if (pollTimer) clearTimeout(pollTimer);
            api('GET', STATUS_URL).then(function(res) {
                if (!res || !res.state) return;
                var s = res.state;
                var running = s.status === 'queued' || s.status === 'running';
                applyState(s);
                var start = document.getElementById('cve-start-btn');
                var rebuild = document.getElementById('cve-rebuild-btn');
                var sources = document.getElementById('cve-sources-btn');
                var cancel = document.getElementById('cve-cancel-btn');
                var progress = document.getElementById('cve-sync-progress-wrap');
                if (start) start.classList.toggle('hidden', running);
                if (rebuild) rebuild.classList.toggle('hidden', running);
                if (sources) sources.classList.toggle('hidden', running);
                if (cancel) cancel.classList.toggle('hidden', !running);
                if (progress) progress.classList.toggle('hidden', !running && s.status !== 'error');
                if (running && !streaming) {
                    var updated = parseDbTime(s.updated_at || '');
                    var stale = !updated || (Date.now() - updated) > 30000;
                    if (stale) { showResumeButton('Continuar'); }
                }
                if (running || streaming) {
                    pollTimer = setTimeout(pollCveSync, 5000);
                }
            }).catch(function() {
                if (wasRunning || streaming) {
                    pollTimer = setTimeout(pollCveSync, 10000);
                }
            });
        }

        if (wasRunning) {
            pollCveSync();
        }
    })();
    </script>
    <?php endif; ?>

    <script>
    (function () {
        'use strict';
        var checks = Array.prototype.slice.call(document.querySelectorAll('.catalog-cve-check'));
        var selectAll = document.getElementById('catalog-select-all');
        var countEl = document.getElementById('catalog-selection-count');
        var sendBtn = document.getElementById('catalog-send-ai');
        var MAX_CVES = <?= (int)CveReportAi::MAX_CVES ?>;
        var REPORTS_URL = <?= json_encode(base_url('modules/cve?tab=reports')) ?>;

        if (!checks.length) {
            return;
        }

        function selectedIds() {
            return checks.filter(function (checkbox) {
                return checkbox.checked;
            }).map(function (checkbox) {
                return checkbox.dataset.cve || checkbox.value;
            });
        }

        function updateSelection() {
            var ids = selectedIds();
            if (countEl) {
                countEl.textContent = ids.length + (ids.length === 1 ? ' seleccionado' : ' seleccionados');
            }
            if (sendBtn) {
                sendBtn.disabled = ids.length === 0;
            }
            if (selectAll) {
                selectAll.checked = ids.length > 0 && ids.length === checks.length;
                selectAll.indeterminate = ids.length > 0 && ids.length < checks.length;
            }
        }

        checks.forEach(function (checkbox) {
            checkbox.addEventListener('change', updateSelection);
        });

        if (selectAll) {
            selectAll.addEventListener('change', function () {
                checks.forEach(function (checkbox) {
                    checkbox.checked = selectAll.checked;
                });
                updateSelection();
            });
        }

        window.catalogSendToAi = function () {
            var ids = selectedIds();
            if (ids.length === 0) {
                return;
            }
            if (ids.length > MAX_CVES) {
                appAlert('Has seleccionado ' + ids.length + ' CVEs. El máximo por informe es ' + MAX_CVES
                    + '. Reduce la selección o divídelos en varios informes.', { title: 'Demasiados CVEs' });
                return;
            }
            window.location.href = REPORTS_URL + '&new_cves=' + encodeURIComponent(ids.join(','));
        };

        updateSelection();
    })();
    </script>
<?php elseif ($tab === 'reports'): ?>

<?php
$aiStatusLabels = [
    'pending'  => 'En cola',
    'running'  => 'Generando',
    'done'     => 'Listo',
    'error'    => 'Error IA',
    'canceled' => 'Cancelado',
];
$aiStatusDots = [
    'pending'  => 'bg-gray-400',
    'running'  => 'bg-blue-500',
    'done'     => 'bg-green-500',
    'error'    => 'bg-red-500',
    'canceled' => 'bg-amber-500',
];
$aiStatusText = [
    'pending'  => 'text-gray-500',
    'running'  => 'text-blue-600 dark:text-blue-400',
    'done'     => 'text-green-600 dark:text-green-400',
    'error'    => 'text-red-600 dark:text-red-400',
    'canceled' => 'text-amber-600 dark:text-amber-400',
];
?>

<div class="no-print mb-4 flex items-center justify-between gap-3 flex-wrap">
    <div>
        <h2 class="text-lg font-bold">Informes</h2>
        <p class="text-xs text-gray-400">Selecciona un informe para verlo aquí mismo, o crea uno nuevo con IA.</p>
    </div>
    <button type="button" onclick="toggleCveAiFullscreen()"
            class="no-print inline-flex items-center gap-2 px-3 py-2 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M4 8V4h4M20 8V4h-4M4 16v4h4M20 16v4h-4"/></svg>
        Pantalla completa
    </button>
</div>

<div id="ai-workspace"
     class="ai-workspace bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden flex flex-col lg:flex-row"
     style="height: calc(100vh - 215px); min-height: 540px;">

    <!-- Panel izquierdo: lista de informes -->
    <aside class="no-print w-full lg:w-[340px] shrink-0 border-b lg:border-b-0 lg:border-r border-gray-200 dark:border-gray-700 flex flex-col max-h-[42vh] lg:max-h-none">
        <div class="p-3 border-b border-gray-200 dark:border-gray-700">
            <?php if ($isAdmin): ?>
                <button type="button" onclick="cveAiNew()"
                        class="w-full px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition-colors">
                    + Nuevo informe con IA
                </button>
                <button type="button" onclick="cveAiDefenderOpen()"
                        class="mt-2 w-full px-3 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 text-xs font-semibold rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                    Desde Defender
                </button>
            <?php endif; ?>
            <input id="ai-list-search" type="search" oninput="cveAiFilterList(this.value)"
                   placeholder="Buscar por CVE o título…"
                   class="mt-2 w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            <?php if ($isAdmin): ?>
                <div class="mt-2 flex items-center gap-2 text-[11px]">
                    <label class="inline-flex items-center gap-1.5 text-gray-500 dark:text-gray-400 cursor-pointer">
                        <input id="ai-reports-select-all" type="checkbox"
                               class="rounded border-gray-300 text-brand-500 focus:ring-brand-500"
                               title="Seleccionar todos los informes visibles">
                        Todos
                    </label>
                    <span id="ai-reports-selected-count" class="text-gray-500 dark:text-gray-400"></span>
                    <button type="button" id="ai-reports-bulk-delete" onclick="cveAiBulkDelete()"
                            class="hidden ml-auto px-2 py-1 rounded border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 font-medium hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors">
                        Eliminar
                    </button>
                </div>
            <?php endif; ?>
        </div>

        <div id="ai-report-list" class="flex-1 overflow-y-auto">
            <?php if (empty($aiReports)): ?>
                <div class="p-5 text-center text-xs text-gray-500">
                    Todavía no hay informes con IA.
                </div>
            <?php else: ?>
                <?php foreach ($aiReports as $aiRow): ?>
                    <?php
                    $aiRowId = (int)$aiRow['id'];
                    $aiRowStatus = (string)($aiRow['status'] ?? 'pending');
                    $aiRowIds = safe_json_decode((string)($aiRow['cve_ids'] ?? ''), []);
                    if (!is_array($aiRowIds)) {
                        $aiRowIds = [];
                    }
                    $aiRowLabel = count($aiRowIds) === 1
                        ? (string)($aiRowIds[0] ?? '')
                        : count($aiRowIds) . ' CVEs';
                    $aiSearch = strtolower(implode(' ', array_map('strval', $aiRowIds)) . ' ' . (string)$aiRow['title']);
                    $aiRowTags = CveReportAi::decodeTags((string)($aiRow['tags'] ?? ''));
                    ?>
                    <div class="ai-report-item group border-b border-gray-100 dark:border-gray-800 px-3 py-2.5 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/40 <?= $selectedAiId === $aiRowId ? 'bg-brand-50 dark:bg-brand-950/40' : '' ?>"
                         data-id="<?= $aiRowId ?>"
                         data-status="<?= e($aiRowStatus) ?>"
                         data-search="<?= e($aiSearch) ?>"
                         role="button" tabindex="0"
                         onclick="cveAiSelect(<?= $aiRowId ?>)"
                         onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); cveAiSelect(<?= $aiRowId ?>); }">
                        <div class="flex items-center gap-2">
                            <?php if ($isAdmin): ?>
                                <input type="checkbox" class="ai-report-check rounded border-gray-300 text-brand-500 focus:ring-brand-500 shrink-0"
                                       data-id="<?= $aiRowId ?>" title="Seleccionar informe"
                                       onclick="event.stopPropagation()" onkeydown="event.stopPropagation()">
                            <?php endif; ?>
                            <span class="ai-status-dot w-2 h-2 rounded-full shrink-0 <?= $aiStatusDots[$aiRowStatus] ?? $aiStatusDots['pending'] ?>"></span>
                            <span class="text-xs font-mono font-medium truncate"><?= e($aiRowLabel) ?></span>
                            <span class="ml-auto text-[10px] text-gray-400 shrink-0"><?= e(format_db_date((string)($aiRow['created_at'] ?? ''), 'd/m H:i')) ?></span>
                        </div>
                        <div class="flex items-center gap-2 mt-1 pl-4">
                            <span class="ai-status-text text-[10px] font-medium <?= $aiStatusText[$aiRowStatus] ?? $aiStatusText['pending'] ?>">
                                <?= e($aiStatusLabels[$aiRowStatus] ?? $aiRowStatus) ?>
                            </span>
                            <?php if (in_array($aiRowStatus, ['pending', 'running'], true) && (int)($aiRow['total_items'] ?? 0) > 0): ?>
                                <span class="text-[10px] text-gray-400">
                                    <?= (int)($aiRow['processed_items'] ?? 0) ?>/<?= (int)$aiRow['total_items'] ?>
                                </span>
                            <?php endif; ?>
                            <span class="text-[10px] text-gray-400 truncate">
                                <?= e((string)($aiRow['ai_model'] ?? '')) ?>
                            </span>
                            <?php if ((int)($aiRow['revision'] ?? 1) > 1): ?>
                                <span class="text-[10px] font-semibold text-gray-500 shrink-0">v<?= (int)$aiRow['revision'] ?></span>
                            <?php endif; ?>
                            <?php if (!empty($aiRow['group_name'])): ?>
                                <span class="text-[10px] text-gray-400 truncate">· <?= e((string)$aiRow['group_name']) ?></span>
                            <?php endif; ?>
                            <?php if (!empty($aiRow['item_groups'])): ?>
                                <span class="text-[10px] text-gray-400 truncate">· <?= e((string)$aiRow['item_groups']) ?></span>
                            <?php endif; ?>
                            <?php if (!empty($aiRow['has_defender'])): ?>
                                <span class="px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 text-[10px] font-semibold shrink-0">Defender</span>
                            <?php endif; ?>
                            <span class="ml-auto flex items-center gap-1 shrink-0">
                                <?php if ($isAdmin && in_array($aiRowStatus, ['pending', 'running'], true)): ?>
                                    <button type="button" title="Cancelar" onclick="event.stopPropagation(); cveAiCancel(<?= $aiRowId ?>)"
                                            class="p-1 rounded text-gray-400 hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                                    </button>
                                <?php endif; ?>
                                <?php if ($isAdmin && in_array($aiRowStatus, ['error', 'canceled'], true)): ?>
                                    <button type="button" title="Reintentar" onclick="event.stopPropagation(); cveAiRetry(<?= $aiRowId ?>)"
                                            class="p-1 rounded text-gray-400 hover:text-brand-600 hover:bg-brand-50 dark:hover:bg-brand-950">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M4 4v5h5M20 20v-5h-5M5.3 9A7 7 0 0118 6.3M18.7 15A7 7 0 016 17.7"/></svg>
                                    </button>
                                <?php endif; ?>
                                <?php if ($isAdmin): ?>
                                    <button type="button" title="Eliminar" onclick="event.stopPropagation(); cveAiDelete(<?= $aiRowId ?>)"
                                            class="p-1 rounded text-gray-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                                    </button>
                                <?php endif; ?>
                            </span>
                        </div>
                        <?php if ($aiRowTags !== []): ?>
                            <div class="flex items-center gap-1.5 flex-wrap mt-1 pl-4">
                                <?php foreach ($aiRowTags as $tag): ?>
                                    <span class="text-[9px] font-medium text-brand-600 dark:text-brand-400">#<?= e($tag) ?></span>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </aside>

    <!-- Panel derecho: informe seleccionado -->
    <section class="flex-1 min-w-0 flex flex-col">
        <div class="no-print px-4 py-2 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between gap-2">
            <p id="ai-detail-title" class="text-xs text-gray-500 truncate"></p>
            <div class="flex items-center gap-2 shrink-0 flex-wrap justify-end">
                <?php if ($isAdmin): ?>
                    <span id="ai-selection-count" class="hidden text-[11px] font-medium text-gray-600 dark:text-gray-300"></span>
                    <button type="button" id="ai-select-all-btn" onclick="cveAiSelectAll()"
                            class="hidden px-2 py-1 text-[11px] text-gray-500 hover:text-brand-600 transition-colors">
                        Todos
                    </button>
                    <button type="button" id="ai-tags-btn" onclick="cveAiTagsOpen()"
                            class="hidden px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                        Etiquetar
                    </button>
                    <button type="button" id="ai-items-group-btn" onclick="cveAiItemsGroupOpen()"
                            class="hidden px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                        Enviar seleccionados
                    </button>
                <?php endif; ?>
                <?php if ($isAdmin): ?>
                    <button type="button" id="ai-refresh-btn" onclick="cveAiRefresh()"
                            class="hidden px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                        Actualizar
                    </button>
                    <button type="button" id="ai-group-btn" onclick="cveAiAssignOpen()"
                            class="hidden px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                        Enviar informe a grupo
                    </button>
                <?php endif; ?>
                <button type="button" id="ai-print-btn" onclick="printCveAiReport()"
                        class="hidden px-3 py-1.5 bg-gray-900 hover:bg-black text-white text-xs font-medium rounded-lg transition-colors">
                    Imprimir / PDF
                </button>
                <?php if ($isAdmin): ?>
                    <button type="button" id="ai-delete-btn" onclick="cveAiDeleteSelected()"
                            class="hidden px-3 py-1.5 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 text-xs font-medium rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors">
                        Eliminar
                    </button>
                <?php endif; ?>
            </div>
        </div>

        <div id="ai-detail-scroll" class="flex-1 overflow-y-auto p-4 lg:p-6 bg-gray-50 dark:bg-gray-950/40">
            <div id="ai-detail">
                <?php if ($selectedAiData !== null): ?>
                    <?php
                    $report = $selectedAiData['report'];
                    $items = $selectedAiData['items'];
                    $aiText = $selectedAiData['aiText'];
                    $sections = $selectedAiData['sections'];
                    $defender = $selectedAiData['defender'] ?? null;
                    require __DIR__ . '/_ai_report_body.php';
                    ?>
                <?php else: ?>
                    <div id="ai-empty" class="h-full flex items-center justify-center">
                        <div class="text-center max-w-sm">
                            <svg class="w-10 h-10 mx-auto text-gray-300 dark:text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.4" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                            <p class="text-sm font-medium mt-3">Ningún informe seleccionado</p>
                            <p class="text-xs text-gray-500 mt-1">Elige un informe de la lista o crea uno nuevo con IA.</p>
                            <?php if ($isAdmin): ?>
                                <button type="button" onclick="cveAiNew()"
                                        class="mt-4 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition-colors">
                                    + Nuevo informe con IA
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Formulario de nuevo informe (oculto) -->
            <div id="ai-new-form" class="hidden">
                <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 max-w-3xl">
                    <div class="flex items-start justify-between gap-3 flex-wrap">
                        <div>
                            <h3 class="text-sm font-semibold">Nuevo informe con IA</h3>
                            <p class="text-xs text-gray-500 mt-1">
                                Introduce uno o varios CVEs (separados por comas). Los datos salen del catálogo local;
                                la IA redacta el análisis.
                            </p>
                        </div>
                        <button type="button" onclick="cveAiCancelNew()" class="text-xs text-gray-400 hover:text-gray-600">Cerrar</button>
                    </div>

                    <?php if (!$llmConfigured): ?>
                        <div class="mt-4 px-4 py-3 rounded-lg text-xs bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
                            La IA no está configurada todavía.
                            <a href="<?= base_url('admin/apis') ?>" class="font-semibold underline">Configúrala en Admin → APIs</a>
                            o marca «Solo datos locales».
                        </div>
                    <?php endif; ?>

                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 mt-4">
                        <label class="block lg:col-span-2">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">CVEs</span>
                            <input id="ai-report-cves" type="text" maxlength="500"
                                   placeholder="CVE-2024-38063, CVE-2024-21762, CVE-2023-48795"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs font-mono focus:ring-2 focus:ring-brand-500 outline-none">
                        </label>
                        <?php if (!empty($llmProfiles)): ?>
                            <label class="block">
                                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Perfil de IA</span>
                                <select id="ai-report-profile"
                                        class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                                    <option value="0">Automático (predeterminado)</option>
                                    <?php foreach ($llmProfiles as $profile): ?>
                                        <option value="<?= (int)$profile['id'] ?>">
                                            <?= e((string)$profile['name']) ?> · <?= e((string)$profile['provider']) ?><?= !empty($profile['model']) ? ' · ' . e((string)$profile['model']) : '' ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </label>
                        <?php endif; ?>
                        <label class="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-5">
                            <input id="ai-report-local" type="checkbox" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                            Solo datos locales (sin IA)
                        </label>
                    </div>

                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 mt-3">
                        <label class="block lg:col-span-2">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Tags / origen</span>
                            <input id="ai-report-tags" type="text" maxlength="500"
                                   placeholder="web, endpoint, cliente-acme (separados por comas)"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                        </label>
                        <label class="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-5">
                            <input id="ai-report-extended" type="checkbox" checked class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                            Análisis extendido por CVE
                        </label>
                    </div>

                    <div class="mt-4 flex items-center gap-3 flex-wrap">
                        <button type="button" onclick="cveAiGenerate(this)" id="ai-report-button"
                                class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                                <?= !$llmConfigured ? 'disabled' : '' ?>>
                            Generar informe con IA
                        </button>
                        <span id="ai-report-message" class="text-xs text-gray-500"></span>
                    </div>
                    <p class="text-[11px] text-gray-400 mt-2">
                        Máximo <?= (int)CveReportAi::MAX_CVES ?> CVEs por informe. El análisis extendido hace una llamada a la IA por CVE
                        y puede tardar varios minutos; verás el progreso en el informe.
                    </p>
                </div>
            </div>

            <!-- Nuevo informe desde Defender (oculto) -->
            <div id="ai-defender-form" class="hidden">
                <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                    <div class="flex items-start justify-between gap-3 flex-wrap">
                        <div>
                            <h3 class="text-sm font-semibold">Nuevo informe desde Defender</h3>
                            <p class="text-xs text-gray-500 mt-1">
                                Elige CVEs expuestos en tus equipos según Defender for Endpoint. El informe añadirá
                                la exposición real (equipos, productos y KB) a los datos del catálogo.
                            </p>
                        </div>
                        <button type="button" onclick="cveAiDefenderClose()" class="text-xs text-gray-400 hover:text-gray-600">Cerrar</button>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-4">
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Tenant</span>
                            <select id="ai-def-tenant" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                                <option value="0">Todos</option>
                            </select>
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Severidad</span>
                            <select id="ai-def-severity" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                                <option value="">Todas</option>
                                <option value="CRITICAL">Crítica</option>
                                <option value="HIGH">Alta</option>
                                <option value="MEDIUM">Media</option>
                                <option value="LOW">Baja</option>
                            </select>
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">EPSS mínimo</span>
                            <input id="ai-def-epss" type="number" min="0" max="1" step="0.01" placeholder="0.10"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Equipos mínimos</span>
                            <input id="ai-def-machines" type="number" min="0" step="1" placeholder="1"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                        </label>
                        <label class="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-5">
                            <input id="ai-def-exploited" type="checkbox" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                            Con exploit público
                        </label>
                        <label class="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-5">
                            <input id="ai-def-kev" type="checkbox" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                            En CISA KEV
                        </label>
                        <label class="block lg:col-span-2">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Buscar CVE</span>
                            <div class="flex gap-2">
                                <input id="ai-def-q" type="text" placeholder="CVE-2024-…"
                                       class="flex-1 px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs font-mono focus:ring-2 focus:ring-brand-500 outline-none">
                                <button type="button" onclick="cveAiDefenderFetch()"
                                        class="px-3 py-1.5 bg-gray-900 hover:bg-black text-white text-xs font-medium rounded-lg">
                                    Aplicar
                                </button>
                            </div>
                        </label>
                    </div>

                    <div class="mt-4 flex items-center justify-between gap-2 flex-wrap">
                        <p id="ai-def-summary" class="text-xs text-gray-500">Cargando…</p>
                        <p id="ai-def-selected" class="text-xs font-medium text-gray-600 dark:text-gray-300">0 seleccionados</p>
                    </div>

                    <div id="ai-def-list" class="mt-2 max-h-72 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-100 dark:divide-gray-800">
                        <p class="p-4 text-xs text-gray-500">Cargando vulnerabilidades de Defender…</p>
                    </div>

                    <div class="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <label class="block sm:col-span-2">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Tags / origen</span>
                            <input id="ai-def-tags" type="text" maxlength="500"
                                   placeholder="web, endpoint, cliente-acme (separados por comas)"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                        </label>
                        <label class="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-5">
                            <input id="ai-def-extended" type="checkbox" checked class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                            Análisis extendido por CVE
                        </label>
                    </div>

                    <div class="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <?php if (!empty($llmProfiles)): ?>
                            <label class="block sm:col-span-1">
                                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Perfil de IA</span>
                                <select id="ai-def-profile"
                                        class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                                    <option value="0">Automático</option>
                                    <?php foreach ($llmProfiles as $profile): ?>
                                        <option value="<?= (int)$profile['id'] ?>"><?= e((string)$profile['name']) ?> · <?= e((string)$profile['provider']) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </label>
                        <?php endif; ?>
                        <label class="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-5">
                            <input id="ai-def-local" type="checkbox" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                            Solo datos locales (sin IA)
                        </label>
                        <div class="flex items-end">
                            <button type="button" onclick="cveAiDefenderCreate(this)"
                                    class="w-full px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                                Crear informe
                            </button>
                        </div>
                    </div>
                    <p id="ai-def-message" class="text-xs text-gray-500 mt-2"></p>
                </div>
            </div>
        </div>
    </section>

    <!-- Modal: enviar a grupo -->
    <div id="ai-group-modal" class="hidden fixed inset-0 z-50 no-print">
        <div class="absolute inset-0 bg-black/40" onclick="cveAiAssignClose()"></div>
        <div class="relative mx-auto mt-24 w-[calc(100%-2rem)] max-w-md bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 shadow-xl p-5">
            <h3 class="text-sm font-semibold">Enviar informe a un grupo</h3>
            <p class="text-xs text-gray-500 mt-1">Asigna el informe a un grupo de aplicaciones. Si el grupo no existe, se crea.</p>
    
            <label class="block mt-4">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Grupo existente</span>
                <select id="ai-group-select"
                        class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="0">— Sin grupo —</option>
                    <?php foreach (($groups ?? []) as $group): ?>
                        <option value="<?= (int)$group['id'] ?>">
                            <?= str_repeat('— ', (int)($group['depth'] ?? 0)) . e((string)$group['name']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </label>
    
            <label class="block mt-3">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">o crear un grupo nuevo</span>
                <input id="ai-group-new" type="text" maxlength="120" placeholder="Nombre del grupo"
                       class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            </label>
    
            <div class="mt-4 flex items-center justify-end gap-2">
                <button type="button" onclick="cveAiAssignClose()"
                        class="px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">
                    Cancelar
                </button>
                <button type="button" onclick="cveAiAssignSubmit(this)"
                        class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg">
                    Enviar
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Modal: etiquetar CVEs seleccionados -->
<div id="ai-tags-modal" class="hidden fixed inset-0 z-50 no-print">
    <div class="absolute inset-0 bg-black/40" onclick="cveAiTagsClose()"></div>
    <div class="relative mx-auto mt-24 w-[calc(100%-2rem)] max-w-lg bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 shadow-xl p-5">
        <div class="flex items-start justify-between gap-3">
            <div>
                <h3 class="text-sm font-semibold">Etiquetar CVEs seleccionados</h3>
                <p class="text-xs text-gray-500 mt-1" id="ai-tags-count"></p>
            </div>
            <button type="button" onclick="cveAiTagsClose()" class="text-xs text-gray-400 hover:text-gray-600">Cerrar</button>
        </div>

        <label class="block mt-4">
            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Tags / origen</span>
            <input id="ai-tags-input" type="text" maxlength="500"
                   placeholder="web, endpoint, cliente-acme (separados por comas)"
                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
        </label>
        <label class="flex items-center gap-2 mt-2 text-[11px] text-gray-600 dark:text-gray-300">
            <input id="ai-tags-append" type="checkbox" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
            Añadir sin borrar los tags actuales
        </label>

        <div id="ai-tags-suggestions" class="hidden mt-4 space-y-2">
            <div id="ai-tags-suggestions-tags-wrap">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Tags usados</p>
                <div id="ai-tags-suggestions-tags" class="flex flex-wrap gap-1.5 mt-1"></div>
            </div>
            <div id="ai-tags-suggestions-groups-wrap">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Grupos de software detectados</p>
                <div id="ai-tags-suggestions-groups" class="flex flex-wrap gap-1.5 mt-1"></div>
            </div>
        </div>

        <div class="mt-4 flex items-center justify-end gap-2">
            <button type="button" onclick="cveAiTagsClose()"
                    class="px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">
                Cancelar
            </button>
            <button type="button" onclick="cveAiTagsSubmit(this)"
                    class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg">
                Aplicar tags
            </button>
        </div>
    </div>
</div>

<!-- Modal: enviar CVEs seleccionados a grupo -->
<div id="ai-items-group-modal" class="hidden fixed inset-0 z-50 no-print">
    <div class="absolute inset-0 bg-black/40" onclick="cveAiItemsGroupClose()"></div>
    <div class="relative mx-auto mt-24 w-[calc(100%-2rem)] max-w-md bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 shadow-xl p-5">
        <div class="flex items-start justify-between gap-3">
            <div>
                <h3 class="text-sm font-semibold">Enviar CVEs a un grupo</h3>
                <p class="text-xs text-gray-500 mt-1" id="ai-items-group-count"></p>
            </div>
            <button type="button" onclick="cveAiItemsGroupClose()" class="text-xs text-gray-400 hover:text-gray-600">Cerrar</button>
        </div>

        <label class="block mt-4">
            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Grupo existente</span>
            <select id="ai-items-group-select"
                    class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="0">— Sin grupo —</option>
                <?php foreach (($groups ?? []) as $group): ?>
                    <option value="<?= (int)$group['id'] ?>">
                        <?= str_repeat('— ', (int)($group['depth'] ?? 0)) . e((string)$group['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </label>

        <label class="block mt-3">
            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">o crear un grupo nuevo</span>
            <input id="ai-items-group-new" type="text" maxlength="120" placeholder="Nombre del grupo"
                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs focus:ring-2 focus:ring-brand-500 outline-none">
        </label>

        <div class="mt-4 flex items-center justify-end gap-2">
            <button type="button" onclick="cveAiItemsGroupClose()"
                    class="px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">
                Cancelar
            </button>
            <button type="button" onclick="cveAiItemsGroupSubmit(this)"
                    class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg">
                Enviar
            </button>
        </div>
    </div>
</div>

<!-- Informes preventivos (plegados) -->
<details class="no-print mt-6 bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <summary class="px-5 py-4 cursor-pointer text-sm font-semibold flex items-center gap-2">
        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 5l7 7-7 7"/></svg>
        Informes preventivos (inventario de software)
    </summary>
    <div class="p-5 border-t border-gray-200 dark:border-gray-700">
        <?php if ($isAdmin): ?>
        <div class="mb-5">
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

        <div class="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
            <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                <h4 class="text-xs font-semibold uppercase tracking-wide text-gray-500">Informes generados</h4>
            </div>
            <?php if (empty($reports)): ?>
                <div class="p-8 text-center text-sm text-gray-500">Todavía no hay informes preventivos.</div>
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
    </div>
</details>

<style>
    #ai-workspace:fullscreen {
        height: 100vh !important;
        min-height: 0 !important;
        border-radius: 0;
        border: 0;
    }
    @media print {
        .ai-workspace {
            height: auto !important;
            min-height: 0 !important;
            display: block !important;
            border: 0 !important;
            overflow: visible !important;
        }
        .ai-workspace > aside { display: none !important; }
        .ai-workspace > section { display: block !important; overflow: visible !important; }
        #ai-detail-scroll {
            overflow: visible !important;
            height: auto !important;
            padding: 0 !important;
            background: #fff !important;
        }
        #ai-detail { overflow: visible !important; }
        #ai-detail > * { max-width: none !important; }
    }
</style>

<script>
(function () {
    'use strict';

    var PAGE_URL   = <?= json_encode(base_url('modules/cve?tab=reports')) ?>;
    var PARTIAL    = <?= json_encode(base_url('modules/cve/report-ai')) ?>;
    var START_URL  = <?= json_encode(base_url('modules/cve/reports/ai-start')) ?>;
    var RUN_URL    = <?= json_encode(base_url('modules/cve/reports/ai-run')) ?>;
    var RETRY_URL  = <?= json_encode(base_url('modules/cve/reports/ai-retry')) ?>;
    var CANCEL_URL = <?= json_encode(base_url('modules/cve/reports/ai-cancel')) ?>;
    var DELETE_URL = <?= json_encode(base_url('modules/cve/reports/ai-delete')) ?>;
    var BULK_DELETE_URL = <?= json_encode(base_url('modules/cve/reports/ai-delete-bulk')) ?>;
    var STATUS_URL = <?= json_encode(base_url('modules/cve/reports/ai-status')) ?>;
    var REFRESH_URL = <?= json_encode(base_url('modules/cve/reports/ai-refresh')) ?>;
    var ASSIGN_URL  = <?= json_encode(base_url('modules/cve/reports/ai-assign')) ?>;
    var ITEM_TAGS_URL = <?= json_encode(base_url('modules/cve/reports/ai-item-tags')) ?>;
    var ITEM_GROUP_URL = <?= json_encode(base_url('modules/cve/reports/ai-assign-items')) ?>;
    var TAG_SUGGEST_URL = <?= json_encode(base_url('modules/cve/reports/ai-tag-suggestions')) ?>;
    var RETRY_ITEM_URL = <?= json_encode(base_url('modules/cve/reports/ai-retry-item')) ?>;
    var DEFENDER_LIST_URL  = <?= json_encode(base_url('modules/cve/reports/defender-list')) ?>;
    var START_DEFENDER_URL = <?= json_encode(base_url('modules/cve/reports/ai-start-defender')) ?>;
    var IS_ADMIN   = <?= $isAdmin ? 'true' : 'false' ?>;

    var detail = document.getElementById('ai-detail');
    var detailScroll = document.getElementById('ai-detail-scroll');
    var list = document.getElementById('ai-report-list');
    var reportsSelectAll = document.getElementById('ai-reports-select-all');
    var reportsSelectedCount = document.getElementById('ai-reports-selected-count');
    var reportsBulkDelete = document.getElementById('ai-reports-bulk-delete');
    var newForm = document.getElementById('ai-new-form');
    var printBtn = document.getElementById('ai-print-btn');
    var deleteBtn = document.getElementById('ai-delete-btn');
    var refreshBtn = document.getElementById('ai-refresh-btn');
    var groupBtn = document.getElementById('ai-group-btn');
    var tagsBtn = document.getElementById('ai-tags-btn');
    var itemsGroupBtn = document.getElementById('ai-items-group-btn');
    var selectionCount = document.getElementById('ai-selection-count');
    var selectAllBtn = document.getElementById('ai-select-all-btn');
    var titleEl = document.getElementById('ai-detail-title');

    var state = { id: 0, status: '', poll: null, running: false };

    function csrfToken() {
        var el = document.querySelector('input[name="csrf_token"]');
        return el ? el.value : '';
    }

    function parseResponse(res) {
        return res.text().then(function (text) {
            var contentType = (res.headers.get('content-type') || '').toLowerCase();
            var looksHtml = /^\s*</.test(text || '');
            if (res.status >= 500 && (looksHtml || contentType.indexOf('text/html') !== -1)) {
                var htmlErr = new Error(
                    'El servidor no respondió correctamente (HTTP ' + res.status
                    + '). Puede que la operación se haya completado; recarga para comprobarlo.'
                );
                htmlErr.httpStatus = res.status;
                htmlErr.serverHtml = true;
                htmlErr.body = text || '';
                throw htmlErr;
            }

            var payload;
            try {
                payload = text ? JSON.parse(text) : {};
            } catch (e) {
                var snippet = (text || '').replace(/\s+/g, ' ').trim().slice(0, 160);
                var err = new Error('HTTP ' + res.status + (snippet ? ' · ' + snippet : ''));
                err.httpStatus = res.status;
                throw err;
            }
            if (res.status === 401) {
                window.location.href = (window.APP_URL || '') + '/admin/login';
            }
            return payload;
        });
    }

    function postJson(url, data) {
        return fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': csrfToken()
            },
            credentials: 'same-origin',
            body: JSON.stringify(data || {})
        }).then(parseResponse);
    }

    function getJson(url) {
        return fetch(url, {
            headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
            credentials: 'same-origin'
        }).then(parseResponse);
    }

    function errorText(err) {
        return (err && err.message) ? err.message : 'error de red';
    }

    function setBanner(text) {
        var el = document.getElementById('ai-processing-text');
        if (el) {
            el.textContent = text;
        }
    }

    function stopPolling() {
        if (state.poll) {
            clearInterval(state.poll);
            state.poll = null;
        }
    }

    function startPolling() {
        if (!state.id || state.poll) {
            return;
        }
        state.poll = setInterval(function () {
            getJson(STATUS_URL + '/' + state.id).then(function (res) {
                if (!res || !res.success) {
                    return;
                }
                if (res.status === 'running') {
                    state.status = 'running';
                    updateToolbar();
                    var total = parseInt(res.total || 0, 10);
                    var processed = parseInt(res.processed || 0, 10);
                    if (total > 0) {
                        setBanner('Analizando CVE ' + Math.max(1, Math.min(processed + 1, total)) + ' de ' + total + '…');
                    }
                    var bar = document.getElementById('ai-processing-bar');
                    if (bar) {
                        bar.style.width = (parseInt(res.progress || 0, 10)) + '%';
                    }
                }
                if (res.status === 'done' || res.status === 'error' || res.status === 'canceled') {
                    stopPolling();
                    load(state.id, false);
                }
            }).catch(function () { /* se reintenta */ });
        }, 3000);
    }

    function updateToolbar() {
        var body = detail ? detail.querySelector('.ai-report-body') : null;
        var id = body ? parseInt(body.dataset.reportId, 10) || 0 : 0;
        var status = state.status || (body ? (body.dataset.status || '') : '');
        var processing = status === 'pending' || status === 'running';
        var running = status === 'running';

        if (printBtn) {
            printBtn.classList.toggle('hidden', !body || processing);
        }
        if (refreshBtn) {
            refreshBtn.classList.toggle('hidden', !IS_ADMIN || !id || processing);
        }
        if (groupBtn) {
            groupBtn.classList.toggle('hidden', !IS_ADMIN || !id);
            groupBtn.disabled = running;
            groupBtn.title = running ? 'Espera a que termine la generación para asignar el grupo' : '';
        }
        if (deleteBtn) {
            deleteBtn.classList.toggle('hidden', !IS_ADMIN || !id);
        }
        if (titleEl) {
            titleEl.textContent = body ? ('Informe #' + id) : '';
        }
        updateSelectionUI();
    }

    function selectedItemIds() {
        if (!detail) {
            return [];
        }
        return Array.prototype.slice.call(detail.querySelectorAll('.ai-cve-check:checked')).map(function (el) {
            return parseInt(el.dataset.itemId, 10) || 0;
        }).filter(function (id) {
            return id > 0;
        });
    }

    function updateSelectionUI() {
        var checks = detail ? detail.querySelectorAll('.ai-cve-check') : [];
        var ids = selectedItemIds();
        var count = ids.length;

        if (selectionCount) {
            selectionCount.textContent = count + (count === 1 ? ' seleccionado' : ' seleccionados');
            selectionCount.classList.toggle('hidden', !IS_ADMIN || count === 0);
        }
        if (tagsBtn) {
            tagsBtn.classList.toggle('hidden', !IS_ADMIN || count === 0);
        }
        if (itemsGroupBtn) {
            itemsGroupBtn.classList.toggle('hidden', !IS_ADMIN || count === 0);
        }
        if (selectAllBtn) {
            selectAllBtn.classList.toggle('hidden', !IS_ADMIN || checks.length === 0);
            selectAllBtn.textContent = (checks.length > 0 && count === checks.length) ? 'Ninguno' : 'Todos';
        }
    }

    window.cveAiSelectAll = function () {
        if (!detail) {
            return;
        }
        var checks = Array.prototype.slice.call(detail.querySelectorAll('.ai-cve-check'));
        if (checks.length === 0) {
            return;
        }
        var allSelected = checks.every(function (el) { return el.checked; });
        checks.forEach(function (el) { el.checked = !allSelected; });
        updateSelectionUI();
    };

    function markSelected(id) {
        if (!list) {
            return;
        }
        list.querySelectorAll('.ai-report-item').forEach(function (el) {
            var isSelected = parseInt(el.dataset.id, 10) === id;
            el.classList.toggle('bg-brand-50', isSelected);
            el.classList.toggle('dark:bg-brand-950/40', isSelected);
        });
    }

    function activate() {
        var body = detail ? detail.querySelector('.ai-report-body') : null;
        if (!body) {
            state.id = 0;
            state.status = '';
            updateToolbar();
            return;
        }

        state.id = parseInt(body.dataset.reportId, 10) || 0;
        state.status = body.dataset.status || '';
        markSelected(state.id);
        updateToolbar();

        if (state.status === 'pending') {
            runReport();
        } else if (state.status === 'running') {
            startPolling();
        }
    }

    function load(id, pushUrl) {
        if (!detail) {
            return;
        }
        stopPolling();
        if (newForm) {
            newForm.classList.add('hidden');
        }
        var defenderForm = document.getElementById('ai-defender-form');
        if (defenderForm) {
            defenderForm.classList.add('hidden');
        }
        detail.innerHTML = '<div class="p-8 text-center text-sm text-gray-500">Cargando informe…</div>';

        fetch(PARTIAL + '/' + id + '?partial=1', {
            headers: {'X-Requested-With': 'XMLHttpRequest'},
            credentials: 'same-origin'
        }).then(function (res) {
            if (!res.ok) {
                throw new Error('HTTP ' + res.status);
            }
            return res.text();
        }).then(function (html) {
            detail.innerHTML = html;
            if (pushUrl !== false && window.history && window.history.replaceState) {
                window.history.replaceState({}, '', PAGE_URL + '&report=' + id);
            }
            if (detailScroll) {
                detailScroll.scrollTop = 0;
            }
            activate();
        }).catch(function (err) {
            detail.innerHTML = '<div class="p-6 text-sm text-red-600">No se pudo cargar el informe: ' + errorText(err) + '</div>';
        });
    }

    function runReport() {
        if (!state.id || state.running) {
            return;
        }
        state.status = 'running';
        state.running = true;
        updateToolbar();
        startPolling();
        setBanner('Preparando el análisis… si la conexión se corta, seguiremos consultando el estado.');

        postJson(RUN_URL + '/' + state.id, {}).then(function (res) {
            if (res && (res.status === 'done' || res.status === 'error' || res.status === 'canceled' || res.url)) {
                stopPolling();
                load(state.id, false);
            } else if (res && res.error) {
                setBanner(res.error);
            }
        }).catch(function (err) {
            setBanner('No se pudo ejecutar: ' + errorText(err) + '. Seguimos comprobando el estado…');
            startPolling();
        }).then(function () {
            state.running = false;
        });
    }

    function withStateId(fn) {
        if (!state.id) {
            return;
        }
        fn(state.id);
    }

    window.cveAiSelect = function (id) {
        if (state.id === id && detail && detail.querySelector('.ai-report-body')) {
            return;
        }
        load(id);
    };

    window.runCveAiReport = runReport;
    window.cancelCveAiReport = function () {
        withStateId(function (id) {
            appConfirm('¿Cancelar la generación de este informe?', {
                title: 'Cancelar informe',
                danger: true,
                confirmText: 'Cancelar informe'
            }).then(function (ok) {
                if (!ok) {
                    return;
                }
                postJson(CANCEL_URL + '/' + id, {}).then(function (res) {
                    if (!res.success) {
                        appAlert(res.error || 'No se pudo cancelar el informe.', { title: 'No se pudo cancelar' });
                        return;
                    }
                    window.location.href = PAGE_URL + '&report=' + id;
                }).catch(function (err) {
                    appAlert('No se pudo cancelar: ' + errorText(err), { title: 'No se pudo cancelar' });
                });
            });
        });
    };
    window.retryCveAiReport = function () {
        withStateId(function (id) {
            postJson(RETRY_URL + '/' + id, {}).then(function (res) {
                if (!res.success) {
                    appAlert(res.error || 'No se pudo reintentar el informe.', { title: 'No se pudo reintentar' });
                    return;
                }
                window.location.href = PAGE_URL + '&report=' + id;
            }).catch(function (err) {
                appAlert('No se pudo reintentar: ' + errorText(err), { title: 'No se pudo reintentar' });
            });
        });
    };

    window.cveAiCancel = function (id) {
        appConfirm('¿Cancelar la generación de este informe?', {
            title: 'Cancelar informe',
            danger: true,
            confirmText: 'Cancelar informe'
        }).then(function (ok) {
            if (!ok) {
                return;
            }
            postJson(CANCEL_URL + '/' + id, {}).then(function (res) {
                if (!res.success) {
                    appAlert(res.error || 'No se pudo cancelar el informe.', { title: 'No se pudo cancelar' });
                    return;
                }
                window.location.href = PAGE_URL + '&report=' + id;
            }).catch(function (err) {
                appAlert('No se pudo cancelar: ' + errorText(err), { title: 'No se pudo cancelar' });
            });
        });
    };

    window.cveAiRetry = function (id) {
        postJson(RETRY_URL + '/' + id, {}).then(function (res) {
            if (!res.success) {
                appAlert(res.error || 'No se pudo reintentar el informe.', { title: 'No se pudo reintentar' });
                return;
            }
            window.location.href = PAGE_URL + '&report=' + id;
        }).catch(function (err) {
            appAlert('No se pudo reintentar: ' + errorText(err), { title: 'No se pudo reintentar' });
        });
    };

    function removeItem(id) {
        if (!list) {
            return null;
        }
        var el = list.querySelector('.ai-report-item[data-id="' + id + '"]');
        if (!el) {
            return null;
        }
        var nodes = Array.prototype.slice.call(list.querySelectorAll('.ai-report-item'));
        var idx = nodes.indexOf(el);
        var next = nodes[idx + 1] || nodes[idx - 1] || null;
        el.remove();
        updateReportSelection();
        return next ? parseInt(next.dataset.id, 10) : null;
    }

    window.cveAiDelete = function (id) {
        appConfirm('¿Eliminar el informe #' + id + '? Esta acción no se puede deshacer.', {
            title: 'Eliminar informe',
            danger: true,
            confirmText: 'Eliminar'
        }).then(function (ok) {
            if (!ok) {
                return;
            }
            postJson(DELETE_URL + '/' + id, {}).then(function (res) {
                if (!res.success) {
                    appAlert(res.error || 'No se pudo eliminar el informe.', { title: 'No se pudo eliminar' });
                    return;
                }
                var next = removeItem(id);
                if (state.id === id) {
                    if (next) {
                        load(next);
                    } else {
                        state.id = 0;
                        state.status = '';
                        detail.innerHTML = '<div class="h-full flex items-center justify-center"><div class="text-center"><p class="text-sm font-medium">Ningún informe seleccionado</p><p class="text-xs text-gray-500 mt-1">Elige un informe de la lista o crea uno nuevo con IA.</p></div></div>';
                        updateToolbar();
                        if (window.history && window.history.replaceState) {
                            window.history.replaceState({}, '', PAGE_URL);
                        }
                    }
                }
            }).catch(function (err) {
                appAlert('No se pudo eliminar: ' + errorText(err), { title: 'No se pudo eliminar' });
            });
        });
    };

    window.cveAiDeleteSelected = function () {
        withStateId(function (id) {
            window.cveAiDelete(id);
        });
    };

    window.cveAiNew = function () {
        stopPolling();
        if (detail) {
            detail.innerHTML = '';
        }
        var defenderForm = document.getElementById('ai-defender-form');
        if (defenderForm) {
            defenderForm.classList.add('hidden');
        }
        if (newForm) {
            newForm.classList.remove('hidden');
        }
        if (printBtn) {
            printBtn.classList.add('hidden');
        }
        if (deleteBtn) {
            deleteBtn.classList.add('hidden');
        }
        if (titleEl) {
            titleEl.textContent = 'Nuevo informe';
        }
        var input = document.getElementById('ai-report-cves');
        if (input) {
            input.focus();
        }
    };

    window.cveAiCancelNew = function () {
        if (newForm) {
            newForm.classList.add('hidden');
        }
        if (state.id) {
            load(state.id, false);
        } else {
            window.location.href = PAGE_URL;
        }
    };

    window.cveAiGenerate = function (button) {
        var input = document.getElementById('ai-report-cves');
        var profile = document.getElementById('ai-report-profile');
        var local = document.getElementById('ai-report-local');
        var tagsInput = document.getElementById('ai-report-tags');
        var extended = document.getElementById('ai-report-extended');
        var message = document.getElementById('ai-report-message');
        if (!input || !message) {
            return;
        }

        var cves = (input.value || '').trim();
        if (cves === '') {
            message.textContent = 'Introduce al menos un CVE.';
            message.className = 'text-xs text-red-500';
            input.focus();
            return;
        }

        var noAi = !!(local && local.checked);
        message.textContent = 'Creando informe…';
        message.className = 'text-xs text-gray-500';
        if (button) {
            button.disabled = true;
        }

        postJson(START_URL, {
            cve_ids: cves,
            profile_id: profile ? profile.value : 0,
            no_ai: noAi ? 1 : 0,
            tags: tagsInput ? tagsInput.value : '',
            mode: (extended && extended.checked) ? 'extended' : 'summary'
        }).then(function (res) {
            if (!res.success) {
                message.textContent = res.error || 'No se pudo crear el informe.';
                message.className = 'text-xs text-red-500';
                if (button) {
                    button.disabled = false;
                }
                return;
            }
            window.location.href = PAGE_URL + '&report=' + res.report_id;
        }).catch(function (err) {
            message.textContent = 'No se pudo crear: ' + errorText(err);
            message.className = 'text-xs text-red-500';
            if (button) {
                button.disabled = false;
            }
        });
    };

    function visibleReportChecks() {
        if (!list) {
            return [];
        }
        return Array.prototype.slice.call(
            list.querySelectorAll('.ai-report-item:not(.hidden) .ai-report-check')
        );
    }

    function reportSelectedIds() {
        if (!list) {
            return [];
        }
        return Array.prototype.slice.call(list.querySelectorAll('.ai-report-check:checked'))
            .map(function (checkbox) {
                return parseInt(checkbox.dataset.id, 10) || 0;
            })
            .filter(function (id) {
                return id > 0;
            });
    }

    function updateReportSelection() {
        var ids = reportSelectedIds();
        var visible = visibleReportChecks();
        var visibleSelected = visible.filter(function (checkbox) {
            return checkbox.checked;
        }).length;

        if (reportsSelectedCount) {
            reportsSelectedCount.textContent = ids.length > 0
                ? ids.length + (ids.length === 1 ? ' seleccionado' : ' seleccionados')
                : '';
        }
        if (reportsBulkDelete) {
            reportsBulkDelete.classList.toggle('hidden', ids.length === 0);
            reportsBulkDelete.textContent = ids.length > 0 ? 'Eliminar (' + ids.length + ')' : 'Eliminar';
        }
        if (reportsSelectAll) {
            reportsSelectAll.checked = visible.length > 0 && visibleSelected === visible.length;
            reportsSelectAll.indeterminate = visibleSelected > 0 && visibleSelected < visible.length;
        }
    }

    window.cveAiBulkDelete = function () {
        var ids = reportSelectedIds();
        if (ids.length === 0) {
            return;
        }
        appConfirm(
            '¿Eliminar ' + ids.length + (ids.length === 1 ? ' informe' : ' informes')
                + '? Se cancelarán los que estén en curso y se borrarán sus análisis.',
            { title: 'Eliminar informes', danger: true, confirmText: 'Eliminar' }
        ).then(function (ok) {
            if (!ok) {
                return;
            }
            if (reportsBulkDelete) {
                reportsBulkDelete.disabled = true;
            }
            postJson(BULK_DELETE_URL, { ids: ids }).then(function (res) {
                if (!res || !res.success) {
                    appAlert((res && res.error) ? res.error : 'No se pudieron eliminar los informes.', { title: 'No se pudo eliminar' });
                    if (reportsBulkDelete) {
                        reportsBulkDelete.disabled = false;
                    }
                    return;
                }
                window.location.href = PAGE_URL;
            }).catch(function (err) {
                appAlert('No se pudieron eliminar: ' + errorText(err), { title: 'No se pudo eliminar' });
                if (reportsBulkDelete) {
                    reportsBulkDelete.disabled = false;
                }
            });
        });
    };

    window.cveAiFilterList = function (query) {
        var q = (query || '').toLowerCase().trim();
        if (!list) {
            return;
        }
        list.querySelectorAll('.ai-report-item').forEach(function (el) {
            var hay = (el.dataset.search || '').toLowerCase();
            var hidden = q !== '' && hay.indexOf(q) === -1;
            el.classList.toggle('hidden', hidden);
            if (hidden) {
                var checkbox = el.querySelector('.ai-report-check');
                if (checkbox) {
                    checkbox.checked = false;
                }
            }
        });
        updateReportSelection();
    };

    window.toggleCveAiFullscreen = function () {
        var el = document.getElementById('ai-workspace');
        if (!el) {
            return;
        }
        if (document.fullscreenElement) {
            document.exitFullscreen();
        } else if (el.requestFullscreen) {
            el.requestFullscreen().catch(function () {});
        }
    };

    // La impresión se hace en la página completa del informe, sin la UI del workspace.
    window.printCveAiReport = function () {
        if (!state.id) {
            return;
        }
        window.open(PARTIAL + '/' + state.id + '?print=1', '_blank');
    };

    window.cveAiRefresh = function () {
        withStateId(function (id) {
            appConfirm('¿Actualizar el informe con los datos actuales del catálogo? Si hay cambios se regenerará el análisis.', {
                title: 'Actualizar informe',
                confirmText: 'Actualizar'
            }).then(function (ok) {
                if (!ok) {
                    return;
                }
                postJson(REFRESH_URL + '/' + id, {}).then(function (res) {
                    if (!res.success) {
                        appAlert(res.error || 'No se pudo actualizar el informe.', { title: 'No se pudo actualizar' });
                        return;
                    }
                    if (!res.changed && res.status !== 'pending') {
                        appAlert(res.message || 'Sin cambios desde la última versión.', { title: 'Sin cambios' });
                        return;
                    }
                    window.location.href = PAGE_URL + '&report=' + id;
                }).catch(function (err) {
                    appAlert('No se pudo actualizar: ' + errorText(err), { title: 'No se pudo actualizar' });
                });
            });
        });
    };

    window.cveAiAssignOpen = function () {
        var modal = document.getElementById('ai-group-modal');
        var body = detail ? detail.querySelector('.ai-report-body') : null;
        if (!modal || !body) {
            return;
        }
        if (state.status === 'running' || body.dataset.status === 'running') {
            appAlert('El informe está generando el análisis. Espera a que termine para asignar el grupo.', { title: 'Informe en curso' });
            return;
        }
        var select = document.getElementById('ai-group-select');
        var input = document.getElementById('ai-group-new');
        if (select) {
            select.value = body.dataset.groupId || '0';
        }
        if (input) {
            input.value = '';
        }
        modal.classList.remove('hidden');
    };

    window.cveAiAssignClose = function () {
        var modal = document.getElementById('ai-group-modal');
        if (modal) {
            modal.classList.add('hidden');
        }
    };

    window.cveAiAssignSubmit = function (button) {
        withStateId(function (id) {
            var body = detail ? detail.querySelector('.ai-report-body') : null;
            if (state.status === 'running' || (body && body.dataset.status === 'running')) {
                appAlert('El informe está generando el análisis. Espera a que termine para asignar el grupo.', { title: 'Informe en curso' });
                return;
            }
            var select = document.getElementById('ai-group-select');
            var input = document.getElementById('ai-group-new');
            var payload = {
                group_id: select ? select.value : 0,
                new_group: input ? input.value.trim() : ''
            };
            if (button) {
                button.disabled = true;
            }
            postJson(ASSIGN_URL + '/' + id, payload).then(function (res) {
                if (!res.success) {
                    appAlert(res.error || 'No se pudo asignar el grupo.', { title: 'No se pudo asignar' });
                    if (button) {
                        button.disabled = false;
                    }
                    return;
                }
                window.location.href = PAGE_URL + '&report=' + id;
            }).catch(function (err) {
                var status = err && err.httpStatus ? err.httpStatus : 0;
                var uncertain = status >= 500 || status === 0 || !!(err && err.serverHtml);
                var message = uncertain
                    ? 'El servidor no respondió correctamente'
                        + (status ? ' (HTTP ' + status + ')' : '')
                        + '. Puede que el grupo se haya asignado igualmente. Recargaremos el informe para comprobarlo.'
                    : 'No se pudo asignar: ' + errorText(err);
                appAlert(message, { title: uncertain ? 'Asignación sin confirmar' : 'No se pudo asignar' }).then(function () {
                    if (uncertain) {
                        window.cveAiAssignClose();
                        load(id, false);
                    } else if (button) {
                        button.disabled = false;
                    }
                });
            });
        });
    };

    function selectionTags() {
        if (!detail) {
            return [];
        }
        var checks = Array.prototype.slice.call(detail.querySelectorAll('.ai-cve-check:checked'));
        var common = null;
        checks.forEach(function (el) {
            var tags = [];
            try {
                tags = JSON.parse(el.dataset.tags || '[]');
            } catch (e) {
                tags = [];
            }
            if (!Array.isArray(tags)) {
                tags = [];
            }
            if (common === null) {
                common = tags.slice();
            } else {
                common = common.filter(function (tag) {
                    return tags.indexOf(tag) !== -1;
                });
            }
        });
        return common || [];
    }

    window.cveAiTagsOpen = function () {
        var ids = selectedItemIds();
        if (!ids.length) {
            appAlert('Selecciona al menos un CVE.', { title: 'Sin selección' });
            return;
        }
        var modal = document.getElementById('ai-tags-modal');
        var count = document.getElementById('ai-tags-count');
        var input = document.getElementById('ai-tags-input');
        var append = document.getElementById('ai-tags-append');
        var suggestions = document.getElementById('ai-tags-suggestions');
        if (!modal) {
            return;
        }
        if (count) {
            count.textContent = ids.length + (ids.length === 1 ? ' CVE seleccionado' : ' CVEs seleccionados');
        }
        if (input) {
            input.value = selectionTags().join(', ');
        }
        if (append) {
            append.checked = false;
        }
        if (suggestions) {
            suggestions.classList.add('hidden');
        }
        modal.classList.remove('hidden');
        if (input) {
            input.focus();
        }

        getJson(TAG_SUGGEST_URL + '?report_id=' + encodeURIComponent(state.id) + '&item_ids=' + encodeURIComponent(ids.join(',')))
            .then(function (res) {
                if (res && res.success) {
                    renderTagSuggestions(res.tags || [], res.groups || []);
                }
            }).catch(function () { /* sugerencias opcionales */ });
    };

    window.cveAiTagsClose = function () {
        var modal = document.getElementById('ai-tags-modal');
        if (modal) {
            modal.classList.add('hidden');
        }
    };

    function renderTagSuggestions(tags, groups) {
        var wrap = document.getElementById('ai-tags-suggestions');
        var tagsWrap = document.getElementById('ai-tags-suggestions-tags');
        var groupsWrap = document.getElementById('ai-tags-suggestions-groups');
        if (!wrap || !tagsWrap || !groupsWrap) {
            return;
        }
        tagsWrap.innerHTML = '';
        groupsWrap.innerHTML = '';
        var addChip = function (target, value) {
            var button = document.createElement('button');
            button.type = 'button';
            button.className = 'px-2 py-0.5 rounded-full border border-gray-300 dark:border-gray-600 text-[10px] text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800';
            button.textContent = value;
            button.addEventListener('click', function () {
                var input = document.getElementById('ai-tags-input');
                if (!input) {
                    return;
                }
                var current = (input.value || '').split(',').map(function (t) { return t.trim(); }).filter(Boolean);
                if (current.indexOf(value) === -1) {
                    current.push(value);
                    input.value = current.join(', ');
                }
                input.focus();
            });
            target.appendChild(button);
        };
        tags.forEach(function (tag) { addChip(tagsWrap, tag); });
        groups.forEach(function (group) { addChip(groupsWrap, group); });
        document.getElementById('ai-tags-suggestions-tags-wrap').classList.toggle('hidden', tags.length === 0);
        document.getElementById('ai-tags-suggestions-groups-wrap').classList.toggle('hidden', groups.length === 0);
        wrap.classList.remove('hidden');
    }

    window.cveAiTagsSubmit = function (button) {
        var ids = selectedItemIds();
        var input = document.getElementById('ai-tags-input');
        var append = document.getElementById('ai-tags-append');
        if (!ids.length) {
            appAlert('Selecciona al menos un CVE.', { title: 'Sin selección' });
            return;
        }
        if (button) {
            button.disabled = true;
        }
        postJson(ITEM_TAGS_URL, {
            report_id: state.id,
            item_ids: ids,
            tags: input ? input.value : '',
            append: (append && append.checked) ? 1 : 0
        }).then(function (res) {
            if (!res || !res.success) {
                appAlert((res && res.error) ? res.error : 'No se pudieron aplicar los tags.', { title: 'No se pudo etiquetar' });
                if (button) {
                    button.disabled = false;
                }
                return;
            }
            window.cveAiTagsClose();
            load(state.id, false);
        }).catch(function (err) {
            appAlert('No se pudieron aplicar los tags: ' + errorText(err), { title: 'No se pudo etiquetar' });
            if (button) {
                button.disabled = false;
            }
        });
    };

    window.cveAiItemsGroupOpen = function () {
        var body = detail ? detail.querySelector('.ai-report-body') : null;
        if (state.status === 'running' || (body && body.dataset.status === 'running')) {
            appAlert('El informe está generando el análisis. Espera a que termine para asignar el grupo.', { title: 'Informe en curso' });
            return;
        }
        var ids = selectedItemIds();
        if (!ids.length) {
            appAlert('Selecciona al menos un CVE.', { title: 'Sin selección' });
            return;
        }
        var modal = document.getElementById('ai-items-group-modal');
        var count = document.getElementById('ai-items-group-count');
        var select = document.getElementById('ai-items-group-select');
        var input = document.getElementById('ai-items-group-new');
        if (!modal) {
            return;
        }
        if (count) {
            count.textContent = ids.length + (ids.length === 1 ? ' CVE seleccionado' : ' CVEs seleccionados');
        }
        if (select) {
            select.value = '0';
        }
        if (input) {
            input.value = '';
        }
        modal.classList.remove('hidden');
    };

    window.cveAiItemsGroupClose = function () {
        var modal = document.getElementById('ai-items-group-modal');
        if (modal) {
            modal.classList.add('hidden');
        }
    };

    window.cveAiItemsGroupSubmit = function (button) {
        var body = detail ? detail.querySelector('.ai-report-body') : null;
        if (state.status === 'running' || (body && body.dataset.status === 'running')) {
            appAlert('El informe está generando el análisis. Espera a que termine para asignar el grupo.', { title: 'Informe en curso' });
            return;
        }
        var ids = selectedItemIds();
        var select = document.getElementById('ai-items-group-select');
        var input = document.getElementById('ai-items-group-new');
        if (!ids.length) {
            appAlert('Selecciona al menos un CVE.', { title: 'Sin selección' });
            return;
        }
        if (button) {
            button.disabled = true;
        }
        postJson(ITEM_GROUP_URL, {
            report_id: state.id,
            item_ids: ids,
            group_id: select ? select.value : 0,
            new_group: input ? input.value.trim() : ''
        }).then(function (res) {
            if (!res || !res.success) {
                appAlert((res && res.error) ? res.error : 'No se pudo asignar el grupo.', { title: 'No se pudo asignar' });
                if (button) {
                    button.disabled = false;
                }
                return;
            }
            window.cveAiItemsGroupClose();
            load(state.id, false);
        }).catch(function (err) {
            var status = err && err.httpStatus ? err.httpStatus : 0;
            var uncertain = status >= 500 || status === 0 || !!(err && err.serverHtml);
            var message = uncertain
                ? 'El servidor no respondió correctamente'
                    + (status ? ' (HTTP ' + status + ')' : '')
                    + '. Puede que el grupo se haya asignado igualmente. Recargaremos el informe para comprobarlo.'
                : 'No se pudo asignar el grupo: ' + errorText(err);
            appAlert(message, { title: uncertain ? 'Asignación sin confirmar' : 'No se pudo asignar' }).then(function () {
                if (uncertain) {
                    window.cveAiItemsGroupClose();
                    load(state.id, false);
                } else if (button) {
                    button.disabled = false;
                }
            });
        });
    };

    function retryAiItem(itemId, button) {
        if (!itemId || !state.id) {
            return;
        }
        if (button) {
            button.disabled = true;
            button.textContent = 'Reintentando…';
        }
        postJson(RETRY_ITEM_URL + '/' + state.id + '/' + itemId, {}).then(function (res) {
            if (res && res.success) {
                load(state.id, false);
                return;
            }
            appAlert((res && res.error) ? res.error : 'No se pudo reintentar el análisis.', { title: 'No se pudo reintentar' });
            if (button) {
                button.disabled = false;
                button.textContent = 'Reintentar';
            }
        }).catch(function (err) {
            appAlert('No se pudo reintentar: ' + errorText(err), { title: 'No se pudo reintentar' });
            if (button) {
                button.disabled = false;
                button.textContent = 'Reintentar';
            }
        });
    }

    if (detail) {
        detail.addEventListener('change', function (event) {
            if (event.target && event.target.classList && event.target.classList.contains('ai-cve-check')) {
                updateSelectionUI();
            }
        });
        detail.addEventListener('click', function (event) {
            var retry = event.target ? event.target.closest('.retry-ai-item') : null;
            if (retry) {
                event.preventDefault();
                retryAiItem(parseInt(retry.dataset.retryItem, 10) || 0, retry);
            }
        });
    }

    function escapeHtml(value) {
        return String(value === null || value === undefined ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    window.cveAiDefenderOpen = function () {
        stopPolling();
        if (detail) {
            detail.innerHTML = '';
        }
        if (newForm) {
            newForm.classList.add('hidden');
        }
        var panel = document.getElementById('ai-defender-form');
        if (!panel) {
            return;
        }
        panel.classList.remove('hidden');
        if (printBtn) printBtn.classList.add('hidden');
        if (deleteBtn) deleteBtn.classList.add('hidden');
        if (refreshBtn) refreshBtn.classList.add('hidden');
        if (groupBtn) groupBtn.classList.add('hidden');
        if (titleEl) titleEl.textContent = 'Desde Defender';
        window.cveAiDefenderFetch();
    };

    window.cveAiDefenderClose = function () {
        var panel = document.getElementById('ai-defender-form');
        if (panel) {
            panel.classList.add('hidden');
        }
        if (state.id) {
            load(state.id, false);
        } else {
            window.location.href = PAGE_URL;
        }
    };

    window.cveAiDefenderFetch = function () {
        var listEl = document.getElementById('ai-def-list');
        if (listEl) {
            listEl.innerHTML = '<p class="p-4 text-xs text-gray-500">Cargando vulnerabilidades de Defender…</p>';
        }

        var params = new URLSearchParams();
        var tenant = document.getElementById('ai-def-tenant');
        var severity = document.getElementById('ai-def-severity');
        var epss = document.getElementById('ai-def-epss');
        var machines = document.getElementById('ai-def-machines');
        var exploited = document.getElementById('ai-def-exploited');
        var kev = document.getElementById('ai-def-kev');
        var q = document.getElementById('ai-def-q');
        if (tenant) params.set('tenant_id', tenant.value);
        if (severity) params.set('severity', severity.value);
        if (epss && epss.value !== '') params.set('epss_min', epss.value);
        if (machines && machines.value !== '') params.set('min_machines', machines.value);
        if (exploited && exploited.checked) params.set('exploited', '1');
        if (kev && kev.checked) params.set('kev', '1');
        if (q && q.value.trim() !== '') params.set('q', q.value.trim());

        getJson(DEFENDER_LIST_URL + '?' + params.toString()).then(function (res) {
            if (!res.success) {
                if (listEl) {
                    listEl.innerHTML = '<p class="p-4 text-xs text-red-600">' + escapeHtml(res.error || 'No se pudo consultar Defender.') + '</p>';
                }
                return;
            }
            renderDefenderList(res);
        }).catch(function (err) {
            if (listEl) {
                listEl.innerHTML = '<p class="p-4 text-xs text-red-600">Error: ' + escapeHtml(errorText(err)) + '</p>';
            }
        });
    };

    function renderDefenderList(data) {
        var listEl = document.getElementById('ai-def-list');
        var summary = document.getElementById('ai-def-summary');
        if (!listEl) {
            return;
        }

        var tenant = document.getElementById('ai-def-tenant');
        if (tenant && tenant.options.length <= 1 && Array.isArray(data.tenants)) {
            data.tenants.forEach(function (t) {
                var opt = document.createElement('option');
                opt.value = t.id;
                opt.textContent = t.name;
                tenant.appendChild(opt);
            });
        }

        var cves = Array.isArray(data.cves) ? data.cves : [];
        if (summary) {
            summary.textContent = cves.length + ' CVEs con exposición' +
                (data.missing_catalog ? ' · ' + data.missing_catalog + ' se descargarán de NVD' : '') +
                (data.nvd_key === false ? ' · sin API key NVD (puede fallar por límite)' : '');
        }

        if (!cves.length) {
            listEl.innerHTML = '<p class="p-4 text-xs text-gray-500">No hay vulnerabilidades con esos filtros. Comprueba que el módulo Vulnerabilidades de Defender esté sincronizado.</p>';
            window.cveAiDefenderUpdateCount();
            return;
        }

        var html = '';
        cves.forEach(function (c) {
            var badges = '';
            if (c.in_kev) {
                badges += '<span class="px-1.5 py-0.5 rounded bg-red-100 text-red-700 text-[10px] font-semibold">KEV</span> ';
            }
            if (c.public_exploit) {
                badges += '<span class="px-1.5 py-0.5 rounded bg-orange-100 text-orange-700 text-[10px] font-semibold">Exploit</span> ';
            }
            if (c.exploit_verified) {
                badges += '<span class="px-1.5 py-0.5 rounded bg-red-100 text-red-700 text-[10px] font-semibold">Verificado</span> ';
            }
            if (!c.in_catalog) {
                badges += '<span class="px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 text-[10px] font-semibold">NVD bajo demanda</span>';
            }

            var meta = [];
            if (c.cvss !== null && c.cvss !== undefined) {
                meta.push('CVSS ' + Number(c.cvss).toFixed(1));
            }
            if (c.epss !== null && c.epss !== undefined) {
                meta.push('EPSS ' + (Number(c.epss) * 100).toFixed(1) + '%');
            }
            meta.push(c.machine_count + ' equipos');
            if (Array.isArray(c.products) && c.products.length) {
                meta.push(c.products.slice(0, 2).join(', '));
            }

            html += '<label class="flex items-start gap-3 p-3 hover:bg-gray-50 dark:hover:bg-gray-800/40">' +
                '<input type="checkbox" class="ai-def-cve mt-0.5 rounded border-gray-300 text-brand-500 focus:ring-brand-500" value="' +
                escapeHtml(c.cve_id) + '" onchange="cveAiDefenderUpdateCount()">' +
                '<span class="min-w-0">' +
                '<span class="flex items-center gap-2 flex-wrap">' +
                '<span class="font-mono text-xs font-semibold">' + escapeHtml(c.cve_id) + '</span>' +
                '<span class="text-[10px] uppercase font-semibold text-gray-500">' + escapeHtml(c.severity) + '</span>' +
                badges +
                '</span>' +
                '<span class="block text-[11px] text-gray-500 mt-0.5">' + escapeHtml(meta.join(' · ')) + '</span>' +
                (!c.in_catalog ? '<span class="block text-[11px] text-blue-600 mt-0.5">Se descargará de NVD al crear el informe.</span>' : '') +
                '</span></label>';
        });

        listEl.innerHTML = html;
        window.cveAiDefenderUpdateCount();
    }

    window.cveAiDefenderUpdateCount = function () {
        var selected = document.querySelectorAll('.ai-def-cve:checked').length;
        var el = document.getElementById('ai-def-selected');
        if (el) {
            el.textContent = selected + ' seleccionados';
        }
    };

    window.cveAiDefenderCreate = function (button) {
        var selected = Array.prototype.slice.call(document.querySelectorAll('.ai-def-cve:checked')).map(function (el) {
            return el.value;
        });
        var message = document.getElementById('ai-def-message');
        if (!selected.length) {
            if (message) {
                message.textContent = 'Selecciona al menos un CVE.';
                message.className = 'text-xs text-red-500 mt-2';
            }
            return;
        }

        var profile = document.getElementById('ai-def-profile');
        var local = document.getElementById('ai-def-local');
        var tenant = document.getElementById('ai-def-tenant');
        var tagsInput = document.getElementById('ai-def-tags');
        var extended = document.getElementById('ai-def-extended');
        if (message) {
            message.textContent = 'Creando informe…';
            message.className = 'text-xs text-gray-500 mt-2';
        }
        if (button) {
            button.disabled = true;
        }

        postJson(START_DEFENDER_URL, {
            cve_ids: selected,
            profile_id: profile ? profile.value : 0,
            no_ai: (local && local.checked) ? 1 : 0,
            tenant_id: tenant ? tenant.value : 0,
            tags: tagsInput ? tagsInput.value : '',
            mode: (extended && extended.checked) ? 'extended' : 'summary'
        }).then(function (res) {
            if (!res.success) {
                if (message) {
                    message.textContent = res.error || 'No se pudo crear el informe.';
                    message.className = 'text-xs text-red-500 mt-2';
                }
                if (button) {
                    button.disabled = false;
                }
                return;
            }
            window.location.href = PAGE_URL + '&report=' + res.report_id;
        }).catch(function (err) {
            if (message) {
                message.textContent = 'Error: ' + errorText(err);
                message.className = 'text-xs text-red-500 mt-2';
            }
            if (button) {
                button.disabled = false;
            }
        });
    };

    if (list) {
        list.addEventListener('change', function (event) {
            if (event.target && event.target.classList && event.target.classList.contains('ai-report-check')) {
                updateReportSelection();
            }
        });
    }

    if (reportsSelectAll) {
        reportsSelectAll.addEventListener('change', function () {
            visibleReportChecks().forEach(function (checkbox) {
                checkbox.checked = reportsSelectAll.checked;
            });
            updateReportSelection();
        });
    }

    function ready(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    ready(function () {
        activate();
        updateReportSelection();

        if (state.status === 'pending' || state.status === 'running') {
            setTimeout(function () {
                if (document.getElementById('ai-processing-banner')) {
                    setBanner('Está tardando más de lo normal. Pulsa «Ejecutar ahora» o revisa Admin → Logs (canal cve_ai).');
                }
            }, 45000);
        }
    });
})();

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
<?php if (($newCves ?? '') !== ''): ?>
<script>
(function () {
    'use strict';
    function openPrefilled() {
        if (typeof cveAiNew !== 'function') {
            return;
        }
        cveAiNew();
        var input = document.getElementById('ai-report-cves');
        if (input) {
            input.value = <?= json_encode($newCves) ?>;
            input.focus();
        }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', openPrefilled);
    } else {
        openPrefilled();
    }
})();
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
