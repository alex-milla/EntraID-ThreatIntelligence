<?php
/**
 * Vista: Dashboard de administración.
 */
$pageTitle = 'Dashboard';
?>

<!-- KPIs -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <div class="flex items-center justify-between">
            <span class="text-sm text-gray-500">Tenants</span>
            <svg class="w-[18px] h-[18px] text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>
        </div>
        <p class="text-3xl font-bold mt-2"><?= $totalStats['tenants'] ?></p>
        <p class="text-xs text-gray-400 mt-1"><?= $totalStats['activeTenants'] ?> activos</p>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <div class="flex items-center justify-between">
            <span class="text-sm text-gray-500">Módulos activos</span>
            <svg class="w-[18px] h-[18px] text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>
        </div>
        <p class="text-3xl font-bold mt-2"><?= $totalStats['modules'] ?></p>
        <p class="text-xs text-gray-400 mt-1">de <?= count($modules) ?> disponibles</p>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <div class="flex items-center justify-between">
            <span class="text-sm text-gray-500">Reportes generados</span>
            <svg class="w-[18px] h-[18px] text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
        </div>
        <p class="text-3xl font-bold mt-2"><?= $totalStats['reports'] ?></p>
        <p class="text-xs text-gray-400 mt-1">histórico total</p>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <div class="flex items-center justify-between">
            <span class="text-sm text-gray-500">Grupos</span>
            <svg class="w-[18px] h-[18px] text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
        </div>
        <p class="text-3xl font-bold mt-2"><?= count($groups) ?></p>
        <p class="text-xs text-gray-400 mt-1">grupos de tenants</p>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Tenants -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h2 class="text-sm font-semibold">Tenants</h2>
            <a href="<?= base_url('admin/tenants') ?>" class="text-xs text-brand-500 hover:underline">Gestionar</a>
        </div>
        <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
            <?php if (empty($tenants)): ?>
                <p class="px-5 py-8 text-sm text-gray-500 text-center">No hay tenants configurados</p>
            <?php else: ?>
                <?php foreach (array_slice($tenants, 0, 5) as $t): ?>
                    <?php $st = $tenantStats[$t['id']] ?? []; ?>
                    <div class="px-5 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($t['name']) ?></p>
                            <p class="text-xs text-gray-400 font-mono truncate"><?= e($t['tenant_id']) ?></p>
                        </div>
                        <div class="flex items-center gap-3 shrink-0">
                            <span class="text-xs text-gray-500"><?= array_sum($st) ?> registros</span>
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $t['is_active'] ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400' ?>">
                                <?= $t['is_active'] ? 'Activo' : 'Inactivo' ?>
                            </span>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- Últimas sincronizaciones -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-sm font-semibold">Últimas sincronizaciones</h2>
        </div>
        <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
            <?php if (empty($recentSyncs)): ?>
                <p class="px-5 py-8 text-sm text-gray-500 text-center">Sin sincronizaciones aún</p>
            <?php else: ?>
                <?php foreach ($recentSyncs as $sync): ?>
                    <div class="px-5 py-3 flex items-center justify-between">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($sync['tenant_name']) ?></p>
                            <p class="text-xs text-gray-400"><?= e($sync['module_key']) ?> · <?= e($sync['sync_type']) ?></p>
                        </div>
                        <div class="text-right shrink-0">
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $sync['status'] === 'success' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : ($sync['status'] === 'error' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300') ?>">
                                <?= e($sync['status']) ?>
                            </span>
                            <p class="text-xs text-gray-400 mt-0.5"><?= time_ago($sync['started_at']) ?></p>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php if (Auth::isAdmin()): ?>
<!-- Acciones rápidas -->
<div class="mt-6 bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
    <h2 class="text-sm font-semibold mb-4">Acciones rápidas</h2>
    <div class="flex flex-wrap gap-3">
        <a href="<?= base_url('admin/tenant/edit') ?>" class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
            Nuevo tenant
        </a>
        <a href="<?= base_url('admin/modules') ?>" class="inline-flex items-center gap-2 px-4 py-2 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-sm font-medium rounded-lg transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6z"/></svg>
            Gestionar módulos
        </a>
        <a href="<?= base_url('modules/reports') ?>" class="inline-flex items-center gap-2 px-4 py-2 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-sm font-medium rounded-lg transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            Generar reporte
        </a>
    </div>
</div>
<?php endif; ?>
