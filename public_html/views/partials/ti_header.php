<?php
/**
 * Partial: cabecera común de Threat Intelligence (botón Sincronizar + pestañas).
 *
 * Un solo botón "Sincronizar todo" (arriba de las pestañas) y una barra de
 * pestañas idéntica en Reports / Threat actors / Tools / Indicators.
 *
 * Requiere: $selectedTenant, $tiActiveTab ('reports'|'actor'|'tool'|'indicators'),
 *           $profileCounts (actor/tool/total).
 */
$pc       = array_merge(['actor' => 0, 'tool' => 0, 'total' => 0], (array)($profileCounts ?? []));
$tiActive = $tiActiveTab ?? 'reports';

// Filtros que se propagan entre pestañas (los define cada vista).
$tiFilterQs = array_filter((array)($tiFilterQs ?? []), fn($v) => $v !== '' && $v !== null && $v !== []);

$tiTabUrl = function (string $path, array $extra = []) use ($selectedTenant, $tiFilterQs): string {
    $params = array_merge(['tenant' => (int)$selectedTenant], $tiFilterQs, $extra);
    return base_url($path) . '?' . http_build_query($params);
};

$tab      = 'px-3 py-2 text-sm font-medium border-b-2';
$tabOn    = 'border-brand-500 text-brand-600 dark:text-brand-300';
$tabOff   = 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300';
?>
<div class="mb-4 space-y-3">
    <?php if (!empty($selectedTenant)): ?>
        <div class="flex items-center gap-2 flex-wrap">
            <button type="button" onclick="runTiSync()" title="Actualiza Reports + Threat actors/Tools + Indicators"
                    class="inline-flex items-center gap-2 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                Sincronizar todo
            </button>
            <button type="button" onclick="startTiBackgroundSync()" title="Se ejecuta en el servidor: puedes seguir trabajando o cerrar la pestaña"
                    class="inline-flex items-center gap-2 px-3 py-2 border border-brand-500 text-brand-600 dark:text-brand-300 hover:bg-brand-50 dark:hover:bg-brand-950 text-sm font-medium rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                Sincronizar en 2º plano
            </button>
        </div>
    <?php endif; ?>

    <div class="flex flex-wrap items-center gap-1 border-b border-gray-200 dark:border-gray-700">
        <a href="<?= e($tiTabUrl('modules/threat_intelligence')) ?>" class="<?= $tab ?> <?= $tiActive === 'reports' ? $tabOn : $tabOff ?>">Reports</a>
        <a href="<?= e($tiTabUrl('modules/threat_intelligence/profiles', ['kind' => 'actor'])) ?>" class="<?= $tab ?> <?= $tiActive === 'actor' ? $tabOn : $tabOff ?>">Threat actors (<?= (int)($pc['actor'] ?? 0) ?>)</a>
        <a href="<?= e($tiTabUrl('modules/threat_intelligence/profiles', ['kind' => 'tool'])) ?>" class="<?= $tab ?> <?= $tiActive === 'tool' ? $tabOn : $tabOff ?>">Tools (<?= (int)($pc['tool'] ?? 0) ?>)</a>
        <a href="<?= e($tiTabUrl('modules/threat_intelligence/iocs')) ?>" class="<?= $tab ?> <?= $tiActive === 'indicators' ? $tabOn : $tabOff ?>">Indicators</a>
    </div>
</div>
