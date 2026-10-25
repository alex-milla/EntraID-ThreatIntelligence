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
        <div class="flex items-center">
            <button type="button" onclick="startTiSync()" title="Sincroniza en segundo plano; si no arranca, continúa en modo clásico"
                    class="btn btn-small">
                <i class="material-icons icon-16" aria-hidden="true">sync</i>
                Sincronizar
            </button>
        </div>
    <?php endif; ?>

    <div class="flex flex-wrap items-center gap-1 border-b border-line">
        <a href="<?= e($tiTabUrl('modules/threat_intelligence')) ?>" class="<?= $tab ?> <?= $tiActive === 'reports' ? $tabOn : $tabOff ?>">Reports</a>
        <a href="<?= e($tiTabUrl('modules/threat_intelligence/profiles', ['kind' => 'actor'])) ?>" class="<?= $tab ?> <?= $tiActive === 'actor' ? $tabOn : $tabOff ?>">Threat actors (<?= (int)($pc['actor'] ?? 0) ?>)</a>
        <a href="<?= e($tiTabUrl('modules/threat_intelligence/profiles', ['kind' => 'tool'])) ?>" class="<?= $tab ?> <?= $tiActive === 'tool' ? $tabOn : $tabOff ?>">Tools (<?= (int)($pc['tool'] ?? 0) ?>)</a>
        <a href="<?= e($tiTabUrl('modules/threat_intelligence/iocs')) ?>" class="<?= $tab ?> <?= $tiActive === 'indicators' ? $tabOn : $tabOff ?>">Indicators</a>
    </div>
</div>
