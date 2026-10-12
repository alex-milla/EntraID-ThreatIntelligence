<?php
/**
 * Vista: detalle de un Intel Profile (threat actor / tool).
 */
$aliases  = safe_json_decode((string)($profile['aliases'] ?? ''), []);
$targets  = safe_json_decode((string)($profile['targets'] ?? ''), []);
$countries = safe_json_decode((string)($profile['countries'] ?? ''), []);
$summaryHtml    = render_markdown((string)($profile['summary'] ?? ''));
$descHtml       = render_markdown((string)($profile['description'] ?? ''));
$tradecraftHtml = render_markdown((string)($profile['tradecraft'] ?? ''));

$countryLabel = function ($c) {
    if (is_array($c)) {
        return (string)($c['countryOrRegion'] ?? $c['name'] ?? json_encode($c));
    }
    return (string)$c;
};
?>
<div class="mb-6">
    <a href="<?= base_url('modules/threat_intelligence/profiles?tenant=' . (int)$profile['tenant_id'] . '&kind=' . urlencode((string)($profile['kind'] ?? ''))) ?>" class="text-xs text-brand-500 hover:underline">← Volver a perfiles</a>
    <div class="flex items-start justify-between gap-3 mt-3 flex-wrap">
        <div class="min-w-0">
            <h2 class="text-xl font-bold"><?= e($profile['title']) ?></h2>
            <p class="text-xs text-gray-400 mt-1">
                <?= e(ucfirst((string)($profile['kind'] ?? ''))) ?>
                <?php if (!empty($profile['first_active'])): ?> · Primera actividad: <?= e($profile['first_active']) ?><?php endif; ?>
                <?php if ($tenant): ?> · <?= e($tenant['name']) ?><?php endif; ?>
            </p>
        </div>
        <?php if (($profile['kind'] ?? '') === 'actor'): ?>
            <span class="inline-flex px-3 py-1 text-xs rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300">threat actor</span>
        <?php else: ?>
            <span class="inline-flex px-3 py-1 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300"><?= e((string)($profile['kind'] ?? 'tool')) ?></span>
        <?php endif; ?>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <div class="lg:col-span-2 space-y-6">
        <?php if (is_array($aliases) && $aliases): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <h3 class="text-sm font-semibold mb-2">Alias</h3>
                <div class="flex flex-wrap gap-1.5">
                    <?php foreach ($aliases as $a): ?><span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300"><?= e($a) ?></span><?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if (is_array($targets) && $targets || (is_array($countries) && $countries)): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <h3 class="text-sm font-semibold mb-2">Objetivos / origen</h3>
                <?php if (is_array($targets) && $targets): ?>
                    <p class="text-sm text-gray-600 dark:text-gray-300"><strong class="font-medium">Objetivos:</strong> <?= e(implode(', ', array_map('strval', array_slice($targets, 0, 20)))) ?></p>
                <?php endif; ?>
                <?php if (is_array($countries) && $countries): ?>
                    <p class="text-sm text-gray-600 dark:text-gray-300 mt-1"><strong class="font-medium">Origen:</strong> <?= e(implode(', ', array_map($countryLabel, array_slice($countries, 0, 20)))) ?></p>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($summaryHtml !== ''): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 md-body"><?= $summaryHtml ?></div>
        <?php endif; ?>

        <?php if ($descHtml !== ''): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <details open>
                    <summary class="text-sm font-semibold cursor-pointer select-none">Descripción</summary>
                    <div class="md-body mt-4"><?= $descHtml ?></div>
                </details>
            </div>
        <?php endif; ?>

        <?php if ($tradecraftHtml !== ''): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <details>
                    <summary class="text-sm font-semibold cursor-pointer select-none">Tradecraft (TTP)</summary>
                    <div class="md-body mt-4"><?= $tradecraftHtml ?></div>
                </details>
            </div>
        <?php endif; ?>
    </div>

    <div class="lg:col-span-1">
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <h2 class="text-sm font-semibold">Indicadores (<?= count($indicators) ?>)</h2>
                <?php if (!empty($indicators)): ?>
                    <button onclick="copyProfileIocs()" class="text-xs text-brand-500 hover:underline">Copiar todos</button>
                <?php endif; ?>
            </div>
            <?php if (empty($indicators)): ?>
                <p class="px-4 py-6 text-sm text-gray-500 text-center">Sin indicadores sincronizados. Pulsa «Sincronizar indicadores» en la lista de perfiles.</p>
            <?php else: ?>
                <div class="divide-y divide-gray-100 dark:divide-gray-700/50 max-h-[70vh] overflow-y-auto">
                    <?php foreach ($indicators as $ioc): ?>
                        <div class="px-4 py-2.5">
                            <div class="flex items-center justify-between gap-2">
                                <span class="font-mono text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-500"><?= e($ioc['ioc_type']) ?></span>
                            </div>
                            <p class="font-mono text-xs break-all mt-1" data-ioc="<?= e($ioc['ioc_value']) ?>"><?= e($ioc['ioc_value']) ?></p>
                            <?php if (!empty($ioc['first_seen']) || !empty($ioc['last_seen'])): ?>
                                <p class="text-[11px] text-gray-400 mt-0.5"><?= e((string)$ioc['first_seen']) ?><?= $ioc['first_seen'] && $ioc['last_seen'] ? ' → ' . e((string)$ioc['last_seen']) : '' ?></p>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
function copyProfileIocs() {
    var vals = Array.prototype.map.call(document.querySelectorAll('[data-ioc]'), function (el) { return el.getAttribute('data-ioc'); });
    navigator.clipboard.writeText(vals.join('\n')).then(function () { toast('Copiados ' + vals.length + ' indicadores', 'success'); })
        .catch(function () { toast('No se pudo copiar', 'error'); });
}
</script>
