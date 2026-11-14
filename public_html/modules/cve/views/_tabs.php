<?php
/**
 * Parcial: pestañas del módulo CVE.
 * Variable: $tab (vm | software | catalog | reports | import).
 *
 * v0.3.21 — navegación minimalista: la mesa de trabajo es la primera pestaña
 * y las vistas ocasionales viven en «Más». Las claves y las URLs no cambian:
 * cualquier enlace antiguo sigue funcionando.
 *
 * v0.4.15 — «Informes» pasa a pestaña visible (estaba escondido en «Más» y no
 * se encontraba). «Importar CSV» sigue en «Más».
 */

$cveTabs = [
    'vm'       => 'Mesa de trabajo',
    'software' => 'Mis CVE',
    'catalog'  => 'Catálogo',
    'reports'  => 'Informes',
];
$cveMoreTabs = [
    'import'  => 'Importar CSV',
];
$currentTab = (isset($tab) && (isset($cveTabs[$tab]) || isset($cveMoreTabs[$tab]))) ? $tab : 'catalog';
$moreOpen = isset($cveMoreTabs[$currentTab]);
?>
<div class="no-print sticky top-0 z-20 -mx-6 px-6 bg-muted/95 dark:bg-gray-900/95 backdrop-blur border-b border-line mb-5">
    <style>
        .cve-tabs summary::-webkit-details-marker { display: none; }
    </style>
    <nav class="cve-tabs flex items-center gap-2">
        <?php foreach ($cveTabs as $key => $label): ?>
            <a href="<?= base_url('modules/cve?tab=' . $key) ?>"
               class="px-3 py-2.5 -mb-px text-sm font-medium border-b-2 transition-colors <?= $currentTab === $key
                   ? 'border-brand-500 text-brand-600 dark:text-brand-300'
                   : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' ?>">
                <?= e($label) ?>
            </a>
        <?php endforeach; ?>

        <details class="relative ml-auto" <?= $moreOpen ? 'open' : '' ?>>
            <summary class="list-none cursor-pointer px-3 py-2.5 -mb-px text-sm font-medium border-b-2 transition-colors <?= $moreOpen
                ? 'border-brand-500 text-brand-600 dark:text-brand-300'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' ?>"
                     style="list-style:none">
                Más
                <i class="material-icons icon-14 align-middle" aria-hidden="true">expand_more</i>
            </summary>
            <div class="absolute right-0 mt-1 z-30 w-48 card shadow-xl p-1">
                <?php foreach ($cveMoreTabs as $key => $label): ?>
                    <a href="<?= base_url('modules/cve?tab=' . $key) ?>"
                       class="flex items-center justify-between px-3 py-2 rounded-lg text-xs <?= $currentTab === $key
                           ? 'bg-muted font-semibold text-ink'
                           : 'text-ink-muted hover:bg-muted' ?>">
                        <?= e($label) ?>
                        <?php if ($currentTab === $key): ?>
                            <i class="material-icons icon-14" aria-hidden="true">check</i>
                        <?php endif; ?>
                    </a>
                <?php endforeach; ?>
            </div>
        </details>
    </nav>
</div>
