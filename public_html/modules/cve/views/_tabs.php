<?php
/**
 * Parcial: pestañas del módulo CVE.
 * Variable: $tab (catalog | software | reports).
 */

$cveTabs = [
    'catalog'  => 'Catálogo',
    'software' => 'Mis CVE',
    'reports'  => 'Informes',
];
$currentTab = (isset($tab) && isset($cveTabs[$tab])) ? $tab : 'catalog';
?>
<div class="no-print sticky top-0 z-20 -mx-6 px-6 bg-gray-50/95 dark:bg-gray-900/95 backdrop-blur border-b border-gray-200 dark:border-gray-700 mb-5">
    <nav class="flex items-center gap-2">
        <?php foreach ($cveTabs as $key => $label): ?>
            <a href="<?= base_url('modules/cve?tab=' . $key) ?>"
               class="px-3 py-2.5 -mb-px text-sm font-medium border-b-2 transition-colors <?= $currentTab === $key
                   ? 'border-brand-500 text-brand-600 dark:text-brand-300'
                   : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' ?>">
                <?= e($label) ?>
            </a>
        <?php endforeach; ?>
    </nav>
</div>
