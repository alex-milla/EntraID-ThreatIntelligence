<?php
/**
 * Vista: detalle de un CVE del catálogo.
 * Variables: $cveId, $cve, $products, $references, $cwes, $kev, $epss
 */

$tab = 'catalog';
require __DIR__ . '/_tabs.php';
?>

<div class="mb-5">
    <a href="<?= base_url('modules/cve?tab=catalog') ?>" class="text-sm text-gray-500 hover:underline">← Volver al catálogo</a>
</div>

<?php if ($cve === null): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
        <h2 class="text-lg font-semibold mb-2">CVE no encontrado</h2>
        <p class="text-sm text-gray-500">No hay datos para <code class="font-mono"><?= e($cveId) ?></code> en el catálogo.</p>
    </div>
<?php else: ?>
    <?php require __DIR__ . '/_cve_detail_content.php'; ?>
<?php endif; ?>
