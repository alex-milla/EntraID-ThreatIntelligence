<?php
/**
 * Parcial: ficha compacta de un CVE para el panel inline de Mis CVE.
 * Variables: $cveId, $cve, $products, $references, $cwes, $kev, $epss, $exploits, $isAdmin.
 */

$severity = (string)($cve['severity'] ?? '');
$severityClasses = [
    'Critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'High'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'Medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'Low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
];
$severityClass = $severityClasses[$severity] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300';
$cvss = $cve['cvss_v3_score'] ?? $cve['cvss_v2_score'] ?? null;
$epssScore = $epss['epss'] ?? null;
$description = (string)($cve['description_display'] ?? $cve['description'] ?? '');
$descriptionLang = (string)($cve['description_display_lang'] ?? '');
$exploitItems = is_array($exploits['items'] ?? null) ? $exploits['items'] : [];
$exploitTotal = count($exploitItems);
$productLabels = [];
foreach ($products as $product) {
    $label = trim((string)($product['vendor'] ?? '') . ' ' . (string)($product['product'] ?? ''));
    if ($label !== '') {
        $productLabels[] = $label;
    }
}
?>
<div class="p-4 bg-gray-50/70 dark:bg-gray-900/40 border-t border-gray-100 dark:border-gray-800">
    <div class="flex items-start justify-between gap-3 flex-wrap">
        <div>
            <div class="flex items-center gap-2 flex-wrap">
                <span class="font-mono text-sm font-bold"><?= e($cveId) ?></span>
                <span class="inline-flex px-2 py-0.5 text-[10px] rounded-full <?= $severityClass ?>">
                    <?= e($severity !== '' ? $severity : 'Sin severidad') ?>
                </span>
                <?php if (!empty($kev)): ?>
                    <span class="inline-flex px-2 py-0.5 text-[10px] rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300">KEV</span>
                <?php endif; ?>
                <span class="text-[10px] text-gray-400">CVSS <?= $cvss !== null ? e(number_format((float)$cvss, 1)) : '—' ?></span>
                <span class="text-[10px] text-gray-400">EPSS <?= $epssScore !== null ? e(number_format((float)$epssScore * 100, 1)) . ' %' : '—' ?></span>
            </div>
            <p class="text-[11px] text-gray-400 mt-1">
                Publicado <?= e(format_date($cve['published_at'] ?? null, 'd/m/Y')) ?>
                <?php if (!empty($cve['source_identifier'])): ?> · <?= e((string)$cve['source_identifier']) ?><?php endif; ?>
                <?php if (!empty($cve['vuln_status'])): ?> · <?= e((string)$cve['vuln_status']) ?><?php endif; ?>
            </p>
        </div>
        <div class="flex items-center gap-2">
            <a href="<?= e((string)($cve['nvd_url'] ?? ('https://nvd.nist.gov/vuln/detail/' . $cveId))) ?>"
               target="_blank" rel="noopener noreferrer"
               class="text-xs text-gray-500 hover:text-brand-600">NVD ↗</a>
            <a href="<?= base_url('modules/cve/detail/' . rawurlencode($cveId)) ?>"
               class="text-xs text-brand-600 dark:text-brand-400 hover:underline">Abrir ficha completa</a>
        </div>
    </div>

    <?php if ($description !== ''): ?>
        <div class="mt-3">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">
                Descripción <?= $descriptionLang === 'es' ? '· catálogo local' : '· original' ?>
            </p>
            <p class="text-sm text-gray-600 dark:text-gray-300 mt-1"><?= e($description) ?></p>
        </div>
    <?php endif; ?>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4">
        <div>
            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Productos afectados</p>
            <?php if ($productLabels === []): ?>
                <p class="text-xs text-gray-400 mt-1">Sin productos identificados.</p>
            <?php else: ?>
                <p class="text-xs text-gray-600 dark:text-gray-300 mt-1">
                    <?= e(implode(' · ', array_slice($productLabels, 0, 12))) ?>
                    <?php if (count($productLabels) > 12): ?> +<?= count($productLabels) - 12 ?><?php endif; ?>
                </p>
            <?php endif; ?>
            <?php if ($cwes !== []): ?>
                <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400 mt-3">CWE</p>
                <p class="text-xs text-gray-600 dark:text-gray-300 mt-1"><?= e(implode(', ', array_slice($cwes, 0, 8))) ?></p>
            <?php endif; ?>
        </div>

        <div>
            <div class="flex items-center justify-between gap-2">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">
                    Exploits públicos (<?= $exploitTotal ?>)
                </p>
                <?php if ($isAdmin): ?>
                    <button type="button"
                            class="js-cve-exploits-refresh text-[11px] text-brand-600 dark:text-brand-400 hover:underline"
                            data-cve-id="<?= e($cveId) ?>">
                        Buscar ahora
                    </button>
                <?php endif; ?>
            </div>
            <div class="js-cve-exploits-body mt-1">
                <?php if ($exploitItems === []): ?>
                    <p class="text-xs text-gray-400">Sin exploits en la caché actual. Pulsa «Buscar ahora» para consultar las fuentes.</p>
                <?php else: ?>
                    <ul class="space-y-1.5 max-h-52 overflow-y-auto pr-1">
                        <?php foreach (array_slice($exploitItems, 0, 20) as $exploit): ?>
                            <?php
                            $exploitSource = (string)($exploit['source_label'] ?? $exploit['source'] ?? 'Exploit');
                            $exploitUrl = (string)($exploit['url'] ?? '');
                            $exploitTitle = trim((string)($exploit['title'] ?? ''));
                            ?>
                            <li class="text-xs">
                                <span class="inline-flex px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-[9px] font-semibold text-gray-500 dark:text-gray-400"><?= e($exploitSource) ?></span>
                                <a href="<?= e($exploitUrl) ?>" target="_blank" rel="noopener noreferrer"
                                   class="text-brand-600 dark:text-brand-400 hover:underline break-all ml-1">
                                    <?= e($exploitTitle !== '' ? truncate($exploitTitle, 90) : $exploitUrl) ?>
                                </a>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                    <?php if ($exploitTotal > 20): ?>
                        <p class="text-[10px] text-gray-400 mt-1">… y <?= $exploitTotal - 20 ?> más</p>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php if ($references !== []): ?>
        <div class="mt-4">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Referencias</p>
            <ul class="mt-1 space-y-0.5">
                <?php foreach (array_slice($references, 0, 8) as $reference): ?>
                    <li>
                        <a href="<?= e((string)$reference) ?>" target="_blank" rel="noopener noreferrer"
                           class="text-xs text-brand-600 dark:text-brand-400 hover:underline break-all">
                            <?= e(truncate((string)$reference, 120)) ?>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>
</div>
