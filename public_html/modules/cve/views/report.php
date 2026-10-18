<?php
/**
 * Vista: informe preventivo de CVEs del inventario de software.
 * Variables: $report, $data, $summary.
 */

$report = is_array($report ?? null) ? $report : null;
$data = is_array($data ?? null) ? $data : [];
$summary = is_array($summary ?? null) ? $summary : [];

$softwareSections = is_array($data['software'] ?? null) ? $data['software'] : [];
$period = is_array($data['period'] ?? null) ? $data['period'] : [];
$filters = is_array($data['filters'] ?? null) ? $data['filters'] : [];
$isTruncated = !empty($summary['truncated']) || !empty($data['truncated']);

$severityLabels = [
    'Critical' => 'Crítica',
    'High'     => 'Alta',
    'Medium'   => 'Media',
    'Low'      => 'Baja',
    'None'     => 'Ninguna',
];
$severityClasses = [
    'Critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'High'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'Medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'Low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'None'     => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
];
$criticalityLabels = [
    'critical' => 'Crítica',
    'high'     => 'Alta',
    'medium'   => 'Media',
    'low'      => 'Baja',
    'info'     => 'Informativa',
];
$reportFilterLabels = [];
if (($filters['severity'] ?? '') !== '') {
    $reportFilterLabels[] = 'Severidad: ' . ($severityLabels[$filters['severity']] ?? $filters['severity']);
}
if (!empty($filters['only_kev'])) {
    $reportFilterLabels[] = 'Solo KEV';
}
if (($filters['epss_min'] ?? null) !== null) {
    $reportFilterLabels[] = 'EPSS ≥ ' . number_format((float)$filters['epss_min'], 2, ',', '');
}
if (!empty($filters['new_only'])) {
    $reportFilterLabels[] = 'Solo nuevas o recién detectadas';
}

$tab = 'reports';
require __DIR__ . '/_tabs.php';
?>

<?php if ($report === null): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-red-200 dark:border-red-800 p-6">
        <h1 class="text-lg font-semibold text-red-600 dark:text-red-400">Informe no encontrado</h1>
        <p class="text-sm text-gray-500 mt-2">El informe solicitado no existe o ha sido eliminado.</p>
        <a href="<?= base_url('modules/cve?tab=reports') ?>" class="inline-block mt-4 text-sm text-brand-600 dark:text-brand-400 hover:underline">Volver a informes</a>
    </div>
<?php else: ?>

    <div class="mb-5 flex items-start justify-between gap-4 flex-wrap no-print">
        <a href="<?= base_url('modules/cve?tab=reports') ?>" class="inline-flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19l-7-7 7-7"/></svg>
            Informes CVE
        </a>
        <div class="flex items-center gap-2">
            <a href="<?= base_url('modules/cve/report/' . (int)$report['id'] . '/csv') ?>"
               class="px-3 py-2 border border-gray-200 dark:border-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                Descargar CSV
            </a>
            <button type="button" onclick="window.print()"
                    class="px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                Imprimir / PDF
            </button>
        </div>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-5">
        <div class="flex items-start justify-between gap-4 flex-wrap">
            <div class="min-w-0">
                <p class="text-xs font-semibold uppercase tracking-wide text-brand-600 dark:text-brand-400">Informe preventivo CVE</p>
                <h1 class="text-xl font-bold mt-1 break-words"><?= e((string)($report['title'] ?? 'Informe CVE')) ?></h1>
                <p class="text-xs text-gray-500 mt-2">
                    <?= e((string)($period['label'] ?? '')) ?>
                    <?php if (!empty($period['start'])): ?>
                        · <?= e(format_date((string)$period['start'], 'd/m/Y H:i')) ?> — <?= e(format_date((string)($period['end'] ?? ''), 'd/m/Y H:i')) ?>
                    <?php endif; ?>
                    · Generado <?= e(format_date((string)($report['generated_at'] ?? ''), 'd/m/Y H:i')) ?>
                </p>
                <?php if (!empty($reportFilterLabels)): ?>
                    <p class="text-xs text-gray-400 mt-1"><?= e(implode(' · ', $reportFilterLabels)) ?></p>
                <?php endif; ?>
            </div>
            <div class="text-right text-xs text-gray-400">
                <p class="font-semibold text-gray-600 dark:text-gray-300">EntraID Threat Intelligence</p>
                <p>Fuentes: NVD · CISA KEV · EPSS</p>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-5">
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">CVEs únicos</p>
            <p class="text-2xl font-bold mt-1"><?= number_format((int)($summary['unique_cves'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">Productos afectados</p>
            <p class="text-2xl font-bold mt-1"><?= number_format((int)($summary['software_count'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">KEV</p>
            <p class="text-2xl font-bold mt-1 text-red-500"><?= number_format((int)($summary['kev'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">EPSS ≥ 0,1</p>
            <p class="text-2xl font-bold mt-1 text-amber-500"><?= number_format((int)($summary['epss_high'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">Críticas</p>
            <p class="text-2xl font-bold mt-1 text-red-500"><?= number_format((int)($summary['critical'] ?? 0)) ?></p>
        </div>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <p class="text-xs text-gray-500">Altas</p>
            <p class="text-2xl font-bold mt-1 text-orange-500"><?= number_format((int)($summary['high'] ?? 0)) ?></p>
        </div>
    </div>

    <?php if ($isTruncated): ?>
        <div class="mb-5 px-4 py-3 rounded-lg text-xs bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
            El informe se ha limitado a <?= number_format((int)($summary['max_rows'] ?? $data['max_rows'] ?? 0)) ?> afectaciones.
            Reduce el periodo o filtra por grupo/software para un informe completo.
        </div>
    <?php endif; ?>

    <?php if (empty($softwareSections)): ?>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
            <h2 class="text-sm font-semibold">Sin CVEs en el periodo seleccionado</h2>
            <p class="text-sm text-gray-500 mt-2">
                No hay coincidencias para el alcance y los filtros elegidos. Prueba a ampliar el periodo o desmarcar «Solo nuevas».
            </p>
        </div>
    <?php else: ?>
        <div class="space-y-5">
            <?php foreach ($softwareSections as $section): ?>
                <?php
                $sectionCves = is_array($section['cves'] ?? null) ? $section['cves'] : [];
                $counts = is_array($section['counts'] ?? null) ? $section['counts'] : [];
                $criticality = (string)($section['criticality'] ?? '');
                ?>
                <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden break-inside-avoid">
                    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-start justify-between gap-3 flex-wrap">
                        <div class="min-w-0">
                            <h2 class="text-sm font-semibold break-words">
                                <?= e((string)($section['name'] ?? '')) ?>
                                <?php if (!empty($section['version'])): ?>
                                    <span class="font-normal text-gray-500">· <?= e((string)$section['version']) ?></span>
                                <?php endif; ?>
                            </h2>
                            <p class="text-xs text-gray-500 mt-1">
                                <?php if (!empty($section['group'])): ?>Grupo: <?= e((string)$section['group']) ?> · <?php endif; ?>
                                <?php if (!empty($section['environment'])): ?>Entorno: <?= e((string)$section['environment']) ?> · <?php endif; ?>
                                <?php if ($criticality !== ''): ?>Criticidad: <?= e($criticalityLabels[$criticality] ?? $criticality) ?> · <?php endif; ?>
                                <?php if (($section['asset_count'] ?? null) !== null): ?>Activos: <?= number_format((int)$section['asset_count']) ?><?php endif; ?>
                            </p>
                        </div>
                        <div class="flex items-center gap-2 text-[11px] whitespace-nowrap">
                            <span class="px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300"><?= number_format((int)($counts['total'] ?? 0)) ?> CVEs</span>
                            <?php if ((int)($counts['kev'] ?? 0) > 0): ?>
                                <span class="px-2 py-0.5 rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300"><?= number_format((int)$counts['kev']) ?> KEV</span>
                            <?php endif; ?>
                            <?php if ((int)($counts['epss_high'] ?? 0) > 0): ?>
                                <span class="px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300"><?= number_format((int)$counts['epss_high']) ?> EPSS alto</span>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="overflow-x-auto">
                        <table class="w-full text-xs">
                            <thead>
                                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-[10px] text-gray-500 uppercase">
                                    <th class="text-left px-4 py-2">CVE</th>
                                    <th class="text-left px-4 py-2">Severidad</th>
                                    <th class="text-left px-4 py-2">CVSS</th>
                                    <th class="text-left px-4 py-2">EPSS</th>
                                    <th class="text-left px-4 py-2">KEV</th>
                                    <th class="text-left px-4 py-2">Publicado</th>
                                    <th class="text-left px-4 py-2">Versiones afectadas</th>
                                    <th class="text-left px-4 py-2">Descripción / acción</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
                                <?php foreach ($sectionCves as $cve): ?>
                                    <?php
                                    $cveId = (string)($cve['cve_id'] ?? '');
                                    $severity = (string)($cve['severity'] ?? '');
                                    $epss = $cve['epss'] !== null ? (float)$cve['epss'] : null;
                                    $versions = is_array($cve['affected_versions'] ?? null) ? $cve['affected_versions'] : [];
                                    $versionText = implode(', ', array_map('strval', $versions));
                                    $isKev = !empty($cve['kev']);
                                    $nvdUrl = (string)($cve['nvd_url'] ?? '');
                                    if (!preg_match('#^https?://#i', $nvdUrl)) {
                                        $nvdUrl = 'https://nvd.nist.gov/vuln/detail/' . rawurlencode($cveId);
                                    }
                                    ?>
                                    <tr class="<?= $isKev ? 'bg-red-50/60 dark:bg-red-900/10' : '' ?> align-top">
                                        <td class="px-4 py-2.5 whitespace-nowrap">
                                            <a href="<?= e($nvdUrl) ?>"
                                               target="_blank" rel="noopener"
                                               class="font-mono font-medium text-brand-600 dark:text-brand-400 hover:underline">
                                                <?= e($cveId) ?>
                                            </a>
                                        </td>
                                        <td class="px-4 py-2.5 whitespace-nowrap">
                                            <span class="inline-flex px-2 py-0.5 text-[10px] rounded-full <?= $severityClasses[$severity] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300' ?>">
                                                <?= e($severityLabels[$severity] ?? ($severity !== '' ? $severity : '—')) ?>
                                            </span>
                                        </td>
                                        <td class="px-4 py-2.5 whitespace-nowrap font-medium">
                                            <?= $cve['cvss'] !== null ? number_format((float)$cve['cvss'], 1) : '—' ?>
                                        </td>
                                        <td class="px-4 py-2.5 whitespace-nowrap">
                                            <?php if ($epss !== null): ?>
                                                <span class="<?= $epss >= 0.1 ? 'font-semibold text-amber-600 dark:text-amber-400' : 'text-gray-500' ?>">
                                                    <?= number_format($epss * 100, 1) ?>%
                                                </span>
                                            <?php else: ?>
                                                <span class="text-gray-400">—</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="px-4 py-2.5 whitespace-nowrap">
                                            <?php if ($isKev): ?>
                                                <span class="inline-flex px-2 py-0.5 text-[10px] rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300"
                                                      title="<?= e((string)($cve['kev_date'] ?? '')) ?>">KEV</span>
                                                <?php if (!empty($cve['kev_due'])): ?>
                                                    <div class="text-[10px] text-red-500 mt-0.5">Vence <?= e(format_date((string)$cve['kev_due'], 'd/m/Y')) ?></div>
                                                <?php endif; ?>
                                                <?php if (strcasecmp((string)($cve['kev_ransomware'] ?? ''), 'Known') === 0): ?>
                                                    <div class="text-[10px] text-red-500 mt-0.5">Ransomware conocido</div>
                                                <?php endif; ?>
                                            <?php else: ?>
                                                <span class="text-gray-400">—</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="px-4 py-2.5 whitespace-nowrap text-gray-500">
                                            <?= e(format_date((string)($cve['published_at'] ?? ''), 'd/m/Y')) ?>
                                        </td>
                                        <td class="px-4 py-2.5 text-gray-500 max-w-[220px]">
                                            <?= e(truncate($versionText !== '' ? $versionText : '—', 120)) ?>
                                        </td>
                                        <td class="px-4 py-2.5 text-gray-600 dark:text-gray-300 min-w-[260px] max-w-[420px]">
                                            <p><?= e(truncate((string)($cve['description'] ?? ''), 220)) ?></p>
                                            <?php if ($isKev && !empty($cve['kev_action'])): ?>
                                                <p class="text-[11px] text-red-600 dark:text-red-400 mt-1">
                                                    <span class="font-semibold">Acción KEV:</span> <?= e(truncate((string)$cve['kev_action'], 160)) ?>
                                                </p>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <div class="mt-6 text-[11px] text-gray-400 leading-relaxed">
        <p>
            Prioridad orientativa: KEV &gt; EPSS &gt; CVSS. KEV indica explotación conocida según CISA;
            EPSS estima la probabilidad de explotación a 30 días. Un CVE puede afectar a varios productos,
            por lo que el número de afectaciones puede superar el de CVEs únicos.
        </p>
        <p class="mt-1">
            Informe generado automáticamente a partir del catálogo NVD y del inventario de software.
            Verifica siempre las versiones afectadas y el estado de tus activos antes de aplicar cambios.
        </p>
    </div>
<?php endif; ?>
