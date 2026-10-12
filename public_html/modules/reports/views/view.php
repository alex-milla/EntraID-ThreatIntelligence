<?php
/**
 * Vista: Visualización de un reporte generado.
 */
$pageTitle = $report['title'] ?? 'Reporte';
$data = $report['data'] ?? [];
?>

<div class="mb-6 flex items-center justify-between">
    <div>
        <h2 class="text-xl font-bold"><?= e($report['title']) ?></h2>
        <p class="text-sm text-gray-500 mt-1">
            <?= e($report['period_type']) ?> · <?= e($report['period_start']) ?> — <?= e($report['period_end']) ?>
            · Generado <?= time_ago($report['generated_at']) ?>
        </p>
    </div>
    <button onclick="window.print()" class="inline-flex items-center gap-2 px-4 py-2 border border-gray-200 dark:border-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors no-print">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"/></svg>
        Imprimir
    </button>
</div>

<!-- Resumen ejecutivo -->
<?php if (!empty($data['executive'])): ?>
<div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
    <?php
    $exec = $data['executive'];
    $kpis = [
        ['label' => 'Incidentes', 'value' => $exec['totalIncidents'] ?? 0, 'color' => 'text-red-500'],
        ['label' => 'Alertas', 'value' => $exec['totalAlerts'] ?? 0, 'color' => 'text-orange-500'],
        ['label' => 'IOCs', 'value' => $exec['totalIocs'] ?? 0, 'color' => 'text-brand-500'],
        ['label' => 'Equipos', 'value' => $exec['totalMachines'] ?? 0, 'color' => 'text-blue-500'],
        ['label' => 'Vulns', 'value' => $exec['totalVulnerabilities'] ?? 0, 'color' => 'text-yellow-500'],
        ['label' => 'Críticas', 'value' => $exec['criticalVulns'] ?? 0, 'color' => 'text-red-600'],
        ['label' => 'Secure Score', 'value' => ($exec['secureScore'] ?? 0) . '%', 'color' => 'text-green-500'],
    ];
    foreach ($kpis as $kpi):
    ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-center">
        <p class="text-2xl font-bold <?= $kpi['color'] ?>"><?= number_format((float)$kpi['value']) ?></p>
        <p class="text-xs text-gray-500 mt-1"><?= e($kpi['label']) ?></p>
    </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<!-- Secciones del reporte -->
<?php if (!empty($data['incidents'])): ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-6">
    <h3 class="text-lg font-semibold mb-4">Incidentes</h3>
    <?php if (!empty($data['incidents']['topIncidents'])): ?>
        <div class="overflow-x-auto">
            <table class="w-full text-sm">
                <thead><tr class="border-b border-gray-200 dark:border-gray-700">
                    <th class="text-left py-2 font-medium text-gray-600 dark:text-gray-400">Incidente</th>
                    <th class="text-left py-2 font-medium text-gray-600 dark:text-gray-400">Severidad</th>
                    <th class="text-left py-2 font-medium text-gray-600 dark:text-gray-400">Estado</th>
                    <th class="text-right py-2 font-medium text-gray-600 dark:text-gray-400">Alertas</th>
                </tr></thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                    <?php foreach ($data['incidents']['topIncidents'] as $inc): ?>
                    <tr>
                        <td class="py-2"><?= e($inc['display_name']) ?></td>
                        <td class="py-2"><span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= severity_badge_class($inc['severity']) ?>"><?= e($inc['severity'] ?? '—') ?></span></td>
                        <td class="py-2 text-gray-500"><?= e($inc['status'] ?? '—') ?></td>
                        <td class="py-2 text-right"><?= $inc['alert_count'] ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <p class="text-sm text-gray-500">Sin incidentes en el periodo.</p>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php if (!empty($data['vulnerabilities'])): ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-6">
    <h3 class="text-lg font-semibold mb-4">Vulnerabilidades</h3>
    <?php if (!empty($data['vulnerabilities']['topCves'])): ?>
        <div class="overflow-x-auto">
            <table class="w-full text-sm">
                <thead><tr class="border-b border-gray-200 dark:border-gray-700">
                    <th class="text-left py-2 font-medium text-gray-600 dark:text-gray-400">CVE</th>
                    <th class="text-right py-2 font-medium text-gray-600 dark:text-gray-400">Equipos afectados</th>
                    <th class="text-right py-2 font-medium text-gray-600 dark:text-gray-400">CVSS máx</th>
                    <th class="text-center py-2 font-medium text-gray-600 dark:text-gray-400">Exploit</th>
                </tr></thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                    <?php foreach ($data['vulnerabilities']['topCves'] as $cve): ?>
                    <tr>
                        <td class="py-2 font-mono"><?= e($cve['cve_id']) ?></td>
                        <td class="py-2 text-right"><?= $cve['affected'] ?></td>
                        <td class="py-2 text-right"><span class="inline-flex px-2 py-0.5 text-xs rounded <?= cvss_badge_class($cve['max_cvss'] ? (float)$cve['max_cvss'] : null) ?>">CVSS <?= $cve['max_cvss'] ? number_format((float)$cve['max_cvss'], 1) : '—' ?></span></td>
                        <td class="py-2 text-center"><?= $cve['public_exploit'] ? '<span class="text-red-500 font-bold">SÍ</span>' : '<span class="text-gray-400">No</span>' ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <p class="text-sm text-gray-500">Sin vulnerabilidades registradas.</p>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php if (!empty($data['threatIntel'])): ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-6">
    <h3 class="text-lg font-semibold mb-4">Threat Intelligence</h3>
    <?php if (!empty($data['threatIntel']['articles'])): ?>
        <div class="space-y-2">
            <?php foreach (array_slice($data['threatIntel']['articles'], 0, 10) as $art): ?>
                <div class="flex items-center justify-between py-2 border-b border-gray-100 dark:border-gray-700/50 last:border-0">
                    <p class="text-sm truncate"><?= e($art['title']) ?></p>
                    <span class="text-xs text-gray-400 shrink-0 ml-3"><?= e(substr($art['created_date'] ?? '', 0, 10)) ?></span>
                </div>
            <?php endforeach; ?>
        </div>
    <?php else: ?>
        <p class="text-sm text-gray-500">Sin artículos en el periodo.</p>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php if (!empty($data['secureScore'])): ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-6">
    <h3 class="text-lg font-semibold mb-4">Secure Score</h3>
    <?php if (!empty($data['secureScore']['trend'])): ?>
        <div class="space-y-2">
            <?php foreach ($data['secureScore']['trend'] as $point): ?>
                <div class="flex items-center gap-3">
                    <span class="text-xs text-gray-400 w-20 shrink-0 font-mono"><?= e(substr($point['score_date'], 0, 7)) ?></span>
                    <div class="flex-1 bg-gray-100 dark:bg-gray-800 rounded-full h-2 overflow-hidden">
                        <div class="bg-brand-500 h-full rounded-full" style="width: <?= $point['percentage'] ?? 0 ?>%"></div>
                    </div>
                    <span class="text-xs font-medium w-12 text-right"><?= $point['percentage'] ?? 0 ?>%</span>
                </div>
            <?php endforeach; ?>
        </div>
    <?php else: ?>
        <p class="text-sm text-gray-500">Sin datos de Secure Score en el periodo.</p>
    <?php endif; ?>
</div>
<?php endif; ?>

<!-- Botón LLM para resumen -->
<div class="no-print bg-brand-50 dark:bg-brand-950 border border-brand-200 dark:border-brand-800 rounded-xl p-5">
    <div class="flex items-center justify-between">
        <div>
            <h3 class="text-sm font-semibold text-brand-700 dark:text-brand-300">Resumen con IA</h3>
            <p class="text-xs text-brand-600 dark:text-brand-400 mt-0.5">Genera un resumen ejecutivo narrativo de este reporte usando LLM.</p>
        </div>
        <button onclick="summarizeReport(<?= (int)$report['id'] ?>)" id="btn-summarize" class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
            Generar resumen
        </button>
    </div>
    <div id="llm-summary" class="hidden mt-4 text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap bg-white dark:bg-surface-dark rounded-lg p-4 border border-gray-200 dark:border-gray-700"></div>
</div>

<script>
function summarizeReport(id) {
    var btn = document.getElementById('btn-summarize');
    var container = document.getElementById('llm-summary');
    btn.disabled = true;
    btn.innerHTML = '<span class="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span> Generando...';
    container.classList.remove('hidden');
    container.textContent = 'Generando resumen con IA...';

    api('POST', '<?= base_url('modules/llm/summarize-report/') ?>' + id, {})
        .then(function(res) {
            if (res.success) {
                container.textContent = res.content;
            } else {
                container.innerHTML = '<span class="text-red-500">' + (res.error || 'Error desconocido') + '</span>';
            }
        })
        .catch(function() { container.innerHTML = '<span class="text-red-500">Error de conexión</span>'; })
        .finally(function() { btn.disabled = false; btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg> Generar resumen'; });
}
</script>
