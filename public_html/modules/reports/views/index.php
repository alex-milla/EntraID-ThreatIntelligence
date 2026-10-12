<?php
/**
 * Vista índice del módulo Reportes.
 */
?>
<div class="mb-6">
    <form method="GET" class="flex items-center gap-3 flex-wrap">
        <label class="text-sm font-medium text-gray-700 dark:text-gray-300">Tenant:</label>
        <select name="tenant" onchange="this.form.submit()"
                class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </form>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Generar reporte -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h2 class="text-sm font-semibold mb-4">Generar reporte</h2>
        <div class="space-y-3">
            <div>
                <label class="block text-xs text-gray-500 mb-1">Tipo de reporte</label>
                <select id="report-type" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="full">Completo</option>
                    <option value="executive">Ejecutivo</option>
                    <option value="incidents">Incidentes</option>
                    <option value="vulnerabilities">Vulnerabilidades</option>
                    <option value="threat_intel">Threat Intelligence</option>
                    <option value="secure_score">Secure Score</option>
                </select>
            </div>
            <div>
                <label class="block text-xs text-gray-500 mb-1">Periodo</label>
                <select id="period-type" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="daily">Diario</option>
                    <option value="weekly">Semanal</option>
                    <option value="monthly" selected>Mensual</option>
                    <option value="quarterly">Trimestral</option>
                    <option value="yearly">Anual</option>
                </select>
            </div>
            <button onclick="generateReport()" class="w-full px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                Generar reporte
            </button>
        </div>
    </div>

    <!-- Reportes generados -->
    <div class="lg:col-span-2 bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-sm font-semibold">Reportes generados</h2>
        </div>
        <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
            <?php if (empty($reports['data'])): ?>
                <p class="px-5 py-8 text-sm text-gray-500 text-center">Sin reportes generados</p>
            <?php else: ?>
                <?php foreach ($reports['data'] as $r): ?>
                    <div class="px-5 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($r['title']) ?></p>
                            <p class="text-xs text-gray-400"><?= e($r['report_type']) ?> · <?= e($r['period_type']) ?> · <?= time_ago($r['generated_at']) ?></p>
                        </div>
                        <a href="<?= base_url('modules/reports/view/' . $r['id']) ?>" class="text-xs text-brand-500 hover:underline shrink-0 ml-3">Ver</a>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
function generateReport() {
    var tenantId = <?= (int)($selectedTenant ?? 0) ?>;
    if (!tenantId) { toast('Selecciona un tenant', 'warning'); return; }

    toast('Generando reporte...', 'info');
    api('POST', '<?= base_url('modules/reports/generate') ?>', {
        tenant_id: tenantId,
        report_type: document.getElementById('report-type').value,
        period_type: document.getElementById('period-type').value
    }).then(function(res) {
        if (res.success) {
            toast('Reporte generado: ' + res.title, 'success');
            setTimeout(function() { location.reload(); }, 1500);
        } else {
            toast('Error al generar reporte', 'error');
        }
    }).catch(function() { toast('Error de conexión', 'error'); });
}
</script>
