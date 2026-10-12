<?php
/**
 * Vista índice del módulo Exportación.
 */
?>
<div class="mb-6">
    <form method="GET" class="flex items-center gap-3 flex-wrap">
        <label class="text-sm font-medium text-gray-700 dark:text-gray-300">Tenant:</label>
        <select name="tenant" id="export-tenant" onchange="this.form.submit()"
                class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
            <?php endforeach; ?>
        </select>
        <span class="text-sm text-gray-500"><?= number_format($iocCount) ?> IOCs disponibles</span>
    </form>
</div>

<?php if (!empty($selectedTenant)): ?>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Configuración de exportación -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h2 class="text-sm font-semibold mb-4">Configuración</h2>
        <div class="space-y-3">
            <div class="grid grid-cols-2 gap-3">
                <div>
                    <label class="block text-xs text-gray-500 mb-1">TLP</label>
                    <select id="export-tlp" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        <option value="white">TLP:WHITE</option>
                        <option value="green" selected>TLP:GREEN</option>
                        <option value="amber">TLP:AMBER</option>
                        <option value="red">TLP:RED</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs text-gray-500 mb-1">Formato salida</label>
                    <select id="export-format" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        <option value="merged" selected>Archivo único</option>
                        <option value="split">Separado por tipo</option>
                    </select>
                </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
                <div>
                    <label class="block text-xs text-gray-500 mb-1">Filtro por tipo</label>
                    <select id="export-type" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        <option value="">Todos los tipos</option>
                        <?php foreach ($iocTypes as $t): ?>
                            <option value="<?= e($t['ioc_type']) ?>"><?= e($t['ioc_type']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label class="block text-xs text-gray-500 mb-1">Dirección IP (MISP)</label>
                    <select id="export-ip-dir" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        <option value="ip-dst" selected>ip-dst</option>
                        <option value="ip-src">ip-src</option>
                        <option value="both">Ambas</option>
                    </select>
                </div>
            </div>
            <div>
                <label class="block text-xs text-gray-500 mb-1">Buscar valor</label>
                <input type="text" id="export-search" placeholder="Filtrar por valor de IOC..."
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            </div>
        </div>
    </div>

    <!-- Botones de exportación -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h2 class="text-sm font-semibold mb-4">Exportar IOCs</h2>
        <div class="grid grid-cols-2 gap-3">
            <button onclick="doExport('txt')" class="flex flex-col items-center gap-2 p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 transition-colors">
                <svg class="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                <span class="text-sm font-medium">TXT</span>
            </button>
            <button onclick="doExport('csv')" class="flex flex-col items-center gap-2 p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 transition-colors">
                <svg class="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                <span class="text-sm font-medium">CSV</span>
            </button>
            <button onclick="doExport('stix')" class="flex flex-col items-center gap-2 p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 transition-colors">
                <svg class="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>
                <span class="text-sm font-medium">STIX 2.1</span>
            </button>
            <button onclick="doExport('misp')" class="flex flex-col items-center gap-2 p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 transition-colors">
                <svg class="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                <span class="text-sm font-medium">MISP</span>
            </button>
        </div>
    </div>
</div>

<script>
function getExportConfig() {
    return {
        tenant_id: parseInt(document.getElementById('export-tenant').value),
        filters: {
            type: document.getElementById('export-type').value,
            search: document.getElementById('export-search').value
        },
        config: {
            tlp: document.getElementById('export-tlp').value,
            format: document.getElementById('export-format').value,
            ip_direction: document.getElementById('export-ip-dir').value,
            source: 'EntraID TI Platform'
        }
    };
}

function doExport(format) {
    toast('Generando exportación ' + format.toUpperCase() + '...', 'info');
    var cfg = getExportConfig();

    api('POST', '<?= base_url('modules/export') ?>/' + format, cfg)
        .then(function(res) {
            if (!res.success) { toast('Error: ' + (res.error || 'Error desconocido'), 'error'); return; }
            if (res.files) {
                // Split: descargar cada archivo
                Object.keys(res.files).forEach(function(type) {
                    var f = res.files[type];
                    downloadFile(f.content, f.filename, f.mime);
                });
                toast('Descargados ' + Object.keys(res.files).length + ' archivos', 'success');
            } else {
                downloadFile(res.content, res.filename, res.mime);
                toast('Descarga completada: ' + (res.count || 0) + ' IOCs', 'success');
            }
        })
        .catch(function() { toast('Error de conexión', 'error'); });
}
</script>
<?php else: ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
    <p class="text-sm text-gray-500">Selecciona un tenant para exportar IOCs.</p>
</div>
<?php endif; ?>
