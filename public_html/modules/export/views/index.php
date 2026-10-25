<?php
/**
 * Vista índice del módulo Exportación.
 */
?>
<div class="mb-6">
    <form method="GET" class="flex items-center gap-3 flex-wrap">
        <label class="text-sm font-medium text-ink">Tenant:</label>
        <select name="tenant" id="export-tenant" onchange="this.form.submit()"
                class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
            <?php endforeach; ?>
        </select>
        <span class="text-sm text-ink-muted"><?= number_format($iocCount) ?> IOCs disponibles</span>
    </form>
</div>

<?php if (!empty($selectedTenant)): ?>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Configuración de exportación -->
    <div class="card p-5">
        <h2 class="text-sm font-semibold mb-4">Configuración</h2>
        <div class="space-y-3">
            <div class="grid grid-cols-2 gap-3">
                <div>
                    <label class="block text-xs text-ink-muted mb-1">TLP</label>
                    <select id="export-tlp" class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        <option value="white">TLP:WHITE</option>
                        <option value="green" selected>TLP:GREEN</option>
                        <option value="amber">TLP:AMBER</option>
                        <option value="red">TLP:RED</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs text-ink-muted mb-1">Formato salida</label>
                    <select id="export-format" class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        <option value="merged" selected>Archivo único</option>
                        <option value="split">Separado por tipo</option>
                    </select>
                </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
                <div>
                    <label class="block text-xs text-ink-muted mb-1">Filtro por tipo</label>
                    <select id="export-type" class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        <option value="">Todos los tipos</option>
                        <?php foreach ($iocTypes as $t): ?>
                            <option value="<?= e($t['ioc_type']) ?>"><?= e($t['ioc_type']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label class="block text-xs text-ink-muted mb-1">Dirección IP (MISP)</label>
                    <select id="export-ip-dir" class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        <option value="ip-dst" selected>ip-dst</option>
                        <option value="ip-src">ip-src</option>
                        <option value="both">Ambas</option>
                    </select>
                </div>
            </div>
            <div>
                <label class="block text-xs text-ink-muted mb-1">Buscar valor</label>
                <input type="text" id="export-search" placeholder="Filtrar por valor de IOC..."
                       class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            </div>
        </div>
    </div>

    <!-- Botones de exportación -->
    <div class="card p-5">
        <h2 class="text-sm font-semibold mb-4">Exportar IOCs</h2>
        <div class="grid grid-cols-2 gap-3">
            <button onclick="doExport('txt')" class="flex flex-col items-center gap-2 p-4 rounded-lg border border-line hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 transition-colors">
                <i class="material-icons icon-32 text-ink-soft" aria-hidden="true">description</i>
                <span class="text-sm font-medium">TXT</span>
            </button>
            <button onclick="doExport('csv')" class="flex flex-col items-center gap-2 p-4 rounded-lg border border-line hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 transition-colors">
                <i class="material-icons icon-32 text-ink-soft" aria-hidden="true">dns</i>
                <span class="text-sm font-medium">CSV</span>
            </button>
            <button onclick="doExport('stix')" class="flex flex-col items-center gap-2 p-4 rounded-lg border border-line hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 transition-colors">
                <i class="material-icons icon-32 text-ink-soft" aria-hidden="true">inventory_2</i>
                <span class="text-sm font-medium">STIX 2.1</span>
            </button>
            <button onclick="doExport('misp')" class="flex flex-col items-center gap-2 p-4 rounded-lg border border-line hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 transition-colors">
                <i class="material-icons icon-32 text-ink-soft" aria-hidden="true">terminal</i>
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
<div class="card p-8 text-center">
    <p class="text-sm text-ink-muted">Selecciona un tenant para exportar IOCs.</p>
</div>
<?php endif; ?>
