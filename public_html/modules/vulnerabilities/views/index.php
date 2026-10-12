<?php
/**
 * Vista índice del módulo Vulnerabilidades.
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
        <?php if (!empty($selectedTenant)): ?>
            <button type="button" onclick="api('POST','<?= base_url('modules/vulnerabilities/sync/' . $selectedTenant) ?>',{}).then(function(r){toast(r.success?'Sincronizado: '+(r.records||0)+' registros':'Error',r.success?'success':'error');if(r.success)setTimeout(function(){location.reload()},1500)})" class="inline-flex items-center gap-2 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                Sincronizar
            </button>
        <?php endif; ?>
    </form>
</div>

<?php if (!empty($selectedTenant)): ?>
<div id="vuln-stats" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <p class="text-sm text-gray-500">Cargando estadísticas...</p>
</div>

<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-sm font-semibold">Vulnerabilidades</h2>
    </div>
    <div id="vuln-list" class="divide-y divide-gray-100 dark:divide-gray-700/50">
        <p class="px-5 py-8 text-sm text-gray-500 text-center">Cargando...</p>
    </div>
</div>

<script>
(function() {
    var tenantId = <?= (int)($selectedTenant ?? 0) ?>;
    if (!tenantId) return;

    api('GET', '<?= base_url('modules/vulnerabilities/stats') ?>?tenant=' + tenantId)
        .then(function(res) {
            var s = res.stats || {};
            var html = '';
            (s.bySeverity || []).forEach(function(row) {
                var color = row.severity === 'Critical' ? 'text-red-500' : row.severity === 'High' ? 'text-orange-500' : row.severity === 'Medium' ? 'text-yellow-500' : 'text-green-500';
                html += '<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">'
                    + '<p class="text-sm text-gray-500">' + esc(row.severity || '—') + '</p>'
                    + '<p class="text-3xl font-bold mt-1 ' + color + '">' + number_format(row.cnt) + '</p>'
                    + '<p class="text-xs text-gray-400 mt-1">' + number_format(row.machines) + ' equipos</p></div>';
            });
            document.getElementById('vuln-stats').innerHTML = html || '<p class="text-sm text-gray-500">Sin datos</p>';
        });

    api('GET', '<?= base_url('modules/vulnerabilities/list') ?>?tenant=' + tenantId + '&page=1')
        .then(function(res) {
            var html = '';
            if (!res.data || !res.data.length) {
                html = '<p class="px-5 py-8 text-sm text-gray-500 text-center">Sin vulnerabilidades. Sincroniza el tenant.</p>';
            } else {
                res.data.forEach(function(v) {
                    var cvss = v.cvss_v3 ? parseFloat(v.cvss_v3).toFixed(1) : '—';
                    var sevClass = v.severity === 'Critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                        : v.severity === 'High' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'
                        : v.severity === 'Medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                        : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
                    html += '<div class="px-5 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">'
                        + '<div class="flex items-start justify-between gap-3">'
                        + '<div class="min-w-0"><p class="text-sm font-mono font-medium">' + esc(v.cve_id) + '</p>'
                        + '<p class="text-xs text-gray-400 mt-0.5">' + esc(v.computer_dns_name || '—') + ' · ' + esc(v.product_name || '') + (v.public_exploit ? ' · <span class="text-red-500">Exploit público</span>' : '') + '</p></div>'
                        + '<div class="text-right shrink-0"><span class="inline-flex px-2 py-0.5 text-xs rounded-full ' + sevClass + '">' + esc(v.severity || '—') + '</span>'
                        + '<p class="text-xs text-gray-400 mt-0.5">CVSS ' + cvss + '</p></div>'
                        + '</div></div>';
                });
            }
            document.getElementById('vuln-list').innerHTML = html;
        })
        .catch(function() {
            document.getElementById('vuln-list').innerHTML = '<p class="px-5 py-8 text-sm text-red-500 text-center">Error al cargar.</p>';
        });

    function esc(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
    function number_format(n) { return (n || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, '.'); }
})();
</script>
<?php else: ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
    <p class="text-sm text-gray-500">Selecciona un tenant.</p>
</div>
<?php endif; ?>
