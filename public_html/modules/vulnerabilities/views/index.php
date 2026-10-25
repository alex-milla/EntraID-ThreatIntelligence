<?php
/**
 * Vista índice del módulo Vulnerabilidades.
 */
?>
<div class="mb-6">
    <form method="GET" class="flex items-center gap-3 flex-wrap">
        <label class="text-sm font-medium text-ink">Tenant:</label>
        <select name="tenant" onchange="this.form.submit()"
                class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
            <?php endforeach; ?>
        </select>
        <?php if (!empty($selectedTenant)): ?>
            <button type="button" onclick="api('POST','<?= base_url('modules/vulnerabilities/sync/' . $selectedTenant) ?>',{}).then(function(r){if(r.success){toast('Sincronizado: '+(r.records||0)+' registros','success');setTimeout(function(){location.reload()},1500);}else{toast(r.error||'Error','error');}})" class="btn btn-small">
                <i class="material-icons icon-16" aria-hidden="true">sync</i>
                Sincronizar
            </button>
        <?php endif; ?>
    </form>
</div>

<?php if (!empty($selectedTenant)): ?>
<div id="vuln-stats" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <p class="text-sm text-ink-muted">Cargando estadísticas...</p>
</div>

<div class="card overflow-hidden">
    <div class="px-5 py-4 border-b border-line">
        <h2 class="text-sm font-semibold">Vulnerabilidades</h2>
    </div>
    <div id="vuln-list" class="divide-y divide-line-subtle">
        <p class="px-5 py-8 text-sm text-ink-muted text-center">Cargando...</p>
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
                html += '<div class="card p-5">'
                    + '<p class="text-sm text-ink-muted">' + esc(row.severity || '—') + '</p>'
                    + '<p class="text-3xl font-bold mt-1 ' + color + '">' + number_format(row.cnt) + '</p>'
                    + '<p class="text-xs text-ink-soft mt-1">' + number_format(row.machines) + ' equipos</p></div>';
            });
            document.getElementById('vuln-stats').innerHTML = html || '<p class="text-sm text-ink-muted">Sin datos</p>';
        });

    api('GET', '<?= base_url('modules/vulnerabilities/list') ?>?tenant=' + tenantId + '&page=1')
        .then(function(res) {
            var html = '';
            if (!res.data || !res.data.length) {
                html = '<p class="px-5 py-8 text-sm text-ink-muted text-center">Sin vulnerabilidades. Sincroniza el tenant.</p>';
            } else {
                res.data.forEach(function(v) {
                    var cvss = v.cvss_v3 ? parseFloat(v.cvss_v3).toFixed(1) : '—';
                    var sevClass = v.severity === 'Critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                        : v.severity === 'High' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'
                        : v.severity === 'Medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                        : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
                    html += '<div class="px-5 py-3 hover:bg-muted transition-colors">'
                        + '<div class="flex items-start justify-between gap-3">'
                        + '<div class="min-w-0"><p class="text-sm font-mono font-medium">' + esc(v.cve_id) + '</p>'
                        + '<p class="text-xs text-ink-soft mt-0.5">' + esc(v.computer_dns_name || '—') + ' · ' + esc(v.product_name || '') + (v.public_exploit ? ' · <span class="text-red-500">Exploit público</span>' : '') + '</p></div>'
                        + '<div class="text-right shrink-0"><span class="inline-flex px-2 py-0.5 text-xs rounded-full ' + sevClass + '">' + esc(v.severity || '—') + '</span>'
                        + '<p class="text-xs text-ink-soft mt-0.5">CVSS ' + cvss + '</p></div>'
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
<div class="card p-8 text-center">
    <p class="text-sm text-ink-muted">Selecciona un tenant.</p>
</div>
<?php endif; ?>
