<?php
/**
 * Vista índice del módulo Incidentes.
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
            <button type="button" onclick="api('POST','<?= base_url('modules/incidents/sync/' . $selectedTenant) ?>',{}).then(function(r){toast(r.success?'Sincronizado: '+(r.records||0)+' registros':'Error','success');if(r.success)setTimeout(function(){location.reload()},1500)})" class="inline-flex items-center gap-2 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                Sincronizar
            </button>
        <?php endif; ?>
    </form>
</div>

<div id="incidents-container" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-sm font-semibold">Incidentes</h2>
    </div>
    <div id="incidents-list" class="divide-y divide-gray-100 dark:divide-gray-700/50">
        <p class="px-5 py-8 text-sm text-gray-500 text-center">Cargando...</p>
    </div>
</div>

<script>
(function() {
    var tenantId = <?= (int)($selectedTenant ?? 0) ?>;
    if (!tenantId) {
        document.getElementById('incidents-list').innerHTML = '<p class="px-5 py-8 text-sm text-gray-500 text-center">Selecciona un tenant.</p>';
        return;
    }
    api('GET', '<?= base_url('modules/incidents/list') ?>?tenant=' + tenantId)
        .then(function(res) {
            var html = '';
            if (!res.data || !res.data.length) {
                html = '<p class="px-5 py-8 text-sm text-gray-500 text-center">Sin incidentes. Sincroniza el tenant.</p>';
            } else {
                res.data.forEach(function(inc) {
                    var sevClass = inc.severity === 'high' || inc.severity === 'critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                        : inc.severity === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                        : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
                    html += '<div class="px-5 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">'
                        + '<div class="flex items-start justify-between gap-3">'
                        + '<div class="min-w-0"><p class="text-sm font-medium truncate">' + esc(inc.display_name) + '</p>'
                        + '<p class="text-xs text-gray-400 mt-0.5">' + (inc.created_date || '') + ' · ' + (inc.alert_count || 0) + ' alertas</p></div>'
                        + '<span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 ' + sevClass + '">' + esc(inc.severity || '—') + '</span>'
                        + '</div></div>';
                });
            }
            document.getElementById('incidents-list').innerHTML = html;
        })
        .catch(function() {
            document.getElementById('incidents-list').innerHTML = '<p class="px-5 py-8 text-sm text-red-500 text-center">Error al cargar incidentes.</p>';
        });

    function esc(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
})();
</script>
