<?php
/**
 * Vista índice del módulo Incidentes.
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
            <button type="button" onclick="api('POST','<?= base_url('modules/incidents/sync/' . $selectedTenant) ?>',{}).then(function(r){if(r.success){toast('Sincronizado: '+(r.records||0)+' registros','success');setTimeout(function(){location.reload()},1500);}else{toast(r.error||'Error','error');}})" class="btn btn-small">
                <i class="material-icons icon-16" aria-hidden="true">sync</i>
                Sincronizar
            </button>
        <?php endif; ?>
    </form>
</div>

<div id="incidents-container" class="card overflow-hidden">
    <div class="px-5 py-4 border-b border-line">
        <h2 class="text-sm font-semibold">Incidentes</h2>
    </div>
    <div id="incidents-list" class="divide-y divide-line-subtle">
        <p class="px-5 py-8 text-sm text-ink-muted text-center">Cargando...</p>
    </div>
</div>

<script>
(function() {
    var tenantId = <?= (int)($selectedTenant ?? 0) ?>;
    if (!tenantId) {
        document.getElementById('incidents-list').innerHTML = '<p class="px-5 py-8 text-sm text-ink-muted text-center">Selecciona un tenant.</p>';
        return;
    }
    api('GET', '<?= base_url('modules/incidents/list') ?>?tenant=' + tenantId)
        .then(function(res) {
            var html = '';
            if (!res.data || !res.data.length) {
                html = '<p class="px-5 py-8 text-sm text-ink-muted text-center">Sin incidentes. Sincroniza el tenant.</p>';
            } else {
                res.data.forEach(function(inc) {
                    var sevClass = inc.severity === 'high' || inc.severity === 'critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                        : inc.severity === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                        : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
                    html += '<a href="<?= base_url('modules/incidents/incident') ?>/' + inc.id + '" class="block px-5 py-3 hover:bg-muted transition-colors">'
                        + '<div class="flex items-start justify-between gap-3">'
                        + '<div class="min-w-0"><p class="text-sm font-medium truncate">' + esc(inc.display_name) + '</p>'
                        + '<p class="text-xs text-ink-soft mt-0.5">' + (inc.created_date || '') + ' · ' + (inc.alert_count || 0) + ' alertas</p></div>'
                        + '<span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 ' + sevClass + '">' + esc(inc.severity || '—') + '</span>'
                        + '</div></a>';
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
