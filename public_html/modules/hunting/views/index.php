<?php
/**
 * Vista índice del módulo Hunting (KQL).
 */
?>
<div class="mb-6">
    <form method="GET" class="flex items-center gap-3 flex-wrap">
        <label class="text-sm font-medium text-ink">Tenant:</label>
        <select name="tenant" id="tenant-select"
                class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </form>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Consultas predefinidas -->
    <div class="card p-5">
        <h2 class="text-sm font-semibold mb-4">Consultas predefinidas</h2>
        <div class="space-y-2">
            <?php foreach ($presets as $key => $preset): ?>
                <button onclick="runPreset('<?= e($key) ?>', <?= json_encode($preset['query']) ?>, '<?= e(addslashes($preset['name'])) ?>')"
                        class="w-full text-left px-4 py-3 rounded-lg border border-line hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50 dark:hover:bg-brand-950/30 transition-colors">
                    <p class="text-sm font-medium"><?= e($preset['name']) ?></p>
                    <p class="text-xs text-ink-soft font-mono mt-0.5 line-clamp-1"><?= e(truncate($preset['query'], 80)) ?></p>
                </button>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- Consulta personalizada -->
    <div class="card p-5">
        <h2 class="text-sm font-semibold mb-4">Consulta personalizada (KQL)</h2>
        <textarea id="kql-query" rows="8"
                  class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink font-mono text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none"
                  placeholder="AlertInfo&#10;  | where Timestamp >= ago(7d)&#10;  | summarize count() by Title&#10;  | top 20 by count_"></textarea>
        <button onclick="runCustom()" class="mt-3 btn w-full">
            Ejecutar consulta
        </button>
    </div>
</div>

<!-- Resultados -->
<div id="results-container" class="hidden mt-6 card overflow-hidden">
    <div class="px-5 py-4 border-b border-line flex items-center justify-between">
        <h2 class="text-sm font-semibold" id="results-title">Resultados</h2>
        <span class="text-xs text-ink-soft" id="results-count"></span>
    </div>
    <div class="overflow-x-auto">
        <table class="data-table w-full text-sm" id="results-table">
            <thead></thead>
            <tbody class="divide-y divide-line-subtle"></tbody>
        </table>
    </div>
</div>

<script>
function runPreset(key, query, name) {
    document.getElementById('kql-query').value = query;
    executeQuery(query, name);
}

function runCustom() {
    var q = document.getElementById('kql-query').value.trim();
    if (!q) { toast('Escribe una consulta KQL', 'warning'); return; }
    executeQuery(q, 'Consulta personalizada');
}

function executeQuery(query, name) {
    var tenantId = document.getElementById('tenant-select').value;
    toast('Ejecutando consulta...', 'info');

    api('POST', '<?= base_url('modules/hunting/run') ?>', {
        tenant_id: parseInt(tenantId),
        query: query,
        query_name: name
    }).then(function(res) {
        if (!res.success) { toast('Error: ' + (res.error || 'Error desconocido'), 'error'); return; }
        showResults(res.results || [], name, res.rowCount || 0);
    }).catch(function() { toast('Error de conexión', 'error'); });
}

function showResults(rows, title, count) {
    var container = document.getElementById('results-container');
    container.classList.remove('hidden');
    document.getElementById('results-title').textContent = title;
    document.getElementById('results-count').textContent = count + ' filas';

    var table = document.getElementById('results-table');
    if (!rows.length) {
        table.innerHTML = '<tbody><tr><td class="px-5 py-8 text-center text-ink-muted">Sin resultados</td></tr></tbody>';
        return;
    }

    var cols = Object.keys(rows[0]);
    var thead = '<tr class="bg-muted">' + cols.map(function(c) {
        return '<th class="text-left px-4 py-2 text-xs font-medium text-ink-muted uppercase">' + esc(c) + '</th>';
    }).join('') + '</tr>';

    var tbody = rows.map(function(row) {
        return '<tr class="hover:bg-muted">' + cols.map(function(c) {
            var val = row[c];
            if (typeof val === 'object') val = JSON.stringify(val);
            return '<td class="px-4 py-2 text-xs font-mono">' + esc(String(val ?? '')) + '</td>';
        }).join('') + '</tr>';
    }).join('');

    table.querySelector('thead').innerHTML = thead;
    table.querySelector('tbody').innerHTML = tbody;
    toast('Consulta completada: ' + count + ' filas', 'success');
}

function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
</script>
