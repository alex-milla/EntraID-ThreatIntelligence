<?php
/**
 * Vista índice del módulo Graph Connector.
 */
?>
<div class="mb-6">
    <h2 class="text-xl font-bold">Conexión Microsoft Graph</h2>
    <p class="text-sm text-gray-500 mt-1">Prueba la conexión y sincroniza datos de cada tenant.</p>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <?php foreach ($tenants as $t): ?>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5" data-tenant="<?= $t['id'] ?>">
            <div class="flex items-start justify-between gap-3 mb-4">
                <div class="min-w-0">
                    <h3 class="text-sm font-semibold truncate"><?= e($t['name']) ?></h3>
                    <p class="text-xs text-gray-400 font-mono mt-0.5"><?= e(truncate($t['tenant_id'], 24)) ?></p>
                </div>
                <span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 <?= $t['is_active'] ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400' ?>">
                    <?= $t['is_active'] ? 'Activo' : 'Inactivo' ?>
                </span>
            </div>

            <div class="flex flex-wrap gap-2">
                <button onclick="testConnection(<?= $t['id'] ?>)" class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                    Probar conexión
                </button>
                <button onclick="syncAll(<?= $t['id'] ?>)" class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                    Sincronizar todo
                </button>
                <button onclick="diagnose(<?= $t['id'] ?>)" class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    Diagnóstico
                </button>
            </div>

            <div id="result-<?= $t['id'] ?>" class="hidden mt-3 text-xs px-3 py-2 rounded-lg"></div>
            <div id="diag-<?= $t['id'] ?>" class="hidden mt-3"></div>

            <div class="mt-3 text-xs text-gray-400">
                Última sync: <?= $t['last_sync_at'] ? time_ago($t['last_sync_at']) : 'Nunca' ?>
                <?php if ($t['last_sync_status']): ?>
                    · Estado: <span class="<?= $t['last_sync_status'] === 'success' ? 'text-green-500' : 'text-red-500' ?>"><?= e($t['last_sync_status']) ?></span>
                <?php endif; ?>
            </div>
        </div>
    <?php endforeach; ?>

    <?php if (empty($tenants)): ?>
        <div class="lg:col-span-2 bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
            <p class="text-sm text-gray-500">No hay tenants configurados.</p>
            <a href="<?= base_url('admin/tenants') ?>" class="inline-block mt-3 text-sm text-brand-500 hover:underline">Añadir tenant</a>
        </div>
    <?php endif; ?>
</div>

<script>
function testConnection(id) {
    var el = document.getElementById('result-' + id);
    el.classList.remove('hidden');
    el.className = 'mt-3 text-xs px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-800';
    el.textContent = 'Probando conexión...';

    api('POST', '<?= base_url('modules/graph_connector/test') ?>/' + id, {})
        .then(function(res) {
            el.className = 'mt-3 text-xs px-3 py-2 rounded-lg ' + (res.success ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300' : 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300');
            el.textContent = res.message;
        })
        .catch(function() { el.textContent = 'Error de conexión'; el.className = 'mt-3 text-xs px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700'; });
}

function syncAll(id) {
    var el = document.getElementById('result-' + id);
    el.classList.remove('hidden');
    el.className = 'mt-3 text-xs px-3 py-2 rounded-lg bg-blue-50 dark:bg-blue-900/20 text-blue-700';
    el.textContent = 'Sincronizando todos los módulos...';

    api('POST', '<?= base_url('modules/graph_connector/sync-all') ?>/' + id, {})
        .then(function(res) {
            var results = res.results || {};
            var ok = 0, err = 0, skip = 0, rec = 0, msgs = [], skips = [];
            Object.keys(results).forEach(function(k) {
                var r = results[k] || {};
                if (r.skipped) { skip++; skips.push(k + ' (' + (r.reason || 'sin permisos') + ')'); return; }
                if (r.success) ok++; else err++;
                rec += (r.records || 0);
                if (r.error) msgs.push(k + ': ' + r.error);
                if (r.errors && r.errors.length) msgs.push(k + ': ' + r.errors.join('; '));
            });
            var msg = ok + ' sincronizados, ' + err + ' con errores, ' + skip + ' omitidos por permisos, ' + rec + ' registros.';
            if (skips.length) msg += ' Omitidos: ' + skips.join(' | ');
            if (msgs.length) msg += ' Errores: ' + msgs.join(' | ');
            el.className = 'mt-3 text-xs px-3 py-2 rounded-lg ' + (err === 0 ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300' : 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700');
            el.textContent = msg;
            if (rec > 0) setTimeout(function() { location.reload(); }, 2500);
        })
        .catch(function() { el.textContent = 'Error de conexión'; el.className = 'mt-3 text-xs px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700'; });
}

function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }

function diagnose(id) {
    var el = document.getElementById('diag-' + id);
    el.classList.remove('hidden');
    el.innerHTML = '<p class="text-xs text-gray-500">Comprobando conexión y permisos…</p>';

    api('POST', '<?= base_url('modules/graph_connector/diagnose') ?>/' + id, {})
        .then(function(res) {
            if (!res.success) {
                el.innerHTML = '<p class="text-xs text-red-500">' + esc(res.error || 'Error') + '</p>';
                return;
            }
            var html = '<div class="bg-gray-50 dark:bg-gray-800/40 rounded-lg p-3 text-xs space-y-2">';
            html += '<div><strong>Token:</strong> ' + (res.token && res.token.success
                ? '<span class="text-green-600">OK</span>'
                : '<span class="text-red-600">ERROR</span> — ' + esc(res.token ? res.token.message : '')) + '</div>';
            html += '<div><strong>Permisos:</strong> ' + res.summary.ok + '/' + res.summary.total + ' OK'
                + (res.summary.missing ? ' · <span class="text-red-600">' + res.summary.missing + ' faltan</span>' : ' <span class="text-green-600">✔</span>') + '</div>';
            html += '<div class="space-y-1 mt-1">';
            res.checks.forEach(function(c) {
                var icon = c.ok ? '<span class="text-green-600">✔</span>' : '<span class="text-red-600">✘</span>';
                var detail = c.ok
                    ? (c.count !== null ? (c.count + ' elementos') : 'OK')
                    : ((c.http ? 'HTTP ' + c.http + ' — ' : '') + esc(c.message));
                html += '<div class="flex items-start gap-2">' + icon
                    + '<div class="min-w-0"><span class="font-mono">' + esc(c.permission) + '</span> <span class="text-gray-400">[' + esc(c.scope) + ']</span>'
                    + '<div class="' + (c.ok ? 'text-gray-400' : 'text-red-500') + '">' + detail + '</div></div></div>';
            });
            html += '</div>';
            if (res.last_sync) {
                html += '<div class="text-gray-400 pt-1 border-t border-gray-200 dark:border-gray-700">Última sync: '
                    + esc(res.last_sync.module_key) + ' · ' + esc(res.last_sync.status)
                    + (res.last_sync.error_message ? ' — <span class="text-red-500">' + esc(res.last_sync.error_message) + '</span>' : '') + '</div>';
            }
            html += '</div>';
            el.innerHTML = html;
        })
        .catch(function() { el.innerHTML = '<p class="text-xs text-red-500">Error de conexión</p>'; });
}
</script>
