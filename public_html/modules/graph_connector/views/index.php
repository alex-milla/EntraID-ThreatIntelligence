<?php
/**
 * Vista índice del módulo Graph Connector.
 */
?>
<div class="mb-6 flex items-start justify-between gap-3 flex-wrap">
    <div>
        <h2 class="text-xl font-bold">Conexión Microsoft Graph</h2>
        <p class="text-sm text-ink-muted mt-1">Prueba la conexión y sincroniza datos de cada tenant. Las conexiones nuevas se crean en <strong>Admin → Tenants</strong>.</p>
    </div>
    <a href="<?= base_url('admin/tenant/edit') ?>" class="btn">
        <i class="material-icons icon-16" aria-hidden="true">add</i>
        Nuevo tenant
    </a>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <?php foreach ($tenants as $t): ?>
        <div class="card p-5" data-tenant="<?= $t['id'] ?>">
            <div class="flex items-start justify-between gap-3 mb-4">
                <div class="min-w-0">
                    <h3 class="text-sm font-semibold truncate"><?= e($t['name']) ?></h3>
                    <p class="text-xs text-ink-soft font-mono mt-0.5"><?= e(truncate($t['tenant_id'], 24)) ?></p>
                    <p class="text-xs text-ink-soft mt-0.5">
                        Sector: <span class="text-ink-muted"><?= e(($t['industry'] ?? '') !== '' && ($t['industry'] ?? null) !== null ? $t['industry'] : '—') ?></span>
                        <?php if (!empty($t['country'])): ?> · <?= e($t['country']) ?><?php endif; ?>
                    </p>
                </div>
                <span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 <?= $t['is_active'] ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400' ?>">
                    <?= $t['is_active'] ? 'Activo' : 'Inactivo' ?>
                </span>
            </div>

            <div class="flex flex-wrap gap-2">
                <button onclick="testConnection(<?= $t['id'] ?>)" class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
                    <i class="material-icons icon-14" aria-hidden="true">bolt</i>
                    Probar conexión
                </button>
                <button onclick="syncAll(<?= $t['id'] ?>)" class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">
                    <i class="material-icons icon-14" aria-hidden="true">sync</i>
                    Sincronizar todo
                </button>
                <button onclick="diagnose(<?= $t['id'] ?>)" class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
                    <i class="material-icons icon-14" aria-hidden="true">check_circle</i>
                    Diagnóstico
                </button>
                <button onclick="detectOrg(<?= $t['id'] ?>)" class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
                    <i class="material-icons icon-14" aria-hidden="true">apartment</i>
                    Detectar organización
                </button>
            </div>

            <div id="result-<?= $t['id'] ?>" class="hidden mt-3 text-xs px-3 py-2 rounded-lg"></div>
            <div id="diag-<?= $t['id'] ?>" class="hidden mt-3"></div>

            <div class="mt-3 text-xs text-ink-soft">
                Última sync: <?= $t['last_sync_at'] ? time_ago($t['last_sync_at']) : 'Nunca' ?>
                <?php if ($t['last_sync_status']): ?>
                    · Estado: <span class="<?= $t['last_sync_status'] === 'success' ? 'text-green-500' : 'text-red-500' ?>"><?= e($t['last_sync_status']) ?></span>
                <?php endif; ?>
            </div>
        </div>
    <?php endforeach; ?>

    <?php if (empty($tenants)): ?>
        <div class="lg:col-span-2 card p-8 text-center">
            <p class="text-sm text-ink-muted">No hay tenants configurados.</p>
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

function detectOrg(id) {
    var el = document.getElementById('result-' + id);
    el.classList.remove('hidden');
    el.className = 'mt-3 text-xs px-3 py-2 rounded-lg bg-blue-50 dark:bg-blue-900/20 text-blue-700';
    el.textContent = 'Detectando organización…';
    api('GET', '<?= base_url('modules/graph_connector/org') ?>/' + id, null)
        .then(function(res) {
            if (res.success && res.data) {
                el.className = 'mt-3 text-xs px-3 py-2 rounded-lg bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300';
                el.textContent = 'Organización: ' + (res.data.displayName || '') + ' · Sector: ' + (res.data.industry || '—') + ' · País: ' + (res.data.country || '—');
                setTimeout(function() { location.reload(); }, 1800);
            } else {
                el.className = 'mt-3 text-xs px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700';
                el.textContent = 'Error: ' + esc(res.message || res.error || 'No se pudo detectar');
            }
        })
        .catch(function() { el.className = 'mt-3 text-xs px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-700'; el.textContent = 'Error de conexión'; });
}

function diagnose(id) {
    var el = document.getElementById('diag-' + id);
    el.classList.remove('hidden');
    el.innerHTML = '<p class="text-xs text-ink-muted">Comprobando conexión y permisos…</p>';

    api('POST', '<?= base_url('modules/graph_connector/diagnose') ?>/' + id, {})
        .then(function(res) {
            if (!res.success) {
                el.innerHTML = '<p class="text-xs text-red-500">' + esc(res.error || 'Error') + '</p>';
                return;
            }
            var html = '<div class="bg-muted/40 rounded-lg p-3 text-xs space-y-2">';
            html += '<div><strong>Token:</strong> ' + (res.token && res.token.success
                ? '<span class="text-success">OK</span>'
                : '<span class="text-danger">ERROR</span> — ' + esc(res.token ? res.token.message : '')) + '</div>';
            html += '<div><strong>Permisos:</strong> ' + res.summary.ok + '/' + res.summary.total + ' OK'
                + (res.summary.missing ? ' · <span class="text-danger">' + res.summary.missing + ' faltan</span>' : ' <span class="text-success">✔</span>') + '</div>';
            html += '<div class="space-y-1 mt-1">';
            res.checks.forEach(function(c) {
                var icon = c.ok ? '<span class="text-success">✔</span>' : '<span class="text-danger">✘</span>';
                var detail = c.ok
                    ? (c.count !== null ? (c.count + ' elementos') : 'OK')
                    : ((c.http ? 'HTTP ' + c.http + ' — ' : '') + esc(c.message));
                html += '<div class="flex items-start gap-2">' + icon
                    + '<div class="min-w-0"><span class="font-mono">' + esc(c.permission) + '</span> <span class="text-ink-soft">[' + esc(c.scope) + ']</span>'
                    + '<div class="' + (c.ok ? 'text-ink-soft' : 'text-red-500')">' + detail + '</div></div></div>';
            });
            html += '</div>';
            if (res.last_sync) {
                html += '<div class="text-ink-soft pt-1 border-t border-line">Última sync: '
                    + esc(res.last_sync.module_key) + ' · ' + esc(res.last_sync.status)
                    + (res.last_sync.error_message ? ' — <span class="text-red-500">' + esc(res.last_sync.error_message) + '</span>' : '') + '</div>';
            }
            html += '</div>';
            el.innerHTML = html;
        })
        .catch(function() { el.innerHTML = '<p class="text-xs text-red-500">Error de conexión</p>'; });
}
</script>
