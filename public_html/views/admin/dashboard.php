<?php
/**
 * Vista: Dashboard de administración.
 */
$pageTitle = 'Dashboard';
?>

<!-- KPIs -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <div class="flex items-center justify-between">
            <span class="text-sm text-gray-500">Tenants</span>
            <svg class="w-[18px] h-[18px] text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>
        </div>
        <p class="text-3xl font-bold mt-2"><?= $totalStats['tenants'] ?></p>
        <p class="text-xs text-gray-400 mt-1"><?= $totalStats['activeTenants'] ?> activos</p>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <div class="flex items-center justify-between">
            <span class="text-sm text-gray-500">Módulos activos</span>
            <svg class="w-[18px] h-[18px] text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>
        </div>
        <p class="text-3xl font-bold mt-2"><?= $totalStats['modules'] ?></p>
        <p class="text-xs text-gray-400 mt-1">de <?= count($modules) ?> disponibles</p>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <div class="flex items-center justify-between">
            <span class="text-sm text-gray-500">Reportes generados</span>
            <svg class="w-[18px] h-[18px] text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
        </div>
        <p class="text-3xl font-bold mt-2"><?= $totalStats['reports'] ?></p>
        <p class="text-xs text-gray-400 mt-1">histórico total</p>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <div class="flex items-center justify-between">
            <span class="text-sm text-gray-500">Grupos</span>
            <svg class="w-[18px] h-[18px] text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
        </div>
        <p class="text-3xl font-bold mt-2"><?= count($groups) ?></p>
        <p class="text-xs text-gray-400 mt-1">grupos de tenants</p>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Tenants -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h2 class="text-sm font-semibold">Tenants</h2>
            <div class="flex items-center gap-3">
                <?php if (!empty($tenants) && Auth::isAdmin()): ?>
                    <button type="button" onclick="openSync()" class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                        Sincronizar
                    </button>
                <?php endif; ?>
                <a href="<?= base_url('admin/tenants') ?>" class="text-xs text-brand-500 hover:underline">Gestionar</a>
            </div>
        </div>
        <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
            <?php if (empty($tenants)): ?>
                <p class="px-5 py-8 text-sm text-gray-500 text-center">No hay tenants configurados</p>
            <?php else: ?>
                <?php foreach (array_slice($tenants, 0, 5) as $t): ?>
                    <?php $st = $tenantStats[$t['id']] ?? []; ?>
                    <div class="px-5 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($t['name']) ?></p>
                            <p class="text-xs text-gray-400 font-mono truncate"><?= e($t['tenant_id']) ?></p>
                        </div>
                        <div class="flex items-center gap-3 shrink-0">
                            <span class="text-xs text-gray-500"><?= array_sum($st) ?> registros</span>
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $t['is_active'] ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400' ?>">
                                <?= $t['is_active'] ? 'Activo' : 'Inactivo' ?>
                            </span>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- Últimas sincronizaciones -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-sm font-semibold">Últimas sincronizaciones</h2>
        </div>
        <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
            <?php if (empty($recentSyncs)): ?>
                <p class="px-5 py-8 text-sm text-gray-500 text-center">Sin sincronizaciones aún</p>
            <?php else: ?>
                <?php foreach ($recentSyncs as $sync): ?>
                    <div class="px-5 py-3 flex items-center justify-between">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($sync['tenant_name']) ?></p>
                            <p class="text-xs text-gray-400"><?= e($sync['module_key']) ?> · <?= e($sync['sync_type']) ?></p>
                        </div>
                        <div class="text-right shrink-0">
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $sync['status'] === 'success' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : ($sync['status'] === 'error' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300') ?>">
                                <?= e($sync['status']) ?>
                            </span>
                            <p class="text-xs text-gray-400 mt-0.5"><?= time_ago($sync['started_at']) ?></p>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php if (Auth::isAdmin()): ?>
<!-- Acciones rápidas -->
<div class="mt-6 bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
    <h2 class="text-sm font-semibold mb-4">Acciones rápidas</h2>
    <div class="flex flex-wrap gap-3">
        <a href="<?= base_url('admin/tenant/edit') ?>" class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
            Nuevo tenant
        </a>
        <a href="<?= base_url('admin/modules') ?>" class="inline-flex items-center gap-2 px-4 py-2 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-sm font-medium rounded-lg transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6z"/></svg>
            Gestionar módulos
        </a>
        <a href="<?= base_url('modules/reports') ?>" class="inline-flex items-center gap-2 px-4 py-2 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-sm font-medium rounded-lg transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            Generar reporte
        </a>
    </div>
</div>
<?php endif; ?>

<?php if (Auth::isAdmin()): ?>
<!-- Modal + progreso de sincronización (Dashboard) -->
<div id="sync-modal" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/50 p-4">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 w-full max-w-lg shadow-xl">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
            <h3 class="text-lg font-semibold">Sincronizar tenants</h3>
            <p class="text-xs text-gray-500 mt-0.5">Se sincronizan todos los módulos de cada tenant seleccionado.</p>
        </div>
        <div class="p-5">
            <div class="flex items-center justify-between mb-2">
                <label class="inline-flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300">
                    <input type="checkbox" id="sync-all-chk" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500" checked>
                    Seleccionar todos
                </label>
                <span id="sync-count" class="text-xs text-gray-400"></span>
            </div>
            <div id="sync-list" class="max-h-64 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-100 dark:divide-gray-700/50"></div>
        </div>
        <div class="px-5 py-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-end gap-2">
            <button type="button" onclick="closeSync()" class="px-4 py-2 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Cancelar</button>
            <button type="button" id="sync-run" onclick="runSync()" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Sincronizar seleccionados</button>
        </div>
    </div>
</div>

<div id="sync-progress" class="fixed bottom-4 left-4 z-50 hidden max-w-sm bg-white dark:bg-surface-dark border border-gray-200 dark:border-gray-700 rounded-xl shadow-lg p-4">
    <p class="text-sm font-medium mb-1">Sincronizando…</p>
    <p id="sync-progress-text" class="text-xs text-gray-500"></p>
    <div class="mt-2 h-1.5 w-full bg-gray-100 dark:bg-gray-800 rounded-full overflow-hidden">
        <div id="sync-progress-bar" class="h-full bg-brand-500 transition-all" style="width:0%"></div>
    </div>
</div>
<?php endif; ?>

<script>
var SYNC_TENANTS = <?= json_encode(array_map(function ($t) {
    return ['id' => (int)$t['id'], 'name' => (string)$t['name'], 'active' => !empty($t['is_active'])];
}, $tenants), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

function syncEsc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }

function openSync() {
    if (!SYNC_TENANTS.length) { toast('No hay tenants configurados', 'warning'); return; }
    if (SYNC_TENANTS.length === 1) { syncTenants([SYNC_TENANTS[0].id]); return; }

    var list = document.getElementById('sync-list');
    list.innerHTML = SYNC_TENANTS.map(function (t) {
        return '<label class="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer">'
            + '<input type="checkbox" class="sync-tenant rounded border-gray-300 text-brand-500 focus:ring-brand-500" value="' + t.id + '" checked>'
            + '<span class="min-w-0 flex-1"><span class="block text-sm truncate">' + syncEsc(t.name) + '</span>'
            + '<span class="block text-xs ' + (t.active ? 'text-green-600' : 'text-gray-400') + '">' + (t.active ? 'Activo' : 'Inactivo') + '</span></span>'
            + '</label>';
    }).join('');
    list.querySelectorAll('.sync-tenant').forEach(function (cb) { cb.addEventListener('change', updateSyncCount); });

    var all = document.getElementById('sync-all-chk');
    all.checked = true;
    updateSyncCount();
    var m = document.getElementById('sync-modal');
    m.classList.remove('hidden'); m.classList.add('flex');
}

function closeSync() {
    var m = document.getElementById('sync-modal');
    m.classList.add('hidden'); m.classList.remove('flex');
}

function updateSyncCount() {
    var total = document.querySelectorAll('.sync-tenant').length;
    var sel = document.querySelectorAll('.sync-tenant:checked').length;
    document.getElementById('sync-count').textContent = sel + ' de ' + total + ' seleccionados';
    document.getElementById('sync-all-chk').checked = (total > 0 && sel === total);
}

function selectedSyncIds() {
    return Array.prototype.slice.call(document.querySelectorAll('.sync-tenant:checked'))
        .map(function (cb) { return parseInt(cb.value, 10); });
}

function runSync() {
    var ids = selectedSyncIds();
    if (!ids.length) { toast('Selecciona al menos un tenant', 'warning'); return; }
    closeSync();
    syncTenants(ids);
}

function syncTenantName(id) {
    for (var i = 0; i < SYNC_TENANTS.length; i++) { if (SYNC_TENANTS[i].id === id) return SYNC_TENANTS[i].name; }
    return '#' + id;
}

async function syncTenants(ids) {
    var prog = document.getElementById('sync-progress');
    var txt = document.getElementById('sync-progress-text');
    var bar = document.getElementById('sync-progress-bar');
    prog.classList.remove('hidden');
    bar.style.width = '0%';

    var ok = 0, err = 0, skip = 0, rec = 0, msgs = [];

    for (var i = 0; i < ids.length; i++) {
        var id = ids[i];
        var name = syncTenantName(id);
        txt.textContent = 'Sincronizando ' + (i + 1) + '/' + ids.length + ': ' + name + '…';
        bar.style.width = Math.round((i / ids.length) * 100) + '%';
        try {
            var res = await api('POST', '<?= base_url('modules/graph_connector/sync-all') ?>/' + id, {});
            var results = (res && res.results) || {};
            Object.keys(results).forEach(function (k) {
                var r = results[k] || {};
                if (r.skipped) { skip++; return; }
                if (r.success) { ok++; } else { err++; if (r.error) msgs.push(name + '/' + k + ': ' + r.error); }
                if (r.errors && r.errors.length) { msgs.push(name + '/' + k + ': ' + r.errors.join('; ')); }
                rec += (r.records || 0);
            });
        } catch (e) {
            err++;
            msgs.push(name + ': error de conexión');
        }
    }

    bar.style.width = '100%';
    txt.textContent = ids.length + ' tenants · ' + ok + ' OK, ' + err + ' con errores, ' + skip + ' omitidos, ' + rec + ' registros';
    var msg = 'Sincronización: ' + ok + ' módulos OK, ' + err + ' con errores, ' + skip + ' omitidos por permisos, ' + rec + ' registros (' + ids.length + ' tenants).';
    if (msgs.length) { msg += ' ' + msgs.slice(0, 3).join(' | '); }
    toast(msg, err === 0 ? 'success' : 'warning');

    setTimeout(function () { prog.classList.add('hidden'); location.reload(); }, 2200);
}

(function () {
    var all = document.getElementById('sync-all-chk');
    if (all) {
        all.addEventListener('change', function () {
            var checked = this.checked;
            document.querySelectorAll('.sync-tenant').forEach(function (cb) { cb.checked = checked; });
            updateSyncCount();
        });
    }
    var modal = document.getElementById('sync-modal');
    if (modal) {
        modal.addEventListener('click', function (ev) { if (ev.target === modal) closeSync(); });
    }
})();
</script>
