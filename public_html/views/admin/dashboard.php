<?php
/**
 * Vista: Dashboard de administración.
 */
$pageTitle = 'Dashboard';
?>

<!-- KPIs -->
<div class="stat-strip">
    <div class="stat">
        <span class="stat-ico"><i class="material-icons icon-18" aria-hidden="true">business</i></span>
        <div class="min-w-0">
            <p class="stat-num"><?= $totalStats['tenants'] ?></p>
            <p class="stat-label">Tenants · <?= $totalStats['activeTenants'] ?> activos</p>
        </div>
    </div>

    <div class="stat">
        <span class="stat-ico info"><i class="material-icons icon-18" aria-hidden="true">widgets</i></span>
        <div class="min-w-0">
            <p class="stat-num"><?= $totalStats['modules'] ?></p>
            <p class="stat-label">Módulos · de <?= count($modules) ?></p>
        </div>
    </div>

    <div class="stat">
        <span class="stat-ico ok"><i class="material-icons icon-18" aria-hidden="true">analytics</i></span>
        <div class="min-w-0">
            <p class="stat-num"><?= $totalStats['reports'] ?></p>
            <p class="stat-label">Reportes generados</p>
        </div>
    </div>

    <div class="stat">
        <span class="stat-ico warn"><i class="material-icons icon-18" aria-hidden="true">group</i></span>
        <div class="min-w-0">
            <p class="stat-num"><?= count($groups) ?></p>
            <p class="stat-label">Grupos de tenants</p>
        </div>
    </div>
</div>

<?php if (!empty($sectorPriority) && !empty($sectorPriority['stats']['sectors'])):
    $sp    = $sectorPriority;
    $spTop = $sp['stats']['sectors'][0] ?? null;
    $spUrl = base_url('modules/threat_intelligence') . '?' . http_build_query(array_filter([
        'tenant' => (int)$sp['tenant']['id'],
        'from'   => (string)$sp['from'],
        'to'     => (string)$sp['to'],
        'sector' => $spTop ? (string)$spTop['sector'] : '',
    ]));
    $spList = array_values(array_filter($sp['stats']['sectors'], fn($s) => (int)$s['count'] > 0));
?>
<div class="mb-6 card p-5">
    <div class="flex items-center justify-between gap-3 flex-wrap">
        <div>
            <p class="text-[11px] uppercase tracking-wide text-ink-soft">Sector a priorizar (últimas 24 h) · <?= e($sp['tenant']['name']) ?></p>
            <?php if ($spTop && (int)$spTop['count'] > 0): ?>
                <p class="text-2xl font-bold text-brand-500 mt-1"><?= e((string)$spTop['sector']) ?></p>
                <p class="text-xs text-ink-muted mt-0.5">El más afectado: <?= (int)$spTop['count'] ?> noticia<?= (int)$spTop['count'] === 1 ? '' : 's' ?> (<?= (int)$spTop['pct'] ?>% de <?= (int)$sp['stats']['total'] ?>)</p>
            <?php else: ?>
                <p class="text-sm text-ink-muted mt-1">Sin noticias en las últimas 24 h.</p>
            <?php endif; ?>
        </div>
        <?php if ($spTop && (int)$spTop['count'] > 0): ?>
            <a href="<?= e($spUrl) ?>" class="btn">Ver noticias de <?= e((string)$spTop['sector']) ?> →</a>
        <?php endif; ?>
    </div>
    <?php if (count($spList) > 1): ?>
        <div class="mt-4 flex flex-wrap gap-x-4 gap-y-1">
            <?php foreach (array_slice($spList, 0, 6) as $s): ?>
                <span class="text-xs text-ink-muted"><?= e((string)$s['sector']) ?> <span class="font-semibold text-ink"><?= (int)$s['count'] ?></span></span>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>
<?php endif; ?>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Tenants -->
    <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-line flex items-center justify-between">
            <h2 class="text-sm font-semibold">Tenants</h2>
            <div class="flex items-center gap-3">
                <?php if (!empty($tenants) && Auth::isAdmin()): ?>
                    <button type="button" onclick="openSync()" class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">
                        <i class="material-icons icon-14" aria-hidden="true">sync</i>
                        Sincronizar
                    </button>
                <?php endif; ?>
                <a href="<?= base_url('admin/tenants') ?>" class="text-xs text-brand-500 hover:underline">Gestionar</a>
            </div>
        </div>
        <div class="divide-y divide-line-subtle">
            <?php if (empty($tenants)): ?>
                <p class="px-5 py-8 text-sm text-ink-muted text-center">No hay tenants configurados</p>
            <?php else: ?>
                <?php foreach (array_slice($tenants, 0, 5) as $t): ?>
                    <?php $st = $tenantStats[$t['id']] ?? []; ?>
                    <div class="px-5 py-3 flex items-center justify-between hover:bg-muted">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($t['name']) ?></p>
                            <p class="text-xs text-ink-soft font-mono truncate"><?= e($t['tenant_id']) ?></p>
                        </div>
                        <div class="flex items-center gap-3 shrink-0">
                            <span class="text-xs text-ink-muted"><?= array_sum($st) ?> registros</span>
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
    <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-line">
            <h2 class="text-sm font-semibold">Últimas sincronizaciones</h2>
        </div>
        <div class="divide-y divide-line-subtle">
            <?php if (empty($recentSyncs)): ?>
                <p class="px-5 py-8 text-sm text-ink-muted text-center">Sin sincronizaciones aún</p>
            <?php else: ?>
                <?php foreach ($recentSyncs as $sync): ?>
                    <div class="px-5 py-3 flex items-center justify-between">
                        <div class="min-w-0">
                            <p class="text-sm font-medium truncate"><?= e($sync['tenant_name']) ?></p>
                            <p class="text-xs text-ink-soft"><?= e($sync['module_key']) ?> · <?= e($sync['sync_type']) ?></p>
                        </div>
                        <div class="text-right shrink-0">
                            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $sync['status'] === 'success' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : ($sync['status'] === 'error' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300') ?>">
                                <?= e($sync['status']) ?>
                            </span>
                            <p class="text-xs text-ink-soft mt-0.5"><?= time_ago($sync['started_at']) ?></p>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php if (Auth::isAdmin()): ?>
<!-- Acciones rápidas -->
<div class="mt-6 card p-5">
    <h2 class="text-sm font-semibold mb-4">Acciones rápidas</h2>
    <div class="flex flex-wrap gap-3">
        <a href="<?= base_url('admin/tenant/edit') ?>" class="btn">
            <i class="material-icons icon-16" aria-hidden="true">add</i>
            Nuevo tenant
        </a>
        <a href="<?= base_url('admin/modules') ?>" class="btn btn-outline">
            <i class="material-icons icon-16" aria-hidden="true">widgets</i>
            Gestionar módulos
        </a>
        <a href="<?= base_url('modules/reports') ?>" class="btn btn-outline">
            <i class="material-icons icon-16" aria-hidden="true">analytics</i>
            Generar reporte
        </a>
    </div>
</div>
<?php endif; ?>

<?php if (Auth::isAdmin()): ?>
<!-- Modal + progreso de sincronización (Dashboard) -->
<div id="sync-modal" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/50 p-4">
    <div class="card w-full max-w-lg shadow-xl">
        <div class="px-5 py-4 border-b border-line">
            <h3 class="text-lg font-semibold">Sincronizar tenants</h3>
            <p class="text-xs text-ink-muted mt-0.5">Se sincronizan todos los módulos de cada tenant seleccionado.</p>
        </div>
        <div class="p-5">
            <div class="flex items-center justify-between mb-2">
                <label class="inline-flex items-center gap-2 text-xs text-ink-muted">
                    <input type="checkbox" id="sync-all-chk" class="rounded border-line-strong text-brand-500 focus:ring-brand-500" checked>
                    Seleccionar todos
                </label>
                <span id="sync-count" class="text-xs text-ink-soft"></span>
            </div>
            <div id="sync-list" class="max-h-64 overflow-y-auto border border-line rounded-lg divide-y divide-line-subtle"></div>
        </div>
        <div class="px-5 py-4 border-t border-line flex items-center justify-end gap-2">
            <button type="button" onclick="closeSync()" class="px-4 py-2 border border-line text-ink text-sm font-medium rounded-lg hover:bg-muted transition-colors">Cancelar</button>
            <button type="button" id="sync-run" onclick="runSync()" class="btn">Sincronizar seleccionados</button>
        </div>
    </div>
</div>

<div id="sync-progress" class="fixed bottom-4 left-4 z-50 hidden max-w-sm card shadow-lg p-4">
    <p class="text-sm font-medium mb-1">Sincronizando…</p>
    <p id="sync-progress-text" class="text-xs text-ink-muted"></p>
    <div class="mt-2 h-1.5 w-full bg-muted rounded-full overflow-hidden">
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
        return '<label class="flex items-center gap-3 px-4 py-2.5 hover:bg-muted cursor-pointer">'
            + '<input type="checkbox" class="sync-tenant rounded border-line-strong text-brand-500 focus:ring-brand-500" value="' + t.id + '" checked>'
            + '<span class="min-w-0 flex-1"><span class="block text-sm truncate">' + syncEsc(t.name) + '</span>'
            + '<span class="block text-xs ' + (t.active ? 'text-success' : 'text-ink-soft')">' + (t.active ? 'Activo' : 'Inactivo') + '</span></span>'
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
