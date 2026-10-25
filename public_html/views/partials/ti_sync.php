<?php
/**
 * Partial: barra de progreso + JS de sincronización por pasos de Threat Intel.
 * Requiere $selectedTenant.
 */
$tiSyncTenant = (int)($selectedTenant ?? 0);
?>
<div id="ti-sync-progress" class="hidden fixed bottom-4 left-4 z-50 w-full max-w-md card shadow-lg p-4">
    <p class="text-sm font-medium mb-2">Sincronizando: <span id="ti-sync-phase" class="text-ink-muted"></span></p>
    <div class="h-2 w-full bg-muted rounded-full overflow-hidden">
        <div id="ti-sync-bar" class="h-full bg-brand-500 transition-all" style="width:0%"></div>
    </div>
    <p id="ti-sync-text" class="text-xs text-ink-soft mt-1.5"></p>
</div>

<div id="ti-bg-progress" class="hidden fixed bottom-4 right-4 z-50 w-full max-w-md card shadow-lg p-4" data-job="">
    <div class="flex items-center justify-between mb-2">
        <p class="text-sm font-medium">Sincronización en 2º plano</p>
        <button type="button" id="ti-bg-cancel" onclick="tiBgCancel()" class="text-xs text-red-500 hover:underline">Cancelar</button>
    </div>
    <p class="text-xs text-ink-muted mb-1">Fase: <span id="ti-bg-phase">—</span></p>
    <div class="h-2 w-full bg-muted rounded-full overflow-hidden">
        <div id="ti-bg-bar" class="h-full bg-brand-500 transition-all" style="width:0%"></div>
    </div>
    <p id="ti-bg-text" class="text-xs text-ink-soft mt-1.5"></p>
    <p class="text-[11px] text-ink-soft mt-1">Puedes seguir navegando o cerrar esta pestaña: el trabajo continúa en el servidor.</p>
</div>
<script>
function runTiSync() {
    var tenant = <?= $tiSyncTenant ?>;
    if (!tenant) { toast('Selecciona un tenant', 'warning'); return; }
    var phases = [['articles', 'Reports'], ['profiles', 'Threat actors / Tools'], ['profile_indicators', 'Indicadores de perfiles']];
    var prog = document.getElementById('ti-sync-progress');
    var bar = document.getElementById('ti-sync-bar');
    var txt = document.getElementById('ti-sync-text');
    var ph = document.getElementById('ti-sync-phase');
    if (!prog) return;
    prog.classList.remove('hidden');
    var added = 0, skipped = 0, i = 0;

    function runPhase() {
        if (i >= phases.length) {
            bar.style.width = '100%';
            txt.textContent = 'Completado · nuevos/actualizados: ' + added + ' · omitidos: ' + skipped;
            toast('Sincronización completada (' + added + ' nuevos/actualizados, ' + skipped + ' omitidos)', 'success');
            setTimeout(function () { location.reload(); }, 1500);
            return;
        }
        var phase = phases[i][0];
        var cursor = 0;

        function step() {
            api('POST', '<?= base_url('modules/threat_intelligence/sync-run') ?>/' + tenant, { phase: phase, cursor: cursor, batch: 8 })
                .then(function (res) {
                    if (!res.success) {
                        prog.classList.add('hidden');
                        toast(res.error || 'Error al sincronizar', 'error');
                        return;
                    }
                    added += (res.added || 0);
                    skipped += (res.skipped || 0);
                    cursor = res.cursor || 0;
                    var frac = res.total > 0 ? (res.processed / res.total) : (res.done ? 1 : 0);
                    if (frac > 1) { frac = 1; }
                    bar.style.width = Math.round(((i + frac) / phases.length) * 100) + '%';
                    ph.textContent = phases[i][1];
                    txt.textContent = res.processed + (res.total ? ' / ' + res.total : '') + ' · +' + added + ' · omitidos ' + skipped;
                    if (res.done) { i++; runPhase(); } else { step(); }
                })
                .catch(function () { prog.classList.add('hidden'); toast('Error de conexión', 'error'); });
        }
        step();
    }
    runPhase();
}

/* ============================================================
   Sincronización en SEGUNDO PLANO (job en el servidor)
   ============================================================ */
var TI_BG_TENANT = <?= (int)($tiSyncTenant ?? 0) ?>;
var TI_BG_BASE = '<?= base_url('modules/threat_intelligence') ?>';
var tiBgTimer = null;

function tiBgRender(st) {
    var prog = document.getElementById('ti-bg-progress');
    var bar = document.getElementById('ti-bg-bar');
    var txt = document.getElementById('ti-bg-text');
    var ph = document.getElementById('ti-bg-phase');
    var cancel = document.getElementById('ti-bg-cancel');
    if (!prog) return;
    prog.classList.remove('hidden');
    if (st.id) prog.setAttribute('data-job', st.id);
    if (ph) ph.textContent = st.phase || '—';
    var frac = st.total > 0 ? (st.processed / st.total) : (st.done ? 1 : 0);
    if (frac > 1) frac = 1;
    if (bar) bar.style.width = Math.round(frac * 100) + '%';
    if (txt) txt.textContent = (st.processed || 0) + (st.total ? ' / ' + st.total : '') + ' · +' + (st.added || 0) + ' · omitidos ' + (st.skipped || 0) + (st.message ? ' · ' + st.message : '');
    if (st.done) {
        if (cancel) cancel.classList.add('hidden');
        if (tiBgTimer) { clearTimeout(tiBgTimer); tiBgTimer = null; }
        var ok = (st.status === 'done');
        toast(ok ? 'Sincronización en 2º plano completada' : ('Sincronización ' + (st.status || 'finalizada')), ok ? 'success' : 'warning');
        setTimeout(function () { location.reload(); }, 1600);
    }
}
var tiBgFallback = false;
function tiBgUseClassic(jobId, msg) {
    if (tiBgFallback) return;
    tiBgFallback = true;
    if (msg) { toast(msg, 'warning'); }
    var go = function () {
        var p = document.getElementById('ti-bg-progress'); if (p) p.classList.add('hidden');
        runTiSync();
    };
    if (jobId) {
        api('POST', TI_BG_BASE + '/job-cancel/' + jobId, {}).then(go).catch(go);
    } else { go(); }
}
function tiBgPoll(jobId) {
    api('GET', TI_BG_BASE + '/job-status/' + jobId).then(function (st) {
        if (st && st.success) {
            tiBgRender(st);
            if (st.done) { return; }
            // Respaldo automático: si el job no avanza en ~60 s, modo clásico.
            if (!tiBgFallback && (st.age || 0) > 60) {
                tiBgUseClassic(jobId, 'El 2º plano no arrancó; usando el modo clásico');
                return;
            }
            tiBgTimer = setTimeout(function () { tiBgPoll(jobId); }, 3000);
        } else {
            var p = document.getElementById('ti-bg-progress'); if (p) p.classList.add('hidden');
        }
    }).catch(function () { tiBgTimer = setTimeout(function () { tiBgPoll(jobId); }, 5000); });
}
function startTiSync() {
    if (!TI_BG_TENANT) { toast('Selecciona un tenant', 'warning'); return; }
    tiBgFallback = false;
    var cancel = document.getElementById('ti-bg-cancel'); if (cancel) cancel.classList.remove('hidden');
    api('POST', TI_BG_BASE + '/job-start/' + TI_BG_TENANT, { type: 'ti_full' }).then(function (res) {
        if (res && res.success) {
            toast('Sincronización iniciada', 'success');
            tiBgRender({ id: res.job_id, phase: '…', added: 0, skipped: 0 });
            tiBgPoll(res.job_id);
        } else {
            toast((res && res.error) ? res.error : '2º plano no disponible; modo clásico', 'warning');
            runTiSync();
        }
    }).catch(function () { toast('2º plano no disponible; modo clásico', 'warning'); runTiSync(); });
}
function tiBgCancel() {
    var prog = document.getElementById('ti-bg-progress');
    var jid = prog ? parseInt(prog.getAttribute('data-job') || '0', 10) : 0;
    if (!jid) return;
    api('POST', TI_BG_BASE + '/job-cancel/' + jid, {}).then(function () { toast('Cancelada', 'success'); setTimeout(function () { location.reload(); }, 800); });
}
(function () {
    if (!TI_BG_TENANT) return;
    api('GET', TI_BG_BASE + '/job-active/' + TI_BG_TENANT).then(function (st) {
        if (st && st.success && st.active) { tiBgRender(st); tiBgPoll(st.id); }
    });
})();
</script>
