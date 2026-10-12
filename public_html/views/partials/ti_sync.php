<?php
/**
 * Partial: barra de progreso + JS de sincronización por pasos de Threat Intel.
 * Requiere $selectedTenant.
 */
$tiSyncTenant = (int)($selectedTenant ?? 0);
?>
<div id="ti-sync-progress" class="hidden fixed bottom-4 left-4 z-50 w-full max-w-md bg-white dark:bg-surface-dark border border-gray-200 dark:border-gray-700 rounded-xl shadow-lg p-4">
    <p class="text-sm font-medium mb-2">Sincronizando: <span id="ti-sync-phase" class="text-gray-500"></span></p>
    <div class="h-2 w-full bg-gray-100 dark:bg-gray-800 rounded-full overflow-hidden">
        <div id="ti-sync-bar" class="h-full bg-brand-500 transition-all" style="width:0%"></div>
    </div>
    <p id="ti-sync-text" class="text-xs text-gray-400 mt-1.5"></p>
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
</script>
