
    </main>
</div><!-- /contenido principal -->

<!-- Scripts globales -->
<script src="<?= asset_url('js/app.js') ?>?v=<?= filemtime(ASSETS_PATH . '/js/app.js') ?: '1' ?>"></script>
<script>
/* Indicador global de sincronización (badge en el sidebar, todas las pantallas) */
(function () {
    var badge = document.getElementById('ti-sync-badge');
    if (!badge) return;
    var pct = document.getElementById('ti-sync-badge-pct');
    var stop = document.getElementById('ti-sync-badge-stop');
    var url = '<?= base_url('modules/threat_intelligence/job-active-any') ?>';
    var cancelBase = '<?= base_url('modules/threat_intelligence/job-cancel') ?>';
    var currentJob = 0;

    if (stop) {
        stop.addEventListener('click', function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            if (!currentJob) { return; }
            var id = currentJob;
            var go = function () { badge.style.display = 'none'; currentJob = 0; if (typeof toast === 'function') { toast('Sincronización detenida', 'success'); } };
            if (typeof api === 'function') {
                api('POST', cancelBase + '/' + id, {}).then(go).catch(go);
            } else {
                var tok = (document.querySelector('input[name="csrf_token"]') || {}).value || '';
                fetch(cancelBase + '/' + id, { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': tok }, credentials: 'same-origin' }).then(go).catch(go);
            }
        });
    }

    function poll() {
        fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin' })
            .then(function (r) { return r.json(); })
            .then(function (st) {
                if (st && st.success && st.active) {
                    currentJob = st.id || 0;
                    badge.style.display = 'inline-flex';
                    var frac = (st.total > 0) ? (st.processed / st.total) : 0;
                    if (frac > 1) { frac = 1; }
                    if (pct) { pct.textContent = (st.processed || 0) + (st.total ? '/' + st.total : '') + ' · ' + Math.round(frac * 100) + '%'; }
                    setTimeout(poll, 8000);
                } else {
                    currentJob = 0;
                    badge.style.display = 'none';
                    setTimeout(poll, 15000);
                }
            })
            .catch(function () { setTimeout(poll, 20000); });
    }
    poll();
})();
</script>
</body>
</html>
