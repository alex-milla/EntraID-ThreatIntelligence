
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
    var url = '<?= base_url('modules/threat_intelligence/job-active-any') ?>';
    function poll() {
        fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin' })
            .then(function (r) { return r.json(); })
            .then(function (st) {
                if (st && st.success && st.active) {
                    badge.style.display = 'inline-flex';
                    var frac = (st.total > 0) ? (st.processed / st.total) : 0;
                    if (frac > 1) { frac = 1; }
                    if (pct) { pct.textContent = (st.processed || 0) + (st.total ? '/' + st.total : '') + ' · ' + Math.round(frac * 100) + '%'; }
                    setTimeout(poll, 8000);
                } else {
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
