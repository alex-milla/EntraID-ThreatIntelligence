
        </div><!-- /page-container -->
    </main>

    <footer class="page-footer">
        <div class="page-container">
            <div class="footer-row">
                <span class="footer-text"><?= e(APP_NAME) ?></span>
                <span class="footer-text mono">v<?= e(APP_VERSION) ?></span>
            </div>
        </div>
    </footer>
</div><!-- /app-body -->
</div><!-- /app-shell -->

<!-- Scripts globales -->
<script src="<?= asset_url('js/app.js') ?>?v=<?= e(APP_VERSION) ?>"></script>
<script src="<?= asset_url('js/shell.js') ?>?v=<?= e(APP_VERSION) ?>"></script>
<script src="<?= asset_url('js/filters.js') ?>?v=<?= e(APP_VERSION) ?>"></script>
<script src="<?= asset_url('js/ui.js') ?>?v=<?= e(APP_VERSION) ?>"></script>
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
<?php if (Auth::check()): ?>
/* Indicador global de sincronización CVE (badge en el sidebar, todas las pantallas) */
(function () {
    var badge = document.getElementById('cve-sync-badge');
    if (!badge) return;
    var pct = document.getElementById('cve-sync-badge-pct');
    var stop = document.getElementById('cve-sync-badge-stop');
    var url = '<?= base_url('modules/cve/active') ?>';
    var cancelUrl = '<?= base_url('modules/cve/cancel') ?>';
    var wasActive = false;

    if (stop) {
        stop.addEventListener('click', function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            var done = function () {
                badge.style.display = 'none';
                if (typeof toast === 'function') { toast('Sincronización CVE detenida', 'success'); }
            };
            if (typeof api === 'function') {
                api('POST', cancelUrl, {}).then(done).catch(done);
            } else {
                var tok = (document.querySelector('input[name="csrf_token"]') || {}).value || '';
                fetch(cancelUrl, { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': tok }, credentials: 'same-origin' }).then(done).catch(done);
            }
        });
    }

    function poll() {
        fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin' })
            .then(function (r) { return r.json(); })
            .then(function (res) {
                var st = (res && res.state) ? res.state : null;
                var active = !!(res && res.active && st && (st.status === 'queued' || st.status === 'running'));
                if (active) {
                    wasActive = true;
                    badge.style.display = 'inline-flex';
                    var processed = parseInt(st.processed || 0, 10);
                    var total = parseInt(st.total || 0, 10);
                    var frac = total > 0 ? (processed / total) : 0;
                    if (frac > 1) { frac = 1; }
                    if (pct) {
                        pct.textContent = processed.toLocaleString('es-ES')
                            + (total > 0 ? '/' + total.toLocaleString('es-ES') : '')
                            + ' · ' + Math.round(frac * 100) + '%';
                    }
                    badge.title = st.message || 'Sincronización CVE en curso';
                    setTimeout(poll, 8000);
                } else {
                    badge.style.display = 'none';
                    if (wasActive) {
                        wasActive = false;
                        var status = st ? String(st.status || '') : '';
                        if (typeof toast === 'function') {
                            if (status === 'idle') {
                                toast('Catálogo CVE actualizado', 'success');
                            } else if (status === 'error') {
                                toast('Sincronización CVE con error' + (st && st.message ? ': ' + st.message : ''), 'error');
                            } else if (status === 'cancelled') {
                                toast('Sincronización CVE cancelada', 'warning');
                            }
                        }
                    }
                    setTimeout(poll, 15000);
                }
            })
            .catch(function () { setTimeout(poll, 20000); });
    }

    poll();
})();
<?php endif; ?>
</script>
</body>
</html>
