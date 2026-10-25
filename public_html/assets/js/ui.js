/**
 * ui.js — Comportamientos transversales: acciones en lote, menú de fila,
 * drawer de detalle, back-to-top, atajo de búsqueda y refresco parcial.
 * Sistema visual: md/ESPECIFICACION-UI.md §6.9–§6.11 y §7.2
 */
(function () {
    'use strict';

    function ready(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    ready(function () {

        // ============================================================
        // Acciones en lote (toolbar contextual)
        // ============================================================
        var bulkForm = document.querySelector('form[id="bulk-form"]');
        if (bulkForm) {
            var toolbar = bulkForm.querySelector('.bulk-toolbar');
            var counter = bulkForm.querySelector('[data-selection-count]');

            function refreshSelection() {
                var checks = bulkForm.querySelectorAll('.row-check');
                var selected = bulkForm.querySelectorAll('.row-check:checked');
                var has = selected.length > 0;

                bulkForm.classList.toggle('has-selection', has);
                if (toolbar) { toolbar.classList.toggle('is-visible', has); }
                if (counter) { counter.textContent = String(selected.length); }
                document.body.classList.toggle('selection-mode', selected.length >= 2);
                if (selected.length >= 2 && typeof window.closeDetailDrawer === 'function') {
                    window.closeDetailDrawer();
                }
                checks.forEach(function (c) {
                    var row = c.closest('tr');
                    if (row) { row.classList.toggle('is-selected', c.checked); }
                });
            }

            bulkForm.addEventListener('change', function (e) {
                if (e.target.classList && e.target.classList.contains('row-check')) {
                    refreshSelection();
                }
            });

            var all = bulkForm.querySelector('[data-check-all]');
            if (all) {
                all.addEventListener('change', function () {
                    bulkForm.querySelectorAll('.row-check').forEach(function (c) {
                        c.checked = all.checked;
                    });
                    refreshSelection();
                });
            }

            refreshSelection();
        }

        // ============================================================
        // Menú de acción por fila (posicionamiento fixed)
        // ============================================================
        var openMenu = null;
        var openTrigger = null;

        function closeActionMenu() {
            if (!openMenu) { return; }
            openMenu.hidden = true;
            if (openTrigger) { openTrigger.setAttribute('aria-expanded', 'false'); }
            openMenu = null;
            openTrigger = null;
        }

        function positionMenu(trigger, menu) {
            var r = trigger.getBoundingClientRect();
            menu.hidden = false;
            menu.style.visibility = 'hidden';
            menu.style.left = '0px';
            menu.style.top = '0px';

            var mw = menu.offsetWidth;
            var mh = menu.offsetHeight;
            var left = Math.max(8, Math.min(r.right - mw, window.innerWidth - mw - 8));
            var top = r.bottom + 4;
            if (top + mh > window.innerHeight - 8) {
                top = Math.max(8, r.top - mh - 4);
            }

            menu.style.left = left + 'px';
            menu.style.top = top + 'px';
            menu.style.visibility = '';
        }

        document.addEventListener('click', function (e) {
            var trigger = e.target.closest ? e.target.closest('[data-action-menu]') : null;
            if (trigger) {
                e.preventDefault();
                e.stopPropagation();
                var targetId = trigger.getAttribute('data-action-menu');
                var menu = document.getElementById(targetId);
                if (!menu) { return; }
                if (openMenu === menu) { closeActionMenu(); return; }
                closeActionMenu();
                openMenu = menu;
                openTrigger = trigger;
                trigger.setAttribute('aria-expanded', 'true');
                positionMenu(trigger, menu);
                return;
            }

            if (openMenu && !openMenu.contains(e.target)) { closeActionMenu(); }
        });

        window.addEventListener('scroll', closeActionMenu, true);
        window.addEventListener('resize', closeActionMenu);
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && openMenu) {
                var t = openTrigger;
                closeActionMenu();
                if (t) { t.focus(); }
            }
        });

        // ============================================================
        // Drawer de detalle
        // ============================================================
        var shell = document.querySelector('.app-shell');
        var drawer = document.getElementById('detail-drawer');
        var drawerBody = drawer ? drawer.querySelector('.dd-body') : null;
        var drawerTitle = drawer ? drawer.querySelector('.dd-title') : null;
        var drawerOverlay = document.getElementById('detail-overlay');
        var lastDetailTrigger = null;

        function openDetailDrawer(trigger) {
            if (!drawer || !shell) { return; }

            lastDetailTrigger = trigger || null;
            var url = trigger ? trigger.getAttribute('data-detail-url') : null;
            var targetId = trigger ? trigger.getAttribute('data-detail-target') : null;

            if (url && drawerBody) {
                drawerBody.innerHTML = '<div class="p-4 text-sm text-ink-muted">Cargando…</div>';
                fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin' })
                    .then(function (r) { return r.text(); })
                    .then(function (html) { drawerBody.innerHTML = html; })
                    .catch(function () {
                        drawerBody.innerHTML = '<div class="alert alert-error">No se pudo cargar el detalle.</div>';
                    });
            } else if (targetId && drawerBody) {
                var src = document.getElementById(targetId);
                if (src) { drawerBody.innerHTML = src.innerHTML; }
            }

            if (drawerTitle && trigger) {
                drawerTitle.textContent = trigger.getAttribute('data-detail-title') || '';
            }

            drawer.classList.add('is-open');
            shell.classList.add('drawer-detail');
            if (drawerOverlay) { drawerOverlay.hidden = false; }
            document.body.classList.add('overflow-hidden');
        }

        function closeDetailDrawer() {
            if (!drawer) { return; }
            drawer.classList.remove('is-open');
            if (shell) { shell.classList.remove('drawer-detail'); }
            if (drawerOverlay) { drawerOverlay.hidden = true; }
            document.body.classList.remove('overflow-hidden');
            if (lastDetailTrigger) { lastDetailTrigger.focus(); lastDetailTrigger = null; }
        }

        window.closeDetailDrawer = closeDetailDrawer;

        document.addEventListener('click', function (e) {
            var trigger = e.target.closest ? e.target.closest('[data-detail-open], [data-detail-url], [data-detail-target]') : null;
            if (trigger) {
                if (trigger.getAttribute('href') === '#!') { e.preventDefault(); }
                openDetailDrawer(trigger);
                return;
            }
            if (drawer && drawer.contains(e.target)) {
                if (e.target.closest('[data-detail-close]')) {
                    e.preventDefault();
                    closeDetailDrawer();
                }
            }
        });

        if (drawerOverlay) {
            drawerOverlay.addEventListener('click', closeDetailDrawer);
        }

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && drawer && drawer.classList.contains('is-open')) {
                closeDetailDrawer();
            }
        });

        // ============================================================
        // Back to top
        // ============================================================
        var scroller = document.querySelector('.app-main');
        if (scroller) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'back-to-top';
            btn.setAttribute('aria-label', 'Volver arriba');
            btn.innerHTML = '<i class="material-icons icon-20" aria-hidden="true">arrow_upward</i>';
            btn.addEventListener('click', function () {
                scroller.scrollTo({ top: 0, behavior: 'smooth' });
            });
            document.body.appendChild(btn);

            scroller.addEventListener('scroll', function () {
                btn.classList.toggle('is-visible', scroller.scrollTop > 600);
            }, { passive: true });
        }

        // ============================================================
        // Atajo Cmd/Ctrl + K
        // ============================================================
        document.addEventListener('keydown', function (e) {
            if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
                var search = document.querySelector('input[type="search"], input[name="q"], input[name="search"]');
                if (!search) { return; }
                e.preventDefault();
                search.focus();
                if (typeof search.select === 'function') { search.select(); }
            }
        });

        // ============================================================
        // Refresco parcial de secciones en vivo
        // ============================================================
        document.querySelectorAll('[data-live-section]').forEach(function (section) {
            var url = section.getAttribute('data-live-url') || window.location.pathname + window.location.search;
            var every = parseInt(section.getAttribute('data-live-interval') || '15000', 10);
            var paused = false;

            document.addEventListener('visibilitychange', function () {
                paused = document.hidden;
            });

            setInterval(function () {
                if (paused) { return; }
                fetch(url, {
                    headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-Partial': '1' },
                    credentials: 'same-origin'
                })
                    .then(function (r) { return r.text(); })
                    .then(function (html) {
                        var doc = new DOMParser().parseFromString(html, 'text/html');
                        var fresh = doc.querySelector('[data-live-section="' + section.getAttribute('data-live-section') + '"]');
                        if (fresh) { section.innerHTML = fresh.innerHTML; }
                    })
                    .catch(function () { /* se reintenta en el siguiente ciclo */ });
            }, Math.max(5000, every));
        });

    });
})();
