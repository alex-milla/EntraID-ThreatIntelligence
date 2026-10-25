/**
 * shell.js — Comportamientos del shell: drawer lateral, submenús y menú de usuario.
 * Sistema visual: md/ESPECIFICACION-UI.md §5
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
        var shell = document.querySelector('.app-shell');
        if (!shell) { return; }

        var menuBtn = shell.querySelector('[data-shell-menu]');
        var overlay = shell.querySelector('[data-shell-overlay]');
        var sidebar = shell.querySelector('.app-sidebar');

        // ------------------------------------------------------------
        // Drawer lateral (< lg)
        // ------------------------------------------------------------
        function drawerOpen() {
            return shell.classList.contains('drawer-open');
        }

        function setDrawer(open, restoreFocus) {
            shell.classList.toggle('drawer-open', open);
            if (overlay) { overlay.hidden = !open; }
            if (menuBtn) { menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false'); }
            document.body.classList.toggle('overflow-hidden', open);

            if (!open && restoreFocus && menuBtn) { menuBtn.focus(); }

            if (open && sidebar) {
                var first = sidebar.querySelector('.sidebar-link, .sidebar-sublink, a, button');
                if (first) {
                    setTimeout(function () { first.focus(); }, 60);
                }
            }
        }

        if (menuBtn) {
            menuBtn.addEventListener('click', function (e) {
                e.preventDefault();
                setDrawer(!drawerOpen(), false);
            });
        }

        if (overlay) {
            overlay.addEventListener('click', function () { setDrawer(false, true); });
        }

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && drawerOpen()) {
                setDrawer(false, true);
            }
        });

        // Cualquier navegación dentro del drawer lo cierra
        if (sidebar) {
            sidebar.addEventListener('click', function (e) {
                var link = e.target.closest ? e.target.closest('a[href]') : null;
                if (link && window.matchMedia('(max-width: 1023.98px)').matches) {
                    setDrawer(false, false);
                }
            });
        }

        // Si se pasa a escritorio, el drawer deja de aplicar
        window.matchMedia('(min-width: 1024px)').addEventListener('change', function (mq) {
            if (mq.matches && drawerOpen()) { setDrawer(false, false); }
        });

        // ------------------------------------------------------------
        // Submenús del sidebar
        // ------------------------------------------------------------
        shell.querySelectorAll('[data-submenu-toggle]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var group = btn.closest('.sidebar-subgroup');
                if (!group) { return; }
                var open = group.classList.toggle('is-open');
                btn.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
        });

        // ------------------------------------------------------------
        // Menú de usuario (disclosure)
        // ------------------------------------------------------------
        var userButton = shell.querySelector('[data-user-menu-toggle]');
        var userPanel = shell.querySelector('#account-dropdown');

        function setUserMenu(open, restoreFocus) {
            if (!userButton || !userPanel) { return; }
            userPanel.hidden = !open;
            userButton.setAttribute('aria-expanded', open ? 'true' : 'false');
            if (!open && restoreFocus) { userButton.focus(); }
        }

        if (userButton && userPanel) {
            userButton.addEventListener('click', function (e) {
                e.preventDefault();
                e.stopPropagation();
                setUserMenu(userPanel.hidden, false);
            });

            document.addEventListener('click', function (e) {
                if (userPanel.hidden) { return; }
                if (userPanel.contains(e.target) || userButton.contains(e.target)) { return; }
                setUserMenu(false, false);
            });

            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && !userPanel.hidden) {
                    setUserMenu(false, true);
                }
            });

            userPanel.addEventListener('click', function (e) {
                if (e.target.closest('a[href]')) { setUserMenu(false, false); }
            });
        }

        // ------------------------------------------------------------
        // Compatibilidad con el markup anterior
        // ------------------------------------------------------------
        window.toggleSidebar = function () { setDrawer(!drawerOpen(), false); };
        window.toggleUserMenu = function () {
            if (userPanel) { setUserMenu(userPanel.hidden, false); }
        };
    });
})();
