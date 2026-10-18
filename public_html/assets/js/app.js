/**
 * EntraID Threat Intelligence — JavaScript principal
 * Funciones globales de UI: tema, sidebar, menús, helpers AJAX.
 */

(function () {
    'use strict';

    // ============================================================
    // Tema (light / dark / auto)
    // ============================================================

    window.toggleTheme = function () {
        var themes = ['light', 'dark', 'auto'];
        var current = localStorage.getItem('theme') || 'auto';
        var next = themes[(themes.indexOf(current) + 1) % themes.length];
        localStorage.setItem('theme', next);
        applyTheme(next);
    };

    window.applyTheme = function (theme) {
        var isDark = theme === 'dark' ||
            (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
        document.documentElement.classList.toggle('dark', isDark);
        updateThemeIcon(theme);
    };

    function updateThemeIcon(theme) {
        var sun = document.getElementById('theme-icon-sun');
        var moon = document.getElementById('theme-icon-moon');
        if (!sun || !moon) return;
        var isDark = document.documentElement.classList.contains('dark');
        sun.classList.toggle('hidden', !isDark);
        moon.classList.toggle('hidden', isDark);
    }

    // Reaccionar a cambios del SO en modo auto
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
        var theme = localStorage.getItem('theme') || 'auto';
        if (theme === 'auto') applyTheme('auto');
    });

    // ============================================================
    // Sidebar móvil
    // ============================================================

    window.toggleSidebar = function () {
        var sidebar = document.getElementById('sidebar');
        var overlay = document.getElementById('sidebar-overlay');
        if (!sidebar) return;
        var isOpen = !sidebar.classList.contains('-translate-x-full');
        sidebar.classList.toggle('-translate-x-full', isOpen);
        if (overlay) overlay.classList.toggle('hidden', isOpen);
    };

    // ============================================================
    // Menú de usuario
    // ============================================================

    window.toggleUserMenu = function () {
        var menu = document.getElementById('user-menu');
        if (menu) menu.classList.toggle('hidden');
    };

    // Cerrar menú al hacer click fuera
    document.addEventListener('click', function (e) {
        var menu = document.getElementById('user-menu');
        if (menu && !menu.classList.contains('hidden') && !menu.contains(e.target) && !e.target.closest('button[onclick="toggleUserMenu()"]')) {
            menu.classList.add('hidden');
        }
    });

    // ============================================================
    // Helper AJAX
    // ============================================================

    window.api = function (method, url, data) {
        var options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': getCsrfToken(),
            },
            credentials: 'same-origin',
        };
        if (data && method !== 'GET') {
            options.body = JSON.stringify(data);
        }
        return fetch(url, options).then(function (res) {
            if (res.status === 401) {
                window.location.href = (window.APP_URL || '') + '/admin/login';
                throw new Error('No autorizado');
            }
            return res.text().then(function (text) {
                var payload;
                try {
                    payload = text ? JSON.parse(text) : {};
                } catch (e) {
                    var snippet = (text || '').replace(/\s+/g, ' ').trim().slice(0, 200);
                    var err = new Error('HTTP ' + res.status + (snippet ? ' · ' + snippet : ''));
                    err.httpStatus = res.status;
                    err.body = text || '';
                    throw err;
                }
                return payload;
            });
        });
    };

    window.getCsrfToken = function () {
        var input = document.querySelector('input[name="csrf_token"]');
        return input ? input.value : '';
    };

    // ============================================================
    // Descarga de archivos (para exportaciones)
    // ============================================================

    window.downloadFile = function (content, filename, mimeType) {
        var blob = new Blob([content], { type: mimeType || 'text/plain' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        setTimeout(function () {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
    };

    // ============================================================
    // Notificaciones toast simples
    // ============================================================

    window.toast = function (message, type) {
        type = type || 'info';
        var colors = {
            success: 'bg-green-500',
            error: 'bg-red-500',
            warning: 'bg-amber-500',
            info: 'bg-blue-500',
        };
        var el = document.createElement('div');
        el.className = 'fixed bottom-4 right-4 z-50 px-4 py-3 rounded-lg text-white text-sm shadow-lg transition-opacity ' + (colors[type] || colors.info);
        el.textContent = message;
        document.body.appendChild(el);
        setTimeout(function () {
            el.style.opacity = '0';
            setTimeout(function () { el.remove(); }, 300);
        }, 4000);
    };

    // ============================================================
    // Inicializar tema al cargar
    // ============================================================

    var savedTheme = localStorage.getItem('theme') || 'auto';
    applyTheme(savedTheme);

    // ============================================================
    // Auto-submit de formularios con clase .auto-submit
    // ============================================================

    document.querySelectorAll('form.auto-submit select, form.auto-submit input[type="checkbox"]').forEach(function (el) {
        el.addEventListener('change', function () {
            el.closest('form').submit();
        });
    });

    // ============================================================
    // Diálogos propios (sustituyen confirm()/alert() nativos)
    // ============================================================

    function _escapeHtml(s) {
        var d = document.createElement('div');
        d.textContent = (s == null) ? '' : s;
        return d.innerHTML;
    }

    function _buildDialog(title) {
        var overlay = document.createElement('div');
        overlay.className = 'fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/50';
        var card = document.createElement('div');
        card.className = 'w-full max-w-md bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 shadow-xl p-5';
        card.setAttribute('role', 'dialog');
        card.setAttribute('aria-modal', 'true');

        var h = document.createElement('h3');
        h.className = 'text-base font-semibold mb-2';
        h.textContent = title || '';
        var p = document.createElement('p');
        p.className = 'text-sm text-gray-600 dark:text-gray-300 whitespace-pre-wrap';
        p.textContent = '';
        var actions = document.createElement('div');
        actions.className = 'mt-5 flex justify-end gap-2';

        card.appendChild(h);
        card.appendChild(p);
        card.appendChild(actions);
        overlay.appendChild(card);
        return { overlay: overlay, message: p, actions: actions };
    }

    function _showDialog(dialog) {
        document.body.appendChild(dialog.overlay);
    }
    function _hideDialog(dialog) {
        if (dialog.overlay.parentNode) {
            dialog.overlay.parentNode.removeChild(dialog.overlay);
        }
    }

    window.appAlert = function (message, opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
            var d = _buildDialog(opts.title || 'Aviso');
            d.message.textContent = message || '';
            var ok = document.createElement('button');
            ok.type = 'button';
            ok.className = 'px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors';
            ok.textContent = opts.confirmText || 'Aceptar';
            var onKey = function (e) { if (e.key === 'Escape' || e.key === 'Enter') close(); };
            function close() { _hideDialog(d); document.removeEventListener('keydown', onKey); resolve(true); }
            ok.onclick = close;
            d.actions.appendChild(ok);
            _showDialog(d);
            document.addEventListener('keydown', onKey);
            ok.focus();
        });
    };

    window.appConfirm = function (message, opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
            var d = _buildDialog(opts.title || 'Confirmar');
            d.message.textContent = message || '';

            var cancel = document.createElement('button');
            cancel.type = 'button';
            cancel.className = 'px-4 py-2 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors';
            cancel.textContent = opts.cancelText || 'Cancelar';

            var ok = document.createElement('button');
            ok.type = 'button';
            ok.className = 'px-4 py-2 ' + (opts.danger ? 'bg-red-600 hover:bg-red-700' : 'bg-brand-500 hover:bg-brand-600') + ' text-white text-sm font-medium rounded-lg transition-colors';
            ok.textContent = opts.confirmText || 'Aceptar';

            function onKey(e) { if (e.key === 'Escape') close(false); }
            function close(val) { _hideDialog(d); document.removeEventListener('keydown', onKey); resolve(val); }

            cancel.onclick = function () { close(false); };
            ok.onclick = function () { close(true); };
            d.overlay.addEventListener('click', function (e) { if (e.target === d.overlay) close(false); });
            document.addEventListener('keydown', onKey);

            d.actions.appendChild(cancel);
            d.actions.appendChild(ok);
            _showDialog(d);
            ok.focus();
        });
    };

    // Formularios con data-confirm="mensaje" (sustituye onsubmit="return confirm(...)")
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!form || form.nodeName !== 'FORM') { return; }
        var msg = form.getAttribute('data-confirm');
        if (!msg || form.dataset.confirmed === '1') { return; }
        e.preventDefault();
        window.appConfirm(msg, { danger: form.hasAttribute('data-confirm-danger') }).then(function (ok) {
            if (ok) {
                form.dataset.confirmed = '1';
                form.submit();
            }
        });
    }, true);

})();
