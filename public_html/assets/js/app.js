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

    var _dialogSeq = 0;

    if (!document.getElementById('ui-dialog-style')) {
        var _dialogStyle = document.createElement('style');
        _dialogStyle.id = 'ui-dialog-style';
        _dialogStyle.textContent = '@keyframes uiDialogIn{from{opacity:0;transform:translateY(6px) scale(.98)}to{opacity:1;transform:none}}';
        document.head.appendChild(_dialogStyle);
    }

    function _dialogIcon(kind) {
        if (kind === 'danger') {
            return '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>';
        }
        if (kind === 'info') {
            return '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
        }
        return '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>';
    }

    function _buildDialog(title, kind) {
        var overlay = document.createElement('div');
        overlay.className = 'fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm';

        var card = document.createElement('div');
        card.className = 'w-full max-w-md bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 shadow-2xl';
        card.style.animation = 'uiDialogIn .16s ease-out';
        card.setAttribute('role', 'dialog');
        card.setAttribute('aria-modal', 'true');

        var titleId = 'ui-dialog-title-' + (++_dialogSeq);
        card.setAttribute('aria-labelledby', titleId);

        var header = document.createElement('div');
        header.className = 'flex items-start gap-3 px-5 pt-5';

        var iconWrap = document.createElement('div');
        iconWrap.className = 'w-9 h-9 rounded-full flex items-center justify-center shrink-0 ' + (
            kind === 'danger'
                ? 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400'
                : (kind === 'info'
                    ? 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400'
                    : 'bg-amber-100 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400')
        );
        iconWrap.innerHTML = _dialogIcon(kind);

        var h = document.createElement('h3');
        h.id = titleId;
        h.className = 'text-base font-semibold leading-6 pt-1';
        h.textContent = title || '';

        header.appendChild(iconWrap);
        header.appendChild(h);

        var p = document.createElement('p');
        p.className = 'text-sm text-gray-600 dark:text-gray-300 whitespace-pre-wrap px-5 mt-3';

        var footer = document.createElement('div');
        footer.className = 'mt-5 px-5 py-4 bg-gray-50 dark:bg-gray-800/40 border-t border-gray-100 dark:border-gray-700 flex justify-end gap-2 rounded-b-xl';

        card.appendChild(header);
        card.appendChild(p);
        card.appendChild(footer);
        overlay.appendChild(card);
        return { overlay: overlay, message: p, actions: footer };
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
            var d = _buildDialog(opts.title || 'Aviso', 'info');
            d.message.textContent = message || '';

            var ok = document.createElement('button');
            ok.type = 'button';
            ok.className = 'px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors';
            ok.textContent = opts.confirmText || 'Aceptar';

            function onKey(e) { if (e.key === 'Escape' || e.key === 'Enter') close(); }
            function close() { _hideDialog(d); document.removeEventListener('keydown', onKey); resolve(true); }

            ok.onclick = close;
            d.overlay.addEventListener('click', function (e) { if (e.target === d.overlay) close(); });
            d.actions.appendChild(ok);
            _showDialog(d);
            document.addEventListener('keydown', onKey);
            ok.focus();
        });
    };

    window.appConfirm = function (message, opts) {
        opts = opts || {};
        var kind = opts.danger ? 'danger' : 'warning';
        return new Promise(function (resolve) {
            var d = _buildDialog(opts.title || 'Confirmar', kind);
            d.message.textContent = message || '';

            var cancel = document.createElement('button');
            cancel.type = 'button';
            cancel.className = 'px-4 py-2 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors';
            cancel.textContent = opts.cancelText || 'Cancelar';

            var ok = document.createElement('button');
            ok.type = 'button';
            ok.className = 'px-4 py-2 ' + (opts.danger ? 'bg-red-600 hover:bg-red-700' : 'bg-brand-500 hover:bg-brand-600') + ' text-white text-sm font-medium rounded-lg transition-colors';
            ok.textContent = opts.confirmText || 'Aceptar';

            function onKey(e) {
                if (e.key === 'Escape') {
                    close(false);
                } else if (e.key === 'Enter' && !opts.danger) {
                    close(true);
                }
            }
            function close(val) { _hideDialog(d); document.removeEventListener('keydown', onKey); resolve(val); }

            cancel.onclick = function () { close(false); };
            ok.onclick = function () { close(true); };
            d.overlay.addEventListener('click', function (e) { if (e.target === d.overlay) close(false); });
            document.addEventListener('keydown', onKey);

            d.actions.appendChild(cancel);
            d.actions.appendChild(ok);
            _showDialog(d);
            // En acciones destructivas el foco va a Cancelar para evitar Enter accidental.
            (opts.danger ? cancel : ok).focus();
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
