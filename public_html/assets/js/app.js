/**
 * app.js — Núcleo de la interfaz (tema, toasts, modales, AJAX).
 * Sistema visual: md/ESPECIFICACION-UI.md §3 y §7.1
 *
 * API pública:
 *   window.App.{init,currentTheme,applyTheme,setThemeCookie,toast,confirm,prompt,csrf}
 * Compatibilidad (no romper módulos existentes):
 *   api(), toast(), appConfirm(), appAlert(), getCsrfToken(),
 *   toggleTheme(), applyTheme(), downloadFile()
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'theme';
    var COOKIE_NAME = 'eiti_theme';

    var App = window.App = window.App || {};

    // ============================================================
    // Tema
    // ============================================================

    function storedTheme() {
        try { return localStorage.getItem(STORAGE_KEY) || 'auto'; } catch (e) { return 'auto'; }
    }

    function isDark(theme) {
        return theme === 'dark' ||
            (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    }

    App.currentTheme = function () {
        return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    };

    function paint() {
        var dark = document.documentElement.classList.contains('dark');
        var icon = dark ? 'light_mode' : 'dark_mode';
        var label = dark ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro';
        document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
            var i = btn.querySelector('.material-icons');
            if (i) { i.textContent = icon; }
            btn.setAttribute('aria-label', label);
            btn.setAttribute('title', label);
        });
    }

    App.setThemeCookie = function (theme) {
        var secure = window.location.protocol === 'https:' ? '; Secure' : '';
        document.cookie = COOKIE_NAME + '=' + theme + '; path=/; max-age=31536000; SameSite=Lax' + secure;
    };

    App.applyTheme = function (theme) {
        var dark = isDark(theme);
        var root = document.documentElement;
        root.classList.toggle('dark', dark);
        root.setAttribute('data-theme', dark ? 'dark' : 'light');
        // La cookie guarda el tema efectivo para que el servidor no parpadee.
        App.setThemeCookie(dark ? 'dark' : 'light');
        paint();
    };

    /** Ciclo claro -> oscuro -> auto -> claro (comportamiento histórico). */
    App.toggleTheme = function () {
        var order = ['light', 'dark', 'auto'];
        var next = order[(order.indexOf(storedTheme()) + 1) % order.length];
        try { localStorage.setItem(STORAGE_KEY, next); } catch (e) { /* sin persistencia */ }
        App.applyTheme(next);
        return next;
    };

    // Mantener el comportamiento del sistema en modo auto
    try {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
            if (storedTheme() === 'auto') { App.applyTheme('auto'); }
        });
    } catch (e) { /* navegador sin matchMedia moderno */ }

    // ============================================================
    // CSRF / AJAX
    // ============================================================

    App.csrf = function () {
        var meta = document.querySelector('meta[name="csrf-token"]');
        if (meta && meta.content) { return meta.content; }
        var input = document.querySelector('input[name="csrf_token"]');
        return input ? input.value : '';
    };

    App.api = function (method, url, data) {
        var options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': App.csrf()
            },
            credentials: 'same-origin'
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

    // ============================================================
    // Toasts
    // ============================================================

    var TOAST_ICONS = {
        success: 'check_circle',
        error: 'error',
        warning: 'warning',
        info: 'info'
    };

    function toastStack() {
        var stack = document.querySelector('.tdl-toast-stack');
        if (!stack) {
            stack = document.createElement('div');
            stack.className = 'tdl-toast-stack';
            stack.setAttribute('role', 'status');
            stack.setAttribute('aria-live', 'polite');
            document.body.appendChild(stack);
        }
        return stack;
    }

    App.toast = function (opts, legacyType) {
        var cfg = (typeof opts === 'string')
            ? { message: opts, type: legacyType || 'info' }
            : (opts || {});
        var type = cfg.type || 'info';
        var timeout = (cfg.timeout === 0) ? 0 : (cfg.timeout || 4000);

        var el = document.createElement('div');
        el.className = 'tdl-toast tdl-toast-' + type;

        var icon = document.createElement('i');
        icon.className = 'material-icons';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = TOAST_ICONS[type] || TOAST_ICONS.info;
        el.appendChild(icon);

        var body = document.createElement('div');
        body.className = 'tdl-toast-body';
        if (cfg.title) {
            var t = document.createElement('div');
            t.className = 'tdl-toast-title';
            t.textContent = cfg.title;
            body.appendChild(t);
        }
        var msg = document.createElement('div');
        msg.textContent = cfg.message || '';
        body.appendChild(msg);
        el.appendChild(body);

        function close() {
            if (!el.parentNode) { return; }
            el.classList.add('is-leaving');
            setTimeout(function () { if (el.parentNode) { el.parentNode.removeChild(el); } }, 200);
        }

        if (cfg.action && cfg.action.label) {
            var act = document.createElement('button');
            act.type = 'button';
            act.className = 'btn btn-small btn-flat';
            act.textContent = cfg.action.label;
            act.addEventListener('click', function () {
                if (typeof cfg.action.onClick === 'function') { cfg.action.onClick(); }
                close();
            });
            body.appendChild(act);
        }

        var x = document.createElement('button');
        x.type = 'button';
        x.className = 'tdl-toast-close';
        x.setAttribute('aria-label', 'Cerrar aviso');
        x.innerHTML = '<i class="material-icons icon-16" aria-hidden="true">close</i>';
        x.addEventListener('click', close);
        el.appendChild(x);

        toastStack().appendChild(el);
        if (timeout > 0) { setTimeout(close, timeout); }
        return el;
    };

    // ============================================================
    // Modales (confirm / alert / prompt)
    // ============================================================

    var dialogSeq = 0;

    var DIALOG_ICONS = {
        danger: 'delete_forever',
        info: 'info',
        warning: 'warning',
        question: 'help'
    };

    function buildDialog(kind, title) {
        var overlay = document.createElement('div');
        overlay.className = 'tdl-modal-overlay';

        var card = document.createElement('div');
        card.className = 'tdl-modal';
        card.setAttribute('role', 'dialog');
        card.setAttribute('aria-modal', 'true');

        var titleId = 'tdl-dialog-title-' + (++dialogSeq);
        card.setAttribute('aria-labelledby', titleId);

        var head = document.createElement('div');
        head.className = 'tdl-modal-head';
        head.innerHTML = '<i class="material-icons" aria-hidden="true">' +
            (DIALOG_ICONS[kind] || DIALOG_ICONS.info) + '</i>';

        var h = document.createElement('span');
        h.id = titleId;
        h.textContent = title || '';
        head.appendChild(h);

        var body = document.createElement('div');
        body.className = 'tdl-modal-body';

        var actions = document.createElement('div');
        actions.className = 'tdl-modal-actions';

        card.appendChild(head);
        card.appendChild(body);
        card.appendChild(actions);
        overlay.appendChild(card);

        return { overlay: overlay, card: card, body: body, actions: actions };
    }

    function mount(dialog, onKey, onOverlay) {
        document.body.appendChild(dialog.overlay);

        function keyHandler(e) { onKey(e); }
        function clickHandler(e) {
            if (e.target === dialog.overlay) { onOverlay(); }
        }
        dialog.overlay.addEventListener('click', clickHandler);
        document.addEventListener('keydown', keyHandler);

        return function unmount() {
            document.removeEventListener('keydown', keyHandler);
            dialog.overlay.removeEventListener('click', clickHandler);
            if (dialog.overlay.parentNode) { dialog.overlay.parentNode.removeChild(dialog.overlay); }
        };
    }

    function makeButton(label, className) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = className;
        b.textContent = label;
        return b;
    }

    App.confirm = function (opts) {
        opts = opts || {};
        var kind = opts.danger ? 'danger' : 'warning';
        return new Promise(function (resolve) {
            var d = buildDialog(kind, opts.title || 'Confirmar');
            d.body.textContent = opts.message || '';

            var cancel = makeButton(opts.cancelText || 'Cancelar', 'btn btn-outline');
            var ok = makeButton(opts.confirmText || 'Aceptar', opts.danger ? 'btn btn-danger' : 'btn');

            var unmount = mount(d, function (e) {
                if (e.key === 'Escape') { finish(false); }
                else if (e.key === 'Enter' && !opts.danger) { finish(true); }
            }, function () { finish(false); });

            function finish(val) { unmount(); resolve(val); }

            cancel.addEventListener('click', function () { finish(false); });
            ok.addEventListener('click', function () { finish(true); });

            d.actions.appendChild(cancel);
            d.actions.appendChild(ok);
            (opts.danger ? cancel : ok).focus();
        });
    };

    App.alert = function (opts) {
        opts = (typeof opts === 'string') ? { message: opts } : (opts || {});
        return new Promise(function (resolve) {
            var d = buildDialog('info', opts.title || 'Aviso');
            d.body.textContent = opts.message || '';

            var ok = makeButton(opts.confirmText || 'Aceptar', 'btn');
            var unmount = mount(d, function (e) {
                if (e.key === 'Escape' || e.key === 'Enter') { finish(); }
            }, finish);
            function finish() { unmount(); resolve(true); }

            ok.addEventListener('click', finish);
            d.actions.appendChild(ok);
            ok.focus();
        });
    };

    App.prompt = function (opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
            var d = buildDialog('question', opts.title || 'Introduce un valor');
            d.body.textContent = opts.message || '';

            var input = document.createElement('input');
            input.type = 'text';
            input.placeholder = opts.placeholder || '';
            input.value = opts.value || '';
            d.body.appendChild(input);

            var cancel = makeButton(opts.cancelText || 'Cancelar', 'btn btn-outline');
            var ok = makeButton(opts.confirmText || 'Aceptar', 'btn');

            var unmount = mount(d, function (e) {
                if (e.key === 'Escape') { finish(null); }
                else if (e.key === 'Enter') { finish(input.value); }
            }, function () { finish(null); });

            function finish(val) { unmount(); resolve(val); }

            cancel.addEventListener('click', function () { finish(null); });
            ok.addEventListener('click', function () { finish(input.value); });

            d.actions.appendChild(cancel);
            d.actions.appendChild(ok);
            input.focus();
            input.select();
        });
    };

    // ============================================================
    // Confirmación declarativa: data-confirm
    // ============================================================

    function confirmOptions(el) {
        return {
            title: el.getAttribute('data-confirm-title') || 'Confirmar',
            message: el.getAttribute('data-confirm') || '',
            confirmText: el.getAttribute('data-confirm-ok') || 'Aceptar',
            danger: el.hasAttribute('data-confirm-danger')
        };
    }

    // Formularios
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!form || form.nodeName !== 'FORM') { return; }
        var msg = form.getAttribute('data-confirm');
        if (!msg || form.dataset.confirmed === '1') { return; }
        e.preventDefault();
        App.confirm(confirmOptions(form)).then(function (ok) {
            if (!ok) { return; }
            form.dataset.confirmed = '1';
            if (typeof form.requestSubmit === 'function') { form.requestSubmit(); }
            else { form.submit(); }
        });
    }, true);

    // Enlaces y botones
    document.addEventListener('click', function (e) {
        var el = e.target.closest ? e.target.closest('[data-confirm]') : null;
        if (!el || el.nodeName === 'FORM') { return; }
        if (el.dataset.confirmed === '1') { return; }
        var isLink = el.nodeName === 'A' && el.getAttribute('href');
        var form = el.closest('form');
        if (!isLink && !form) { return; }
        e.preventDefault();
        App.confirm(confirmOptions(el)).then(function (ok) {
            if (!ok) { return; }
            el.dataset.confirmed = '1';
            if (isLink) {
                window.location.href = el.getAttribute('href');
            } else if (typeof form.requestSubmit === 'function') {
                form.requestSubmit();
            } else {
                form.submit();
            }
        });
    }, true);

    // ============================================================
    // Descarga de archivos
    // ============================================================

    App.downloadFile = function (content, filename, mimeType) {
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
    // Inicialización
    // ============================================================

    App.init = function () {
        App.applyTheme(storedTheme());

        // Auto-submit de formularios (comportamiento previo)
        document.querySelectorAll('form.auto-submit select, form.auto-submit input[type="checkbox"]')
            .forEach(function (el) {
                el.addEventListener('change', function () { el.closest('form').submit(); });
            });

        // Transición de tema solo tras el primer pintado
        window.requestAnimationFrame(function () {
            setTimeout(function () { document.documentElement.classList.add('transition-theme'); }, 0);
        });

        // Toggle de tema por delegación
        document.addEventListener('click', function (e) {
            var btn = e.target.closest ? e.target.closest('[data-theme-toggle]') : null;
            if (!btn) { return; }
            e.preventDefault();
            App.toggleTheme();
        });
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', App.init);
    } else {
        App.init();
    }

    // ============================================================
    // Alias globales (compatibilidad con los módulos)
    // ============================================================

    window.api = App.api;
    window.getCsrfToken = App.csrf;
    window.toast = App.toast;
    window.appConfirm = function (message, opts) {
        opts = opts || {};
        return App.confirm({
            title: opts.title || 'Confirmar',
            message: message,
            confirmText: opts.confirmText,
            cancelText: opts.cancelText,
            danger: !!opts.danger
        });
    };
    window.appAlert = function (message, opts) {
        return App.alert({ message: message, title: (opts || {}).title, confirmText: (opts || {}).confirmText });
    };
    window.appPrompt = App.prompt;
    window.applyTheme = App.applyTheme;
    window.toggleTheme = App.toggleTheme;
    window.downloadFile = App.downloadFile;

})();
