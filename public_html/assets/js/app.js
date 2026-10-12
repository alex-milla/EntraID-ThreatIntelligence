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
            return res.json();
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

})();
