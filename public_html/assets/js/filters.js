/**
 * filters.js — Filtros en drawer por debajo de `lg`.
 * Sistema visual: md/ESPECIFICACION-UI.md §6.8
 *
 * El formulario sigue visible si este script no se carga (degradación segura):
 * solo se convierte en drawer cuando hay `.filter-form` y la ventana es < lg.
 */
(function () {
    'use strict';

    var MQ = '(max-width: 1023.98px)';

    function ready(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    ready(function () {
        var forms = document.querySelectorAll('.filter-form');
        if (!forms.length) { return; }

        var mql = window.matchMedia(MQ);

        forms.forEach(function (form, index) {
            if (form.dataset.filterReady === '1') { return; }
            form.dataset.filterReady = '1';

            var id = form.id || ('filter-form-' + index);
            form.id = id;

            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'filter-toggle btn btn-outline';
            btn.setAttribute('aria-controls', id);
            btn.setAttribute('aria-expanded', 'false');
            btn.innerHTML = '<i class="material-icons icon-16" aria-hidden="true">filter_list</i> Filtros';

            var overlay = document.createElement('div');
            overlay.className = 'filter-overlay';
            overlay.hidden = true;

            form.parentNode.insertBefore(btn, form);
            form.parentNode.insertBefore(overlay, form);

            function isOpen() { return form.classList.contains('is-open'); }

            function open() {
                form.classList.add('is-open');
                overlay.hidden = false;
                btn.setAttribute('aria-expanded', 'true');
                document.body.classList.add('overflow-hidden');
                var first = form.querySelector('input:not([type="hidden"]), select, textarea');
                if (first) { setTimeout(function () { first.focus(); }, 60); }
            }

            function close(restoreFocus) {
                form.classList.remove('is-open');
                overlay.hidden = true;
                btn.setAttribute('aria-expanded', 'false');
                document.body.classList.remove('overflow-hidden');
                if (restoreFocus) { btn.focus(); }
            }

            btn.addEventListener('click', function () {
                if (isOpen()) { close(true); } else { open(); }
            });

            overlay.addEventListener('click', function () { close(true); });

            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && isOpen()) { close(true); }
            });

            function syncMode() {
                if (!mql.matches) {
                    close(false);
                    btn.hidden = true;
                } else {
                    btn.hidden = false;
                }
            }

            mql.addEventListener('change', syncMode);
            syncMode();

            // Al enviar, el drawer se cierra (la página se recarga con el filtro)
            form.addEventListener('submit', function () { close(false); });
        });
    });
})();
