/**
 * perf.js — Core Web Vitals mínimos (LCP e INP) sin dependencias.
 * v0.4.28.16 — Modern Web Guidance, Fase 2.
 *
 * Expone window.EitiVitals y emite `eiti:vitals` en document con:
 *   { lcp, lcpElement, inp, interactions, lcpSupported, inpSupported, updatedAt }
 *
 * No envía nada a la red por defecto. Para reportar, el <body> debe llevar
 * `data-vitals-endpoint="/ruta"`; entonces se hace un sendBeacon al salir.
 * Con `?vitals=1` se pinta un panel de depuración (no se imprime).
 */
(function () {
    'use strict';

    var state = {
        lcp: 0,
        lcpElement: '',
        inp: 0,
        interactions: 0,
        lcpSupported: false,
        inpSupported: false,
        updatedAt: 0
    };

    function copy() {
        return {
            lcp: state.lcp,
            lcpElement: state.lcpElement,
            inp: state.inp,
            interactions: state.interactions,
            lcpSupported: state.lcpSupported,
            inpSupported: state.inpSupported,
            updatedAt: state.updatedAt
        };
    }

    function publish() {
        state.updatedAt = Date.now();
        window.EitiVitals = copy();
        try {
            document.dispatchEvent(new CustomEvent('eiti:vitals', { detail: window.EitiVitals }));
        } catch (err) { /* CustomEvent no disponible */ }
    }

    window.EitiVitals = copy();

    // --- LCP ---------------------------------------------------------------
    try {
        var lcpObserver = new PerformanceObserver(function (list) {
            var entries = list.getEntries();
            var last = entries[entries.length - 1];
            if (!last || last.startTime <= state.lcp) { return; }
            state.lcp = Math.round(last.startTime);
            var el = last.element;
            if (el && el.tagName) {
                var cls = typeof el.className === 'string' ? el.className : '';
                state.lcpElement = el.tagName.toLowerCase()
                    + (cls ? '.' + cls.split(/\s+/).slice(0, 2).join('.') : '');
            }
            state.lcpSupported = true;
            publish();
        });
        lcpObserver.observe({ type: 'largest-contentful-paint', buffered: true });
        state.lcpSupported = true;
    } catch (err) { /* navegador sin PerformanceObserver o sin LCP */ }

    // --- INP (aproximación: mayor duración de evento con interactionId) -----
    try {
        var inpObserver = new PerformanceObserver(function (list) {
            var entries = list.getEntries();
            for (var i = 0; i < entries.length; i++) {
                var entry = entries[i];
                if (!entry.interactionId) { continue; }
                state.interactions++;
                if (entry.duration > state.inp) {
                    state.inp = Math.round(entry.duration);
                    publish();
                }
            }
        });
        inpObserver.observe({ type: 'event', durationThreshold: 16, buffered: true });
        state.inpSupported = true;
    } catch (err) { /* navegador sin el buffer de eventos */ }

    // --- Panel opcional (?vitals=1) ----------------------------------------
    var showPanel = false;
    try {
        showPanel = new URLSearchParams(window.location.search).get('vitals') === '1';
    } catch (err) { /* URLSearchParams no disponible */ }
    if (showPanel) {
        var panel = document.createElement('div');
        panel.setAttribute('data-eiti-vitals', '1');
        panel.className = 'no-print';
        panel.style.cssText = 'position:fixed;bottom:8px;left:8px;z-index:10060;'
            + 'padding:8px 10px;border-radius:8px;background:#111827;color:#f9fafb;'
            + 'font:11px/1.4 monospace;box-shadow:0 8px 24px rgba(0,0,0,.3);pointer-events:none';
        document.body.appendChild(panel);

        function renderPanel(v) {
            panel.textContent = 'LCP ' + (v.lcp ? v.lcp + ' ms' : 'n/d')
                + ' · INP ' + (v.inp ? v.inp + ' ms' : 'n/d')
                + ' · eventos ' + v.interactions;
        }
        renderPanel(window.EitiVitals);
        document.addEventListener('eiti:vitals', function (e) { renderPanel(e.detail); });
    }

    // --- Reporte opcional (opt-in) -----------------------------------------
    var endpoint = document.body ? document.body.getAttribute('data-vitals-endpoint') : null;
    if (endpoint && navigator.sendBeacon && window.Blob) {
        var sent = false;
        function sendVitals() {
            if (sent) { return; }
            sent = true;
            try {
                navigator.sendBeacon(endpoint,
                    new Blob([JSON.stringify(copy())], { type: 'application/json' }));
            } catch (err) { /* beacon rechazado */ }
        }
        window.addEventListener('pagehide', sendVitals);
        document.addEventListener('visibilitychange', function () {
            if (document.visibilityState === 'hidden') { sendVitals(); }
        });
    }
})();
