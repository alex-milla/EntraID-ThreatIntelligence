/**
 * Asistente de extracción y exportación de IOCs.
 * Expone window.IOCExtractor.open(opts) para abrirlo desde cualquier botón.
 */
(function () {
    'use strict';

    var modal = document.getElementById('iocz-modal');
    if (!modal) { return; }

    var BASE = modal.getAttribute('data-base') || '';
    var S = {
        source: 'u42', articleIds: [], articleId: 0, filters: {},
        iocs: [], stats: null, format: 'stix', category: 'all', results: null
    };

    function $(id) { return document.getElementById(id); }
    function esc(v) {
        return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
        });
    }
    function notify(msg, type) {
        if (typeof toast === 'function') { toast(msg, type || 'info'); }
        else if (type === 'error' && typeof appAlert === 'function') { appAlert(msg); }
    }
    function setError(msg) {
        var el = $('iocz-error');
        if (el) { el.textContent = msg || ''; }
    }

    function go(step) {
        for (var i = 1; i <= 4; i++) {
            var sec = $('iocz-step-' + i);
            var nav = $('iocz-nav-' + i);
            if (sec) { sec.classList.toggle('hidden', i !== step); }
            if (nav) {
                var active = i === step;
                nav.className = 'px-2 py-0.5 rounded-full text-[10px] font-medium '
                    + (active ? 'bg-brand-500 text-white' : 'bg-muted text-ink-muted');
            }
        }
        modal.scrollTop = 0;
    }

    function setSource(source) {
        S.source = source;
        var sel = $('iocz-source');
        if (sel) { sel.value = source; }
        ['u42', 'tenant', 'text'].forEach(function (name) {
            var el = $('iocz-src-' + name);
            if (el) { el.classList.toggle('hidden', name !== source); }
        });
        var save = document.querySelector('#iocz-step-3 button[onclick="IOCExtractor.saveCorrections()"]');
        if (save) { save.classList.toggle('hidden', source !== 'u42'); }
        setError('');
    }

    function open(opts) {
        opts = opts || {};
        S.source = opts.source || 'u42';
        S.articleIds = (opts.articleIds || []).map(function (x) { return parseInt(x, 10) || 0; }).filter(function (x) { return x > 0; });
        S.articleId = S.articleIds[0] || parseInt(opts.articleId || 0, 10) || 0;
        S.filters = opts.filters || {};
        S.iocs = []; S.stats = null; S.results = null; S.category = 'all';
        S.format = opts.format || 'stix';

        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        setSource(S.source);

        if (S.source === 'u42' && S.articleIds.length) {
            var label = $('iocz-selected-label');
            if (label) { label.textContent = S.articleIds.length + ' publicación(es) preparadas desde la ficha.'; }
        }
        var fmt = $('iocz-cfg-format');
        if (fmt) { fmt.value = 'split'; }
        var results = $('iocz-results');
        if (results) { results.innerHTML = ''; }
        go(1);
    }

    function close() {
        modal.classList.add('hidden');
        document.body.style.overflow = '';
    }

    function searchArticles() {
        var q = ($('iocz-article-q') || {}).value || '';
        setError('');
        if (typeof api !== 'function') { setError('Falta el helper api().'); return; }
        api('GET', BASE + '/u42-articles?q=' + encodeURIComponent(q), null).then(function (res) {
            if (!res || !res.success) { setError((res && res.error) || 'No se pudo buscar.'); return; }
            renderArticles(res.articles || []);
        }).catch(function (e) { setError(e.message || 'Error de red'); });
    }

    function renderArticles(articles) {
        var box = $('iocz-article-list');
        if (!box) { return; }
        if (!articles.length) {
            box.innerHTML = '<p class="p-3 text-xs text-ink-muted">No hay publicaciones que coincidan.</p>';
            return;
        }
        box.innerHTML = articles.map(function (a) {
            var checked = S.articleIds.indexOf(parseInt(a.id, 10)) >= 0;
            return '<label class="flex items-start gap-2 px-3 py-2 cursor-pointer hover:bg-muted/50">'
                + '<input type="checkbox" class="iocz-article mt-0.5" value="' + esc(a.id) + '"' + (checked ? ' checked' : '') + '>'
                + '<span class="min-w-0"><span class="block text-xs font-medium break-words">' + esc(a.title) + '</span>'
                + '<span class="block text-[10px] text-ink-muted">' + esc(a.published_at || '') + ' · ' + esc(a.path || '') + '</span></span></label>';
        }).join('');
    }

    function syncArticleIds() {
        S.articleIds = Array.prototype.slice.call(document.querySelectorAll('.iocz-article:checked'))
            .map(function (el) { return parseInt(el.value, 10) || 0; })
            .filter(function (id) { return id > 0; });
        S.articleId = S.articleIds[0] || 0;
        var label = $('iocz-selected-label');
        if (label) { label.textContent = S.articleIds.length + ' publicación(es) seleccionada(s)'; }
    }

    function extract() {
        setError('');
        var payload = {source: S.source};
        if (S.source === 'u42') {
            syncArticleIds();
            if (!S.articleIds.length) { setError('Selecciona al menos una publicación.'); return; }
            payload.article_ids = S.articleIds;
        } else if (S.source === 'tenant') {
            payload.tenant_id = S.filters.tenant_id || parseInt(($('export-tenant') || {}).value || '0', 10) || 0;
            payload.filters = S.filters;
        } else {
            payload.text = ($('iocz-text') || {}).value || '';
        }
        var btn = $('iocz-extract');
        if (btn) { btn.disabled = true; btn.textContent = 'Extrayendo…'; }
        api('POST', BASE + '/extract', payload).then(function (res) {
            if (btn) { btn.disabled = false; btn.textContent = 'Extraer IOCs'; }
            if (!res || !res.success) { setError((res && res.error) || 'No se pudo extraer.'); return; }
            S.iocs = (res.iocs || []).map(function (ioc, i) {
                return {
                    index: i, id: parseInt(ioc.id || 0, 10), type: ioc.type || 'domain-name',
                    value: ioc.value || '', description: ioc.description || '', source: ioc.source || ''
                };
            });
            S.stats = res.stats || null;
            renderStats();
            renderTable();
            go(2);
        }).catch(function (e) {
            if (btn) { btn.disabled = false; btn.textContent = 'Extraer IOCs'; }
            setError(e.message || 'Error de red');
        });
    }

    function renderStats() {
        var box = $('iocz-stats');
        if (!box) { return; }
        var st = S.stats || {};
        var cat = st.categories || {};
        var cards = [
            ['Total', st.total], ['Únicos', st.unique], ['Duplicados', st.duplicates],
            ['IPs', cat.ip], ['Dominios', cat.domain], ['URLs', cat.url],
            ['Hashes', cat.hash], ['Emails', cat.email], ['Otros', cat.other]
        ];
        box.innerHTML = cards.map(function (c) {
            return '<div class="rounded-lg border border-line px-2 py-1.5">'
                + '<div class="text-[10px] text-ink-muted">' + esc(c[0]) + '</div>'
                + '<div class="text-sm font-semibold">' + esc(c[1] == null ? 0 : c[1]) + '</div></div>';
        }).join('');
    }

    var TYPES = ['ipv4-addr', 'ipv6-addr', 'domain-name', 'url', 'file', 'email-addr',
        'user-account', 'windows-registry-key', 'mac-addr', 'autonomous-system'];
    var LABELS = {
        all: 'Todos', ip: 'IPs', domain: 'Dominios', url: 'URLs',
        hash: 'Hashes', email: 'Emails', other: 'Otros'
    };

    function categoryOf(type) {
        if (type === 'ipv4-addr' || type === 'ipv6-addr') { return 'ip'; }
        if (type === 'domain-name') { return 'domain'; }
        if (type === 'url') { return 'url'; }
        if (type === 'file') { return 'hash'; }
        if (type === 'email-addr' || type === 'user-account') { return 'email'; }
        return 'other';
    }

    function visibleIocs() {
        if (S.category === 'all') { return S.iocs; }
        return S.iocs.filter(function (ioc) { return categoryOf(ioc.type) === S.category; });
    }

    function renderTabs() {
        var tabs = $('iocz-tabs');
        if (!tabs) { return; }
        var counts = {};
        S.iocs.forEach(function (ioc) {
            var c = categoryOf(ioc.type);
            counts[c] = (counts[c] || 0) + 1;
        });
        var keys = ['all', 'ip', 'domain', 'url', 'hash', 'email', 'other'];
        tabs.innerHTML = keys.map(function (key) {
            var n = key === 'all' ? S.iocs.length : (counts[key] || 0);
            var active = key === S.category;
            return '<button type="button" data-iocz-cat="' + key + '" '
                + 'class="px-2 py-0.5 rounded-full text-[10px] font-medium ' + (active ? 'bg-brand-500 text-white' : 'bg-muted text-ink-muted') + '">'
                + LABELS[key] + ' (' + n + ')</button>';
        }).join('');
    }

    function renderTable() {
        renderTabs();
        var body = $('iocz-tbody');
        if (!body) { return; }
        var list = visibleIocs();
        if (!list.length) {
            body.innerHTML = '<tr><td colspan="5" class="px-2 py-4 text-center text-ink-muted">No hay IOCs en este filtro.</td></tr>';
            return;
        }
        body.innerHTML = list.map(function (ioc) {
            var i = ioc.index;
            return '<tr data-iocz-row="' + i + '">'
                + '<td class="px-2 py-1 text-ink-soft">' + (i + 1) + '</td>'
                + '<td class="px-2 py-1"><select data-iocz-field="type" class="px-1 py-0.5 rounded border border-line-strong bg-input text-ink text-[11px]">'
                + TYPES.map(function (t) {
                    return '<option value="' + t + '"' + (t === ioc.type ? ' selected' : '') + '>' + t + '</option>';
                }).join('') + '</select></td>'
                + '<td class="px-2 py-1 mono break-all">' + esc(ioc.value) + '</td>'
                + '<td class="px-2 py-1"><input type="text" data-iocz-field="description" value="' + esc(ioc.description) + '" '
                + 'class="w-full px-1 py-0.5 rounded border border-line-strong bg-input text-ink text-[11px]"></td>'
                + '<td class="px-2 py-1 whitespace-nowrap">'
                + '<button type="button" data-iocz-action="copy" class="text-[10px] text-brand-600 hover:underline">Copiar</button> '
                + '<button type="button" data-iocz-action="delete" class="text-[10px] text-danger hover:underline">Eliminar</button></td>'
                + '</tr>';
        }).join('');
    }

    function applyBulkDesc() {
        var text = ($('iocz-bulk-desc') || {}).value || '';
        if (!text.trim()) { notify('Escribe una descripción.', 'warning'); return; }
        var onlyEmpty = ($('iocz-bulk-empty') || {}).checked;
        var scope = ($('iocz-bulk-scope') || {}).value || 'all';
        var targets = scope === 'filtered' ? visibleIocs() : S.iocs;
        var n = 0;
        targets.forEach(function (ioc) {
            if (onlyEmpty && ioc.description && ioc.description.trim()) { return; }
            ioc.description = text.trim();
            n++;
        });
        renderTable();
        notify('Descripción aplicada a ' + n + ' indicador(es).', 'success');
    }

    function saveCorrections() {
        if (S.source !== 'u42') { return; }
        if (!S.articleId) { notify('Falta la publicación de origen.', 'warning'); return; }
        var changes = S.iocs.map(function (ioc) {
            return {id: ioc.id, type: ioc.type, value: ioc.value, description: ioc.description};
        });
        api('POST', BASE + '/iocs/save', {article_id: S.articleId, changes: changes}).then(function (res) {
            notify(res && res.success ? 'Correcciones guardadas (' + res.saved + ').' : 'No se pudieron guardar.', res && res.success ? 'success' : 'error');
        }).catch(function (e) { notify(e.message || 'Error de red', 'error'); });
    }

    function copyValues() {
        var text = S.iocs.map(function (i) { return i.value; }).join('\n');
        if (!text) { return; }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () { notify('IOCs copiados.', 'success'); })
                .catch(function () { legacyCopy(text); });
        } else { legacyCopy(text); }
    }
    function legacyCopy(text) {
        var ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); notify('IOCs copiados.', 'success'); } catch (e) { notify('No se pudo copiar.', 'error'); }
        document.body.removeChild(ta);
    }

    function toExport(format) {
        S.format = format;
        var fmt = $('iocz-cfg-format');
        if (fmt) { fmt.value = 'split'; }
        go(4);
    }

    function config() {
        return {
            format: ($('iocz-cfg-format') || {}).value || 'split',
            source: ($('iocz-cfg-source') || {}).value || 'EntraID TI',
            threat_actor: ($('iocz-cfg-actor') || {}).value || '',
            labels: (($('iocz-cfg-tags') || {}).value || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean),
            indicator_type: ($('iocz-cfg-indicator') || {}).value || 'malicious-activity',
            confidence: parseInt(($('iocz-cfg-confidence') || {}).value || '75', 10),
            tlp: ($('iocz-cfg-tlp') || {}).value || 'green',
            valid_days: parseInt(($('iocz-cfg-days') || {}).value || '365', 10),
            ip_direction: ($('iocz-cfg-ipdir') || {}).value || 'ip-dst',
            info: (($('iocz-cfg-source') || {}).value || 'EntraID TI') + ' - IOC Export'
        };
    }

    function generate() {
        if (!S.iocs.length) { notify('No hay IOCs para exportar.', 'warning'); return; }
        var msg = $('iocz-generate-msg');
        var btn = $('iocz-generate');
        if (btn) { btn.disabled = true; btn.textContent = 'Generando…'; }
        if (msg) { msg.textContent = ''; }
        var results = $('iocz-results');
        if (results) { results.innerHTML = ''; }

        api('POST', BASE + '/generate', {format: S.format, iocs: S.iocs, config: config()}).then(function (res) {
            if (btn) { btn.disabled = false; btn.textContent = 'Generar ficheros'; }
            if (!res || !res.success) {
                if (msg) { msg.textContent = (res && res.error) || 'No se pudo generar.'; }
                return;
            }
            S.results = res;
            renderResults(res);
        }).catch(function (e) {
            if (btn) { btn.disabled = false; btn.textContent = 'Generar ficheros'; }
            if (msg) { msg.textContent = e.message || 'Error de red'; }
        });
    }

    function quickExport(format) {
        S.format = format;
        var fmt = $('iocz-cfg-format');
        if (fmt) { fmt.value = 'split'; }
        go(4);
        generate();
    }

    function renderResults(res) {
        var box = $('iocz-results');
        if (!box) { return; }
        var files = res.files || {};
        var keys = Object.keys(files);
        if (!keys.length && res.content) {
            keys = ['all'];
            files = {all: {content: res.content, filename: res.filename || 'iocs.json', mime: res.mime || 'application/json'}};
        }
        if (!keys.length) {
            box.innerHTML = '<p class="text-xs text-ink-muted">No se generaron ficheros.</p>';
            return;
        }
        var html = '<div class="rounded-lg border border-green-300 bg-green-50 dark:bg-green-900/20 p-3">'
            + '<p class="text-xs font-semibold text-green-700 dark:text-green-300">'
            + esc(res.count || 0) + ' indicador(es) · ' + keys.length + ' fichero(s) listo(s). '
            + 'Descarga los que necesites.</p></div>';
        keys.forEach(function (key) {
            var f = files[key] || {};
            var bytes = f.content ? new Blob([f.content]).size : 0;
            html += '<div class="flex items-center justify-between gap-3 rounded-lg border border-line px-3 py-2">'
                + '<div class="min-w-0"><p class="text-xs font-medium break-all">' + esc(f.filename || key) + '</p>'
                + '<p class="text-[10px] text-ink-muted">' + bytes + ' bytes · ' + esc(f.mime || '') + '</p></div>'
                + '<div class="flex items-center gap-2 shrink-0">'
                + '<button type="button" data-iocz-file="' + esc(key) + '" class="px-2 py-1 text-[11px] border border-line-strong rounded-lg hover:bg-muted">Copiar</button>'
                + '<button type="button" data-iocz-download="' + esc(key) + '" class="px-2 py-1 text-[11px] bg-brand-500 hover:bg-brand-600 text-white rounded-lg">Descargar</button>'
                + '</div></div>';
        });
        box.innerHTML = html;
    }

    function fileByKey(key) {
        if (!S.results) { return null; }
        var files = S.results.files || {};
        if (files[key]) { return files[key]; }
        if (key === 'all' && S.results.content) {
            return {content: S.results.content, filename: S.results.filename || 'iocs.json', mime: S.results.mime || 'application/json'};
        }
        return null;
    }

    document.addEventListener('change', function (ev) {
        var t = ev.target;
        if (!t) { return; }
        if (t.id === 'iocz-source') { setSource(t.value); return; }
        if (t.classList && t.classList.contains('iocz-article')) { syncArticleIds(); return; }
        if (t.getAttribute && t.getAttribute('data-iocz-field')) {
            var row = t.closest('[data-iocz-row]');
            if (!row) { return; }
            var ioc = S.iocs[parseInt(row.getAttribute('data-iocz-row'), 10)];
            if (!ioc) { return; }
            ioc[t.getAttribute('data-iocz-field')] = t.value;
            if (t.getAttribute('data-iocz-field') === 'type') { renderTabs(); }
        }
    });

    document.addEventListener('click', function (ev) {
        var t = ev.target && ev.target.closest ? ev.target : null;
        if (!t) { return; }
        var tab = t.closest('[data-iocz-cat]');
        if (tab) { S.category = tab.getAttribute('data-iocz-cat'); renderTable(); return; }
        var action = t.closest('[data-iocz-action]');
        if (action) {
            var row = action.closest('[data-iocz-row]');
            if (!row) { return; }
            var idx = parseInt(row.getAttribute('data-iocz-row'), 10);
            if (action.getAttribute('data-iocz-action') === 'delete') {
                S.iocs.splice(idx, 1);
                S.iocs.forEach(function (ioc, i) { ioc.index = i; });
                renderStats(); renderTable();
            } else {
                legacyCopy(S.iocs[idx] ? S.iocs[idx].value : '');
            }
            return;
        }
        var dl = t.closest('[data-iocz-download]');
        if (dl) {
            var f = fileByKey(dl.getAttribute('data-iocz-download'));
            if (f && typeof downloadFile === 'function') { downloadFile(f.content, f.filename, f.mime); }
            return;
        }
        var cp = t.closest('[data-iocz-file]');
        if (cp) {
            var ff = fileByKey(cp.getAttribute('data-iocz-file'));
            if (ff) { legacyCopy(ff.content); }
        }
    });

    if ($('iocz-article-q')) {
        $('iocz-article-q').addEventListener('keydown', function (ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); searchArticles(); }
        });
    }

    window.IOCExtractor = {
        open: open, close: close, go: go, setSource: setSource,
        searchArticles: searchArticles, extract: extract,
        copyValues: copyValues, quickExport: quickExport,
        applyBulkDesc: applyBulkDesc, saveCorrections: saveCorrections,
        toExport: toExport, generate: generate
    };
})();
