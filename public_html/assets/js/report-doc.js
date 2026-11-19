/**
 * report-doc.js — Copia y exportación de documentos con su aspecto de pantalla.
 *
 * Convierte el DOM de un informe (.report-doc, .doc-sheet) en HTML con estilos
 * en línea para pegarlo en Word o en un correo sin perder colores, badges,
 * bordes ni tablas. Los layouts CSS Grid/Flex se reescriben como tablas porque
 * Word y Outlook no los implementan.
 *
 * Uso:
 *   ReportDoc.copyRich('mi-documento', { markdown: '...' });
 *   ReportDoc.copyPlain('mi-documento');
 *   ReportDoc.downloadHtml('mi-documento', 'informe.html', 'Informe');
 *   ReportDoc.downloadMarkdown('informe.md', markdown);
 */
(function () {
    'use strict';

    var HTML_NS = 'http://www.w3.org/1999/xhtml';

    /* Propiedades que se copian del estilo calculado al inline. */
    var PROPS = [
        'color',
        'background-color',
        'font-family',
        'font-size',
        'font-weight',
        'font-style',
        'line-height',
        'letter-spacing',
        'text-align',
        'text-transform',
        'text-decoration-line',
        'white-space',
        'vertical-align',
        'list-style-type',
        'list-style-position',
        'padding-top',
        'padding-right',
        'padding-bottom',
        'padding-left',
        'margin-top',
        'margin-right',
        'margin-bottom',
        'margin-left',
        'border-top-width',
        'border-top-style',
        'border-top-color',
        'border-right-width',
        'border-right-style',
        'border-right-color',
        'border-bottom-width',
        'border-bottom-style',
        'border-bottom-color',
        'border-left-width',
        'border-left-style',
        'border-left-color',
        'border-top-left-radius',
        'border-top-right-radius',
        'border-bottom-right-radius',
        'border-bottom-left-radius'
    ];

    /* Tamaños: solo para las barras de progreso. Copiar el ancho calculado de
     * un bloque en píxeles dejaría el documento rígido en Word. */
    var BOX_PROPS = ['width', 'height', 'min-width', 'max-width'];

    /* Propiedades heredadas: si valen lo mismo que en el padre no se repiten. */
    var INHERITED = {
        'color': 1,
        'font-family': 1,
        'font-size': 1,
        'font-weight': 1,
        'font-style': 1,
        'line-height': 1,
        'letter-spacing': 1,
        'text-align': 1,
        'text-transform': 1,
        'white-space': 1,
        'list-style-type': 1,
        'list-style-position': 1
    };

    var BORDER_GROUPS = ['top', 'right', 'bottom', 'left'];

    var PADDING_PROPS = ['padding-top', 'padding-right', 'padding-bottom', 'padding-left'];

    var RADIUS_PROPS = [
        'border-top-left-radius',
        'border-top-right-radius',
        'border-bottom-right-radius',
        'border-bottom-left-radius'
    ];

    /* Contenedores del informe CVE que deben viajar como tabla. */
    var TABLE_LAYOUTS = [
        ['.report-summary', 0],
        ['.report-cve dl', 0],
        ['.report-exposure > .grid', 0],
        ['.report-ai > .grid', 2],
        ['.report-cve > .grid', 2]
    ];

    var PURGE_SELECTOR = [
        '.no-print',
        '.print-hide',
        '.print-url',
        'details',
        'script',
        'style',
        'input',
        'button',
        'select',
        'textarea',
        'noscript'
    ].join(',');

    function notify(message, type) {
        if (typeof window.toast === 'function') {
            window.toast(message, type || 'success');
        }
    }

    function sheet(rootId) {
        if (!rootId) {
            return null;
        }
        if (typeof rootId === 'string') {
            return document.getElementById(rootId);
        }
        return rootId;
    }

    /* Ejecuta fn con el tema claro aplicado, para que los estilos calculados
     * no arrastren el modo oscuro a Word o al correo. No hay parpadeo: la
     * lectura es síncrona y el navegador no repinta hasta terminar. */
    function withLightTheme(fn) {
        var root = document.documentElement;
        var hadDark = root.classList.contains('dark');
        var previousTheme = root.getAttribute('data-theme');
        if (hadDark) {
            root.classList.remove('dark');
            root.setAttribute('data-theme', 'light');
        }
        try {
            return fn();
        } finally {
            if (hadDark) {
                root.classList.add('dark');
            }
            if (previousTheme !== null) {
                root.setAttribute('data-theme', previousTheme);
            } else if (hadDark) {
                root.setAttribute('data-theme', 'dark');
            }
        }
    }

    function isZero(value) {
        return value === '' || value === '0px' || value === '0' || value === 'auto' || value === 'normal' || value === 'none';
    }

    /* Copia el estilo calculado del original al clon, sin pisar lo que ya
     * venga declarado en el atributo style (dossiers y planes del servidor). */
    function inlineStyles(source, clone) {
        var sourceNodes = [source].concat(Array.prototype.slice.call(source.querySelectorAll('*')));
        var cloneNodes = [clone].concat(Array.prototype.slice.call(clone.querySelectorAll('*')));
        var total = Math.min(sourceNodes.length, cloneNodes.length);

        for (var i = 0; i < total; i++) {
            var src = sourceNodes[i];
            var dst = cloneNodes[i];
            if (!dst || dst.nodeType !== 1) {
                continue;
            }

            var cs = window.getComputedStyle(src);
            var display = cs.display || '';
            if (display === 'flex' || display === 'grid' || display === 'inline-flex' || display === 'inline-grid') {
                dst.setAttribute('data-rd-layout', display);
            }

            var parentCs = i > 0 && src.parentElement ? window.getComputedStyle(src.parentElement) : null;

            var copyBox = src.tagName === 'IMG'
                || (src.classList && src.classList.contains('report-meter'));

            var props = copyBox ? PROPS.concat(BOX_PROPS) : PROPS;

            for (var p = 0; p < props.length; p++) {
                var prop = props[p];

                if (dst.style.getPropertyValue(prop)) {
                    continue;
                }

                var value = cs.getPropertyValue(prop);
                if (value === '') {
                    continue;
                }

                if (INHERITED[prop] && parentCs && value === parentCs.getPropertyValue(prop)) {
                    continue;
                }

                /* Padding a cero no aporta nada y engorda el HTML. */
                if (PADDING_PROPS.indexOf(prop) !== -1 && isZero(value)) {
                    continue;
                }

                if (RADIUS_PROPS.indexOf(prop) !== -1 && isZero(value)) {
                    continue;
                }

                if (prop.indexOf('border-') === 0) {
                    var side = prop.split('-')[1];
                    var style = cs.getPropertyValue('border-' + side + '-style');
                    if (style === 'none' || style === 'hidden') {
                        continue;
                    }
                }

                dst.style.setProperty(prop, value);
            }
        }
    }

    function purge(clone) {
        Array.prototype.slice.call(clone.querySelectorAll(PURGE_SELECTOR)).forEach(function (node) {
            if (node.parentNode) {
                node.parentNode.removeChild(node);
            }
        });
    }

    function tableStyle(extra) {
        var style = 'width:100%;border-collapse:collapse;margin:0;';
        if (extra) {
            style += String(extra)
                .replace(/display\s*:\s*[^;]+;?/gi, '')
                .replace(/width\s*:\s*[^;]+;?/gi, '');
        }
        return style;
    }

    function hasLooseText(el) {
        return Array.prototype.some.call(el.childNodes, function (node) {
            return node.nodeType === 3 && (node.textContent || '').trim() !== '';
        });
    }

    function toTable(el, columns) {
        if (!el.parentNode || !el.children.length || hasLooseText(el)) {
            return false;
        }

        var children = Array.prototype.slice.call(el.children);
        var perRow = columns > 0 ? columns : children.length;
        if (perRow < 1) {
            return false;
        }

        var table = document.createElement('table');
        table.setAttribute('style', tableStyle(el.getAttribute('style')));
        table.setAttribute('cellspacing', '0');
        table.setAttribute('cellpadding', '0');

        var tbody = document.createElement('tbody');
        var row = null;
        var inRow = 0;

        children.forEach(function (child) {
            if (!row || inRow >= perRow) {
                row = document.createElement('tr');
                tbody.appendChild(row);
                inRow = 0;
            }
            var cell = document.createElement('td');
            cell.setAttribute('style', 'vertical-align:top;border:0;padding:0;width:'
                + Math.floor(100 / perRow) + '%;');
            cell.appendChild(child);
            row.appendChild(cell);
            inRow++;
        });

        table.appendChild(tbody);
        el.parentNode.replaceChild(table, el);
        return true;
    }

    /* Convierte los layouts conocidos y, después, cualquier flex/grid que
     * quede: filas de badges en línea y grupos de bloques como tabla. */
    function normalizeLayout(clone) {
        TABLE_LAYOUTS.forEach(function (entry) {
            Array.prototype.slice.call(clone.querySelectorAll(entry[0])).forEach(function (el) {
                el.removeAttribute('data-rd-layout');
                toTable(el, entry[1]);
            });
        });

        Array.prototype.slice.call(clone.querySelectorAll('[data-rd-layout]')).forEach(function (el) {
            var display = el.getAttribute('data-rd-layout') || '';
            el.removeAttribute('data-rd-layout');

            if (display === 'inline-flex' || display === 'inline-grid') {
                el.style.setProperty('display', 'inline-block');
                Array.prototype.slice.call(el.children).forEach(function (child) {
                    child.style.removeProperty('display');
                });
                return;
            }

            var children = Array.prototype.slice.call(el.children);
            if (!children.length) {
                el.style.setProperty('display', 'block');
                return;
            }

            var allInline = children.every(function (child) {
                var tag = (child.tagName || '').toLowerCase();
                return tag === 'a' || tag === 'span' || tag === 'em' || tag === 'strong' || tag === 'b' || tag === 'i';
            });

            /* Texto suelto (títulos con numeración) o badges: flujo en línea. */
            if (allInline || hasLooseText(el)) {
                el.style.setProperty('display', 'block');
                children.forEach(function (child) {
                    child.style.setProperty('display', 'inline-block');
                });
                return;
            }

            if (!toTable(el, children.length === 2 ? 2 : 0)) {
                el.style.setProperty('display', 'block');
            }
        });
    }

    function buildExport(rootId) {
        var source = sheet(rootId);
        if (!source) {
            return null;
        }

        var clone = source.cloneNode(true);

        withLightTheme(function () {
            inlineStyles(source, clone);
        });

        purge(clone);
        normalizeLayout(clone);

        return {
            html: clone.innerHTML,
            text: source.innerText || source.textContent || ''
        };
    }

    /* HTML autocontenido listo para abrir en Word. */
    function buildDocument(rootId, title) {
        var built = buildExport(rootId);
        if (!built) {
            return '';
        }
        var safeTitle = String(title || 'Informe')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        return '<!DOCTYPE html>'
            + '<html xmlns="' + HTML_NS + '" lang="es">'
            + '<head>'
            + '<meta charset="utf-8">'
            + '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
            + '<title>' + safeTitle + '</title>'
            + '<!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View>'
            + '<w:Zoom>100</w:Zoom></w:WordDocument></xml><![endif]-->'
            + '<style>'
            + '@page { size: A4; margin: 16mm 14mm 18mm; }'
            + 'body { font-family: "Segoe UI", Arial, sans-serif; color: #0f172a;'
            + ' font-size: 11pt; line-height: 1.45; margin: 0; }'
            + 'table { page-break-inside: auto; }'
            + 'tr { page-break-inside: avoid; }'
            + '</style>'
            + '</head>'
            + '<body>' + built.html + '</body>'
            + '</html>';
    }

    function saveFile(name, content, type) {
        var blob = new Blob([content], { type: type });
        var url = URL.createObjectURL(blob);
        var link = document.createElement('a');
        link.href = url;
        link.download = name;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
    }

    function legacyCopyRich(html) {
        var holder = document.createElement('div');
        holder.contentEditable = 'true';
        holder.innerHTML = html;
        holder.style.position = 'fixed';
        holder.style.left = '-9999px';
        holder.style.top = '0';
        holder.style.whiteSpace = 'pre-wrap';
        document.body.appendChild(holder);

        var range = document.createRange();
        range.selectNodeContents(holder);
        var selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);

        var ok = false;
        try {
            ok = document.execCommand('copy');
        } catch (err) {
            ok = false;
        }

        selection.removeAllRanges();
        document.body.removeChild(holder);
        return ok;
    }

    function writeRich(html, text) {
        if (navigator.clipboard && window.ClipboardItem && window.isSecureContext) {
            try {
                return navigator.clipboard.write([new ClipboardItem({
                    'text/html': new Blob([html], { type: 'text/html' }),
                    'text/plain': new Blob([text], { type: 'text/plain' })
                })]);
            } catch (err) {
                /* continúa con el método heredado */
            }
        }
        if (legacyCopyRich(html)) {
            return Promise.resolve();
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text);
        }
        return Promise.reject(new Error('El navegador no permite escribir en el portapapeles.'));
    }

    var ReportDoc = window.ReportDoc = window.ReportDoc || {};

    ReportDoc.build = buildExport;

    ReportDoc.copyRich = function (rootId, options) {
        var opts = options || {};
        var built = buildExport(rootId);
        if (!built) {
            notify('No hay documento que copiar.', 'error');
            return Promise.resolve(false);
        }
        var plain = opts.markdown ? String(opts.markdown) : built.text;

        return writeRich(built.html, plain).then(function () {
            notify(opts.message || 'Documento copiado con formato. Pégalo en Word o en tu correo.', 'success');
            return true;
        }).catch(function () {
            notify('No se pudo copiar con formato. Usa «Descargar .html».', 'error');
            return false;
        });
    };

    ReportDoc.copyPlain = function (rootId, options) {
        var opts = options || {};
        var built = buildExport(rootId);
        if (!built) {
            notify('No hay documento que copiar.', 'error');
            return Promise.resolve(false);
        }
        var text = opts.markdown ? String(opts.markdown) : built.text;

        function done() {
            notify(opts.message || 'Texto copiado.', 'success');
            return true;
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text).then(done).catch(function () {
                notify('No se pudo copiar el texto.', 'error');
                return false;
            });
        }

        var area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        var ok = false;
        try {
            ok = document.execCommand('copy');
        } catch (err) {
            ok = false;
        }
        document.body.removeChild(area);
        if (ok) {
            return Promise.resolve(done());
        }
        notify('No se pudo copiar el texto.', 'error');
        return Promise.resolve(false);
    };

    ReportDoc.downloadHtml = function (rootId, filename, title) {
        var html = buildDocument(rootId, title);
        if (!html) {
            notify('No hay documento que exportar.', 'error');
            return;
        }
        saveFile(filename || 'informe.html', html, 'text/html;charset=utf-8');
        notify('Documento descargado. Ábrelo en Word y guárdalo como .docx.', 'success');
    };

    ReportDoc.downloadMarkdown = function (filename, markdown) {
        var text = String(markdown || '');
        if (text === '') {
            notify('No hay documento que exportar.', 'error');
            return;
        }
        saveFile(filename || 'informe.md', text, 'text/markdown;charset=utf-8');
        notify('Markdown descargado.', 'success');
    };

    /* Delegación: los botones declaran su acción y su documento.
     *
     *   <button data-rd-action="copy-rich" data-rd-target="mi-doc"
     *           data-rd-md="mi-doc-md" data-rd-filename="informe.html"
     *           data-rd-title="Informe">Copiar</button>
     */
    function markdownFor(button) {
        var mdId = button.getAttribute('data-rd-md');
        if (!mdId) {
            return '';
        }
        var node = document.getElementById(mdId);
        return node ? (node.textContent || '') : '';
    }

    document.addEventListener('click', function (ev) {
        var button = ev.target && ev.target.closest ? ev.target.closest('[data-rd-action]') : null;
        if (!button) {
            return;
        }

        var action = button.getAttribute('data-rd-action');
        var target = button.getAttribute('data-rd-target');
        if (!target) {
            return;
        }
        ev.preventDefault();

        var markdown = markdownFor(button);
        var filename = button.getAttribute('data-rd-filename') || 'informe';
        var title = button.getAttribute('data-rd-title') || 'Informe';

        if (action === 'copy-rich') {
            ReportDoc.copyRich(target, { markdown: markdown });
        } else if (action === 'copy-plain') {
            ReportDoc.copyPlain(target, { markdown: markdown, message: 'Texto copiado.' });
        } else if (action === 'download-html') {
            ReportDoc.downloadHtml(target, filename, title);
        } else if (action === 'download-md') {
            ReportDoc.downloadMarkdown(filename, markdown);
        }
    });
})();
