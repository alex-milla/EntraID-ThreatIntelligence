/**
 * report-doc.js — Copia y exportación de documentos con su aspecto de pantalla.
 *
 * Convierte el DOM de un informe (.report-doc, .doc-sheet) en HTML con estilos
 * en línea para pegarlo en Word o en un correo sin perder colores, badges,
 * bordes ni recuadros.
 *
 * El documento exportado va SIEMPRE en una columna (la pantalla conserva sus
 * columnas): Word y Outlook no implementan CSS Grid/Flex. El servidor marca
 * cada contenedor con `data-rd-stack`:
 *   - "metrics": cada métrica en una línea «Etiqueta: valor» (+ su barra).
 *   - "blocks":  los hijos se apilan uno debajo del otro.
 *   - "inline":  chips y badges se quedan en una línea.
 * Las tablas de datos no se tocan.
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

    var PURGE_SELECTOR = [
        '[data-rd-drop]',
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

            var copyBox = src.tagName === 'IMG';

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

    /* ------------------------------------------------------------------
     * Layout: el documento exportado va SIEMPRE en una columna.
     * El marcado del servidor decide qué es una tira de métricas, qué se
     * apila y qué se queda en línea (chips y badges).
     * ------------------------------------------------------------------ */

    function elChildren(el) {
        return Array.prototype.slice.call(el.children || []);
    }

    function textOf(el) {
        return (el.textContent || '').replace(/\s+/g, ' ').trim();
    }

    function hasLooseText(el) {
        return Array.prototype.some.call(el.childNodes, function (node) {
            return node.nodeType === 3 && (node.textContent || '').trim() !== '';
        });
    }

    function replaceNode(node, nodes) {
        if (!node.parentNode) {
            return;
        }
        var frag = document.createDocumentFragment();
        nodes.forEach(function (child) {
            frag.appendChild(child);
        });
        node.parentNode.replaceChild(frag, node);
    }

    /* ¿La parte es texto simple? (no es un bloque de contenido) */
    function isPlainPart(el) {
        if (!el) {
            return false;
        }
        return !el.querySelector('ul,ol,table,dl,pre,section,article,div');
    }

    /* Una celda de métrica: etiqueta + valor, ambos texto plano. */
    function isMetricCell(cell) {
        var texts = elChildren(cell).filter(function (child) {
            return textOf(child) !== '';
        });
        if (texts.length !== 2) {
            return false;
        }
        var label = texts[0];
        var value = texts[1];
        if (!isPlainPart(label) || !isPlainPart(value)) {
            return false;
        }
        if (textOf(label).length > 40) {
            return false;
        }
        var tag = (label.tagName || '').toLowerCase();
        var transform = (label.style.getPropertyValue('text-transform') || '').toLowerCase();
        var labelSize = parseFloat(label.style.getPropertyValue('font-size') || '0');
        var valueSize = parseFloat(value.style.getPropertyValue('font-size') || '0');
        if (tag === 'dt' || transform === 'uppercase') {
            return true;
        }
        return labelSize > 0 && valueSize > 0 && labelSize < valueSize;
    }

    /* Estilo en línea reutilizable dentro de una línea de texto.
     *
     * No se emite `display` ni `vertical-align`: el valor por defecto de un
     * `<span>` ya es en línea, y el importador de Word descarta lo que va
     * detrás de un `display`. Las sustituciones van al final para que el color
     * sea la última declaración. */
    function cleanInlineStyle(el, maxFontPx, overrides) {
        var over = overrides || {};
        var parts = [];
        var seen = {};
        var declarations = (el.getAttribute('style') || '').split(';');

        declarations.forEach(function (declaration) {
            var idx = declaration.indexOf(':');
            if (idx < 0) {
                return;
            }
            var prop = declaration.slice(0, idx).trim().toLowerCase();
            var value = declaration.slice(idx + 1).trim();
            if (prop === '' || value === '') {
                return;
            }
            if (prop === 'display' || prop === 'vertical-align'
                || prop.indexOf('margin') === 0 || prop.indexOf('width') === 0
                || prop === 'height') {
                return;
            }
            if (seen[prop] || Object.prototype.hasOwnProperty.call(over, prop)) {
                return;
            }
            if (prop === 'font-size' && maxFontPx > 0) {
                var px = parseFloat(value);
                if (!isNaN(px) && px > maxFontPx) {
                    value = maxFontPx + 'px';
                }
            }
            seen[prop] = true;
            parts.push(prop + ':' + value);
        });

        /* El color siempre el último: es lo que Word no debe perder. */
        var keys = Object.keys(over).filter(function (prop) {
            return prop !== 'color';
        });
        if (Object.prototype.hasOwnProperty.call(over, 'color')) {
            keys.push('color');
        }
        keys.forEach(function (prop) {
            parts.push(prop + ':' + over[prop]);
        });

        return parts.join(';') + ';';
    }

    /* Valor de un atributo en el propio elemento o en su contenido (la cifra
     * del EPSS vive en un span dentro del dd). */
    function attrFrom(el, name) {
        if (!el || !el.getAttribute) {
            return '';
        }
        var own = el.getAttribute(name);
        if (own) {
            return own;
        }
        if (el.querySelector) {
            var found = el.querySelector('[' + name + ']');
            if (found) {
                return found.getAttribute(name) || '';
            }
        }
        return '';
    }

    /* Celda de métrica → «Etiqueta: valor» con la cifra en su color. */
    function metricLine(cell) {
        var texts = elChildren(cell).filter(function (child) {
            return textOf(child) !== '';
        });
        if (texts.length < 2) {
            return null;
        }

        var labelEl = texts[0];
        var valueEl = texts[1];
        var block = document.createElement('div');
        block.setAttribute('style', 'display:block;margin:0 0 8px;');

        var line = document.createElement('p');
        line.setAttribute('style', 'margin:0;line-height:1.35;');

        var label = document.createElement('span');
        label.setAttribute('style', cleanInlineStyle(labelEl));
        /* Word ignora text-transform: las mayúsculas se aplican al texto. */
        var labelText = textOf(labelEl);
        var transform = (labelEl.style.getPropertyValue('text-transform') || '').toLowerCase();
        if (transform === 'uppercase') {
            labelText = labelText.toUpperCase();
        }
        label.textContent = labelText + ':\u00A0';
        line.appendChild(label);

        var value = document.createElement('span');
        /* Si el valor es una única insignia (KEV «Sí/No»), se conserva su
         * color de fondo y su borde en lugar del estilo del contenedor. */
        var styleSource = valueEl;
        if (valueEl.children.length === 1 && textOf(valueEl) === textOf(valueEl.children[0])) {
            styleSource = valueEl.children[0];
        }

        /* Cuando la cifra lleva tono, el color se pone al final y una sola vez:
         * Word descarta lo que va detrás de un `display`. */
        var overrides = {};
        var tone = attrFrom(valueEl, 'data-rd-color');
        if (tone) {
            overrides.color = tone;
            overrides['font-weight'] = '700';
        }

        var valueStyle = cleanInlineStyle(styleSource, 18, overrides);
        value.setAttribute('style', valueStyle);
        value.textContent = textOf(valueEl);
        line.appendChild(value);

        /* Nivel en texto: el color se pierde en una impresión en blanco y negro. */
        var level = attrFrom(valueEl, 'data-rd-level');
        if (level) {
            var hint = document.createElement('span');
            var labelColor = labelEl.style.getPropertyValue('color') || '#6b7280';
            hint.setAttribute('style', 'color:' + labelColor + ';font-weight:400;');
            hint.textContent = ' (' + level + ')';
            line.appendChild(hint);
        }

        block.appendChild(line);
        return block;
    }

    function stackBlocks(container) {
        container.style.setProperty('display', 'block');
        container.style.removeProperty('gap');

        var kids = elChildren(container);
        kids.forEach(function (child, index) {
            var tag = (child.tagName || '').toLowerCase();
            if (tag !== 'table') {
                child.style.setProperty('display', 'block');
            }
            var marginBottom = parseFloat(child.style.getPropertyValue('margin-bottom') || '0');
            if (index < kids.length - 1 && !(marginBottom > 0)) {
                child.style.setProperty('margin-bottom', '10px');
            }
        });
    }

    /* Número dentro de un círculo (bg oscuro + texto blanco). En Word el fondo
     * puede caerse y quedaría blanco sobre blanco: se exporta como «1.». */
    function isNumberBadge(el) {
        if (!/^\d{1,2}$/.test(textOf(el))) {
            return false;
        }
        if ((el.style.getPropertyValue('background-color') || '') === '') {
            return false;
        }
        var radius = (el.style.getPropertyValue('border-top-left-radius') || '').trim();
        var px = parseFloat(radius);
        return radius === '50%' || (!isNaN(px) && px >= 20);
    }

    /* Pone un espacio real entre dos hijos en línea (Word ignora los márgenes). */
    function insertSpaceAfter(node) {
        var next = node.nextSibling;
        if (!next || next.nodeType !== 1) {
            return;
        }
        var space = document.createTextNode(' ');
        node.parentNode.insertBefore(space, next);
    }

    /* Chips y badges: se quedan en una línea, con espacio real entre ellos.
     * `display:inline` es lo que hace que Word pinte el fondo como resaltado
     * ajustado al texto; con `inline-block` lo convierte en banda de párrafo. */
    function inlineChildren(container) {
        container.style.setProperty('display', 'block');
        elChildren(container).forEach(function (child) {
            var tag = (child.tagName || '').toLowerCase();
            if (tag === 'table' || tag === 'ul' || tag === 'ol' || tag === 'div' || tag === 'p' || /^h[1-6]$/.test(tag)) {
                return;
            }
            if (isNumberBadge(child)) {
                var number = document.createElement('span');
                number.setAttribute('style', 'font-weight:700;color:#0f172a;');
                number.textContent = textOf(child) + '.';
                child.parentNode.replaceChild(number, child);
                insertSpaceAfter(number);
                return;
            }
            child.style.setProperty('display', 'inline');
            insertSpaceAfter(child);
        });
    }

    /* Bordes por lado (ya inlinados) listos para una celda de Word. */
    function borderShorthand(el) {
        var out = [];
        ['top', 'right', 'bottom', 'left'].forEach(function (side) {
            var width = el.style.getPropertyValue('border-' + side + '-width') || '';
            var style = (el.style.getPropertyValue('border-' + side + '-style') || '').trim();
            var color = el.style.getPropertyValue('border-' + side + '-color') || '';
            var px = parseFloat(width);
            if (px > 0 && style !== '' && style !== 'none' && style !== 'hidden') {
                out.push('border-' + side + ':' + width + ' ' + style + ' ' + color);
            }
        });
        return out;
    }

    /* Una tarjeta con caja → tabla de una celda. Word solo pinta bordes y
     * fondos en celdas de tabla, no en `div`. */
    function cardToTable(card) {
        if (!card.parentNode) {
            return;
        }

        var tableStyle = ['width:100%', 'border-collapse:collapse'].concat(borderShorthand(card));
        ['top', 'right', 'bottom', 'left'].forEach(function (side) {
            var margin = card.style.getPropertyValue('margin-' + side);
            if (margin) {
                tableStyle.push('margin-' + side + ':' + margin);
            }
        });
        var background = card.style.getPropertyValue('background-color');
        if (background && background !== 'transparent' && background !== 'rgba(0, 0, 0, 0)') {
            tableStyle.push('background-color:' + background);
        }

        var cellStyle = ['vertical-align:top', 'border:0'];
        ['top', 'right', 'bottom', 'left'].forEach(function (side) {
            var padding = card.style.getPropertyValue('padding-' + side);
            if (padding) {
                cellStyle.push('padding-' + side + ':' + padding);
            }
        });

        var table = document.createElement('table');
        table.setAttribute('cellspacing', '0');
        table.setAttribute('cellpadding', '0');
        table.setAttribute('style', tableStyle.join(';') + ';');

        var tbody = document.createElement('tbody');
        var row = document.createElement('tr');
        var cell = document.createElement('td');
        cell.setAttribute('style', cellStyle.join(';') + ';');

        while (card.firstChild) {
            cell.appendChild(card.firstChild);
        }

        row.appendChild(cell);
        tbody.appendChild(row);
        table.appendChild(tbody);
        card.parentNode.replaceChild(table, card);
    }

    function applyMetrics(container) {
        var lines = [];

        if ((container.tagName || '').toLowerCase() === 'table') {
            Array.prototype.forEach.call(container.rows, function (row) {
                Array.prototype.slice.call(row.cells).forEach(function (cell) {
                    var line = metricLine(cell);
                    if (line) {
                        lines.push(line);
                    } else if (textOf(cell) !== '') {
                        var block = document.createElement('div');
                        block.setAttribute('style', 'display:block;margin:0 0 8px;');
                        while (cell.firstChild) {
                            block.appendChild(cell.firstChild);
                        }
                        lines.push(block);
                    }
                });
            });
        } else {
            elChildren(container).forEach(function (cell) {
                var line = metricLine(cell);
                if (line) {
                    lines.push(line);
                }
            });
        }

        if (!lines.length) {
            return false;
        }

        replaceNode(container, lines);
        return true;
    }

    /* Aplica los marcadores del servidor y, para lo que no esté marcado,
     * apila: el documento exportado nunca va en columnas. */
    function normalizeLayout(clone) {
        /* Las tarjetas con caja se convierten primero: así los pases
         * siguientes ya trabajan sobre la tabla. */
        Array.prototype.slice.call(clone.querySelectorAll('[data-rd-card]')).forEach(function (el) {
            el.removeAttribute('data-rd-card');
            cardToTable(el);
        });

        Array.prototype.slice.call(clone.querySelectorAll('[data-rd-stack="metrics"]')).forEach(function (el) {
            applyMetrics(el);
        });

        Array.prototype.slice.call(clone.querySelectorAll('[data-rd-stack="blocks"]')).forEach(function (el) {
            el.removeAttribute('data-rd-stack');
            el.removeAttribute('data-rd-layout');
            stackBlocks(el);
        });

        Array.prototype.slice.call(clone.querySelectorAll('[data-rd-stack="inline"]')).forEach(function (el) {
            el.removeAttribute('data-rd-stack');
            el.removeAttribute('data-rd-layout');
            inlineChildren(el);
        });

        Array.prototype.slice.call(clone.querySelectorAll('[data-rd-layout]')).forEach(function (el) {
            var display = el.getAttribute('data-rd-layout') || '';
            el.removeAttribute('data-rd-layout');

            if (display === 'inline-flex' || display === 'inline-grid') {
                el.style.setProperty('display', 'inline-block');
                return;
            }

            var kids = elChildren(el);
            if (!kids.length) {
                el.style.setProperty('display', 'block');
                return;
            }

            var allInline = kids.every(function (child) {
                var tag = (child.tagName || '').toLowerCase();
                return tag === 'a' || tag === 'span' || tag === 'em' || tag === 'strong' || tag === 'b' || tag === 'i';
            });

            if (allInline || hasLooseText(el)) {
                inlineChildren(el);
            } else {
                stackBlocks(el);
            }
        });

        Array.prototype.slice.call(clone.querySelectorAll('[data-rd-stack]')).forEach(function (el) {
            el.removeAttribute('data-rd-stack');
        });
    }

    /* El documento exportado no hereda sangrías: en Word, una tabla al 100 %
     * dentro de un contenedor con padding rebasa el margen derecho. */
    function stripHorizontalPadding(root) {
        ['left', 'right'].forEach(function (side) {
            root.style.setProperty('padding-' + side, '0');
            root.style.setProperty('margin-' + side, '0');
        });
        Array.prototype.slice.call(root.querySelectorAll('section, .report-cve, .doc-sheet')).forEach(function (el) {
            el.style.setProperty('padding-left', '0');
            el.style.setProperty('padding-right', '0');
        });
    }

    function buildExport(rootId, htmlId) {
        var source = sheet(rootId);
        if (!source) {
            return null;
        }

        /* Documento generado en servidor para Word: se copia tal cual. */
        var template = htmlId ? document.getElementById(htmlId) : null;
        if (!template && typeof rootId === 'string') {
            template = document.getElementById(rootId + '-word');
        }
        if (template) {
            var inner = typeof template.innerHTML === 'string' ? template.innerHTML : '';
            var templateText = template.content ? (template.content.textContent || '') : (template.textContent || '');
            if (inner.trim() !== '') {
                return { html: inner, text: templateText };
            }
        }

        var clone = source.cloneNode(true);

        withLightTheme(function () {
            inlineStyles(source, clone);
        });

        purge(clone);
        normalizeLayout(clone);
        stripHorizontalPadding(clone);

        return {
            html: clone.innerHTML,
            text: source.innerText || source.textContent || ''
        };
    }

    /* HTML autocontenido listo para abrir en Word. */
    function buildDocument(rootId, title, htmlId) {
        var built = buildExport(rootId, htmlId);
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

    /* Copia con formato. Si la escritura asíncrona falla (permiso denegado,
     * pestaña sin foco, dato demasiado grande), cae al copiador heredado y,
     * como último recurso, a texto plano. Nunca deja al usuario sin nada. */
    function writeRich(html, text) {
        var pending = null;

        if (navigator.clipboard && window.ClipboardItem && window.isSecureContext) {
            try {
                pending = navigator.clipboard.write([new ClipboardItem({
                    'text/html': new Blob([html], { type: 'text/html' }),
                    'text/plain': new Blob([text], { type: 'text/plain' })
                })]);
            } catch (err) {
                pending = null;
            }
        }

        var copy = pending
            ? pending.then(function () {
                return true;
            }).catch(function () {
                /* La escritura asíncrona rechazó: se intenta el método heredado. */
                return legacyCopyRich(html);
            })
            : Promise.resolve(legacyCopyRich(html));

        return copy.then(function (ok) {
            if (ok) {
                return true;
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                return navigator.clipboard.writeText(text).then(function () {
                    return true;
                });
            }
            return Promise.reject(new Error('El navegador no permite escribir en el portapapeles.'));
        });
    }

    var ReportDoc = window.ReportDoc = window.ReportDoc || {};

    ReportDoc.build = buildExport;

    ReportDoc.copyRich = function (rootId, options) {
        var opts = options || {};
        var built = buildExport(rootId, opts.htmlId);
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
        var built = buildExport(rootId, opts.htmlId);
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

    /* Punto de prueba para las comprobaciones automáticas (tools/smoke/report-doc.mjs).
     * No se usa en la interfaz. */
    ReportDoc._internals = {
        isMetricCell: isMetricCell,
        isNumberBadge: isNumberBadge,
        attrFrom: attrFrom,
        cleanInlineStyle: cleanInlineStyle,
        borderShorthand: borderShorthand
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
        var htmlId = button.getAttribute('data-rd-html') || '';

        if (action === 'copy-rich') {
            ReportDoc.copyRich(target, { markdown: markdown, htmlId: htmlId });
        } else if (action === 'copy-plain') {
            ReportDoc.copyPlain(target, { markdown: markdown, htmlId: htmlId, message: 'Texto copiado.' });
        } else if (action === 'download-html') {
            ReportDoc.downloadHtml(target, filename, title, htmlId);
        } else if (action === 'download-md') {
            ReportDoc.downloadMarkdown(filename, markdown);
        }
    });
})();
