/**
 * report-doc.mjs — Pruebas de la lógica de exportación de report-doc.js.
 *
 *   node tools/smoke/report-doc.mjs
 *
 * No necesita navegador: carga el helper con un `document` mínimo y prueba las
 * funciones puras que deciden qué es una métrica, cómo se lee un porcentaje y
 * cómo se limpia un estilo para ponerlo en línea.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(here, '../../public_html/assets/js/report-doc.js'), 'utf8');

/* document/window mínimos: el helper solo los usa al cargar (listener) y
 * dentro de las acciones, que aquí no se ejecutan. */
const sandbox = {
    document: {
        addEventListener() {},
        getElementById() { return null; },
        createElement() { return {}; },
        createDocumentFragment() { return {}; },
        documentElement: { classList: { contains() { return false; }, remove() {}, add() {} }, getAttribute() { return null; }, setAttribute() {} }
    },
    navigator: {},
    URL: { createObjectURL() { return ''; }, revokeObjectURL() {} },
    Blob: class {},
    setTimeout,
    console
};
sandbox.window = sandbox;
sandbox.window.isSecureContext = false;

vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename: 'report-doc.js' });

const ReportDoc = sandbox.window.ReportDoc;
let fail = 0;
let total = 0;

function check(label, ok, detail = '') {
    total++;
    console.log((ok ? 'OK   ' : 'FALLO ') + label + (!ok && detail ? ' - ' + detail : ''));
    if (!ok) { fail++; }
}

/* --- utilidades para construir elementos falsos ------------------------- */
function style(map) {
    return {
        getPropertyValue(name) { return map[name] || ''; }
    };
}

function el(tagName, textContent, options = {}) {
    const node = {
        tagName,
        textContent,
        children: options.children || [],
        style: style(options.style || {}),
        classList: {
            contains(name) { return (options.classes || []).includes(name); }
        },
        getAttribute(name) {
            if (options.attrs && Object.prototype.hasOwnProperty.call(options.attrs, name)) {
                return options.attrs[name];
            }
            return name === 'style' ? (options.styleAttr || '') : null;
        },
        querySelector(selector) {
            if (typeof options.querySelector === 'function') {
                return options.querySelector(selector);
            }
            return options.hasBlockedContent && selector.includes('ul') ? {} : null;
        }
    };
    return node;
}

const I = ReportDoc._internals;

/* --- isMetricCell ------------------------------------------------------- */
check('métrica: etiqueta en mayúsculas + valor (tira de KPIs)',
    I.isMetricCell(el('div', 'CVEs1', {
        children: [
            el('p', 'CVEs', { style: { 'text-transform': 'uppercase', 'font-size': '10px' } }),
            el('p', '1', { style: { 'font-size': '20px' } })
        ]
    })) === true);

check('métrica: dt + dd (CVSS)',
    I.isMetricCell(el('div', 'CVSS10.0', {
        children: [
            el('dt', 'CVSS', { style: { 'text-transform': 'uppercase' } }),
            el('dd', '10.0', { style: { 'font-size': '30px' } })
        ]
    })) === true);

check('métrica: etiqueta más pequeña que el valor (exposición)',
    I.isMetricCell(el('div', 'Equipos afectados3', {
        children: [
            el('p', 'Equipos afectados', { style: { 'font-size': '12px' } }),
            el('p', '3', { style: { 'font-size': '18px' } })
        ]
    })) === true);

check('métrica: una tarjeta del análisis NO es una métrica',
    I.isMetricCell(el('div', '1Naturaleza y alcanceEl parámetro permite inyectar', {
        children: [
            el('h4', '1Naturaleza y alcance', {
                style: { 'font-size': '12px' },
                children: [el('span', '1', {})]
            }),
            el('p', 'El parámetro permite inyectar', { style: { 'font-size': '12px' } })
        ]
    })) === false);

check('métrica: tarjeta de enlaces NO es una métrica',
    I.isMetricCell(el('div', 'Exploits públicos (2)lista', {
        children: [
            el('p', 'Exploits públicos (2)', { style: { 'text-transform': 'uppercase' } }),
            el('ul', 'lista', {
                hasBlockedContent: true,
                querySelector(selector) { return selector.includes('ul') ? {} : null; }
            })
        ]
    })) === false);

check('métrica: etiqueta demasiado larga se descarta',
    I.isMetricCell(el('div', 'x', {
        children: [
            el('p', 'Una etiqueta larguísima que no es una etiqueta de verdad', { style: { 'text-transform': 'uppercase' } }),
            el('p', '1', {})
        ]
    })) === false);

/* --- attrFrom ----------------------------------------------------------- */
check('atributo: lo lee del propio elemento',
    I.attrFrom(el('dd', '10.0', { attrs: { 'data-rd-color': '#dc2626' } }), 'data-rd-color') === '#dc2626');
check('atributo: lo busca en el contenido (EPSS va en un span)',
    I.attrFrom(
        el('dd', '62,88 %', {
            children: [el('span', '62,88 %', { attrs: { 'data-rd-color': '#ea580c' } })],
            querySelector() { return el('span', '62,88 %', { attrs: { 'data-rd-color': '#ea580c' } }); }
        }),
        'data-rd-color'
    ) === '#ea580c');
check('atributo: vacío cuando no existe',
    I.attrFrom(el('dd', 'x', {}), 'data-rd-color') === '');

/* --- cleanInlineStyle --------------------------------------------------- */
const cleaned = I.cleanInlineStyle(
    el('dd', '10.0', { styleAttr: 'font-size:30px;color:#b91c1c;display:block;margin-top:4px;width:10px' }),
    18
);
check('estilo: limita el tamaño de fuente', cleaned.includes('font-size:18px'), cleaned);
check('estilo: conserva el color', cleaned.includes('color:#b91c1c'), cleaned);
check('estilo: quita display/margin/width', !cleaned.includes('display') && !cleaned.includes('margin') && !cleaned.includes('width'), cleaned);
check('estilo: no emite display (Word corta ahí)', !cleaned.includes('display') && !cleaned.includes('vertical-align'), cleaned);

/* El tono sustituye el color de origen: una sola declaración y al final. */
const toned = I.cleanInlineStyle(
    el('dd', '9.8', { styleAttr: 'font-size:30px;font-weight:700;color:#111827;display:block' }),
    18,
    { color: '#dc2626', 'font-weight': '700' }
);
check('estilo: un solo color', (toned.match(/color:/g) || []).length === 1, toned);
check('estilo: un solo font-weight', (toned.match(/font-weight:/g) || []).length === 1, toned);
check('estilo: el color va al final', /color:#dc2626;\s*$/.test(toned), toned);
check('estilo: conserva el tamaño limitado', toned.includes('font-size:18px'), toned);
check('estilo: sin display cuando lleva tono', !toned.includes('display'), toned);

/* --- isNumberBadge ------------------------------------------------------ */
check('número: círculo oscuro con una cifra se detecta',
    I.isNumberBadge(el('span', '1', {
        style: { 'background-color': '#111827', 'border-top-left-radius': '9999px' }
    })) === true);

check('número: un badge normal no se toca',
    I.isNumberBadge(el('span', '1', {
        style: { 'background-color': '#fee2e2', 'border-top-left-radius': '6px' }
    })) === false);

check('número: sin fondo no se considera círculo',
    I.isNumberBadge(el('span', '1', { style: { 'border-top-left-radius': '9999px' } })) === false);

/* --- borderShorthand ---------------------------------------------------- */
const border = I.borderShorthand(el('div', '', {
    style: {
        'border-top-width': '1px', 'border-top-style': 'solid', 'border-top-color': '#e5e7eb',
        'border-right-width': '1px', 'border-right-style': 'solid', 'border-right-color': '#e5e7eb',
        'border-bottom-width': '1px', 'border-bottom-style': 'solid', 'border-bottom-color': '#e5e7eb',
        'border-left-width': '4px', 'border-left-style': 'solid', 'border-left-color': '#ef4444'
    }
}));
check('borde: genera los cuatro lados', border.length === 4, JSON.stringify(border));
check('borde: conserva el grosor del lado izquierdo', border.join(';').includes('border-left:4px solid #ef4444'), JSON.stringify(border));

const noBorder = I.borderShorthand(el('div', '', {
    style: {
        'border-top-width': '0px', 'border-top-style': 'none',
        'border-bottom-width': '1px', 'border-bottom-style': 'solid', 'border-bottom-color': '#e5e7eb'
    }
}));
check('borde: ignora los lados sin borde', noBorder.length === 1 && noBorder[0].includes('border-bottom'), JSON.stringify(noBorder));

console.log('');
console.log(`${total - fail}/${total} OK`);
process.exit(fail === 0 ? 0 : 1);
