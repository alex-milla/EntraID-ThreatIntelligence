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
        getAttribute(name) { return name === 'style' ? (options.styleAttr || '') : null; },
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

/* --- percentFrom -------------------------------------------------------- */
check('barra: porcentaje en línea', I.percentFrom(el('span', '', { style: { width: '62.9%' } })) === 62.9);
check('barra: sin porcentaje asume el 100 %', I.percentFrom(el('span', '', { style: {} })) === 100);
check('barra: recorta por encima del 100 %', I.percentFrom(el('span', '', { style: { width: '140%' } })) === 100);

/* --- cleanInlineStyle --------------------------------------------------- */
const cleaned = I.cleanInlineStyle(
    el('dd', '10.0', { styleAttr: 'font-size:30px;color:#b91c1c;display:block;margin-top:4px;width:10px' }),
    18
);
check('estilo: limita el tamaño de fuente', cleaned.includes('font-size:18px'), cleaned);
check('estilo: conserva el color', cleaned.includes('color:#b91c1c'), cleaned);
check('estilo: quita display/margin/width', !cleaned.includes('display:block') && !cleaned.includes('margin') && !cleaned.includes('width'), cleaned);
check('estilo: fuerza inline-block', cleaned.includes('display:inline-block'), cleaned);

console.log('');
console.log(`${total - fail}/${total} OK`);
process.exit(fail === 0 ? 0 : 1);
