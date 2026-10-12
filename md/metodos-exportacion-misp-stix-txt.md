# Métodos de exportación: MISP, STIX 2.1 y TXT

Documento de referencia para reutilizar los exportadores del proyecto
**IOC Extractor & Classifier** en futuros proyectos.

Rutas del código:
- Cliente (navegador): `public_html/assets/script.js`
- Servidor (STIX): `public_html/export.php` + `public_html/utils.php`
- Configuración (TLP, defaults): `public_html/config.php`

---

## 1. Arquitectura general

| Formato | Dónde se genera | Endpoint | Ficheros de salida |
|---|---|---|---|
| **TXT** | Cliente | — | `iocs.txt` |
| **CSV** | Cliente | — | `iocs.csv` |
| **STIX 2.1** | Cliente (+ validación servidor) | `export.php` (POST JSON) | `iocs_stix_<tipo>_<fecha>.json` (split) o `iocs_stix_<fecha>.json` (merged) |
| **MISP** | Cliente | — | `misp_<tipo>_<fecha>.json` (split) o `misp_event_<fecha>.json` (merged) |

Todos parten del mismo estado en memoria:

```js
state.extractedIOCs = [
  { value: '38.244.50.120', type: 'ipv4-addr', description: 'Threat actor-controlled IP' },
  // ...
];
```

- `value`: indicador normalizado (refanged).
- `type`: tipo STIX-like (`ipv4-addr`, `domain-name`, `url`, `file`, `email-addr`,
  `user-account`, `windows-registry-key`, `mac-addr`, `autonomous-system`).
- `description`: texto opcional (editable o masivo). Se usa como `comment`
  (MISP) y `description` (STIX).

### Utilidad de descarga (común a todos)

```js
function downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
}

function getTimestamp() {
    return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
}
```

### Formato de salida (común)

Un único control `#output-format` decide **split** (un archivo por tipo) o
**merged** (archivo único) para STIX y MISP:

```html
<select id="output-format">
  <option value="split" selected>Separado por tipo (recomendado)</option>
  <option value="merged">Archivo único combinado</option>
</select>
```

---

## 2. Exportación TXT

El más simple: solo los valores, uno por línea.

```js
function exportToTXT() {
    const values = state.extractedIOCs.map(ioc => ioc.value).join('\n');
    downloadFile(values, 'iocs.txt', 'text/plain');
}
```

Salida de ejemplo (`iocs.txt`):

```
38.244.50.120
101.53.80.20
xcai.pro
http://38.244.50.120:18899/.claude/CLAUDE.md
```

---

## 3. Exportación CSV

Incluye descripción y escapado correcto de campos.

```js
function exportToCSV() {
    const headers = ['#', 'Type', 'Value', 'Description'];
    const rows = state.extractedIOCs.map((ioc, index) => [
        index + 1,
        APP.typeNames[ioc.type] || ioc.type,
        ioc.value,
        ioc.description || ''
    ]);
    const csv = [headers, ...rows].map(row => row.map(csvField).join(',')).join('\n');
    downloadFile(csv, 'iocs.csv', 'text/csv');
}

function csvField(value) {
    const s = String(value == null ? '' : value);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
```

---

## 4. Exportación STIX 2.1

### 4.1 Objeto generado

Cada IOC se convierte en un objeto `indicator` de STIX 2.1:

```json
{
  "type": "indicator",
  "id": "indicator--<uuid-v4>",
  "spec_version": "2.1",
  "pattern": "[ipv4-addr:value = '38.244.50.120']",
  "pattern_type": "stix",
  "pattern_version": "2.1",
  "created": "2026-10-09T10:00:00Z",
  "modified": "2026-10-09T10:00:00Z",
  "valid_from": "2026-10-09T10:00:00Z",
  "valid_until": "2027-10-09T10:00:00Z",
  "name": "CrowdStrike - 38.244.50.120",
  "description": "Threat actor-controlled IP",
  "indicator_types": ["malicious-activity"],
  "revoked": false,
  "labels": ["IPv4", "c2", "banking"],
  "confidence": 75,
  "lang": "en",
  "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"],
  "external_references": []
}
```

### 4.2 Patrón STIX por tipo

```js
function generateSTIXPattern(type, value) {
    switch (type) {
        case 'ipv4-addr': return `[ipv4-addr:value = '${value}']`;
        case 'ipv6-addr': return `[ipv6-addr:value = '${value}']`;
        case 'domain-name': return `[domain-name:value = '${value}']`;
        case 'url': return `[url:value = '${value}']`;
        case 'file': return `[file:hashes.MD5 = '${value}']`; // por defecto
        case 'email-addr': return `[email-addr:value = '${value}']`;
        case 'user-account': return `[user-account:value = '${value}']`;
        case 'windows-registry-key': return `[windows-registry-key:key = '${value}']`;
        case 'mac-addr': return `[mac-addr:value = '${value}']`;
        case 'autonomous-system': return `[autonomous-system:number = '${value.replace('AS','')}']`;
        default: return null;
    }
}
```

> En el servidor, `utils.php::generateSTIXPattern()` distingue MD5/SHA-1/SHA-256/SHA-512
> por longitud (`file:hashes.MD5`, `file:hashes.SHA-1`, `file:hashes.SHA-256`,
> `file:hashes.SHA-512`).

### 4.3 TLP → marking-definition (STIX)

IDs estándar (en `config.php`, constante `TLP_MARKINGS` y replicados en el cliente):

| Nivel | `object_marking_refs` |
|---|---|
| white | `marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9` |
| green | `marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da` |
| amber | `marking-definition--f88d31f6-486f-44da-b317-01333bde0b82` |
| red   | `marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed` |

`indicator_types` usa el vocabulario STIX 2.1: `anomalous-activity`,
`attribution`, `benign`, `compromised`, `malicious-activity`, `unknown`.

### 4.4 Flujo cliente + servidor

1. El cliente arma `config` (fuente, tipo, confianza, TLP, validez, actor,
   etiquetas, formato) y llama a `generateSTIXData(config)`.
2. Hace `POST` a `export.php` con `{ iocs: state.extractedIOCs, config }`.
3. `export.php::generateSTIX()` devuelve `{ success, stix, count }` (validación).
4. El cliente descarga los ficheros a partir de `stixData`:
   - **split**: agrupa por tipo y descarga `iocs_stix_<tipo>_<fecha>.json`.
   - **merged**: un único `iocs_stix_<fecha>.json`.
5. Ante error del servidor, hay **fallback** a exportación 100% cliente.

Snippet del POST:

```js
const response = await fetch('export.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ iocs: state.extractedIOCs, config })
});
const result = await response.json();
if (result.success) { /* descargar stixData */ }
```

---

## 5. Exportación MISP

Formato **MISP core** (`Event` con `Attribute[]` y `Tag[]`).

### 5.1 Estructura del evento

```json
{
  "Event": {
    "info": "CrowdStrike - APT28 - IOC Export",
    "date": "2026-10-09",
    "distribution": "1",
    "threat_level_id": "2",
    "analysis": "2",
    "published": false,
    "Attribute": [
      {
        "type": "ip-dst",
        "category": "Network activity",
        "value": "38.244.50.120",
        "to_ids": true,
        "comment": "Threat actor-controlled IP"
      }
    ],
    "Tag": [{ "name": "tlp:amber" }, { "name": "c2" }, { "name": "banking" }]
  }
}
```

### 5.2 Mapeo tipo app → atributo MISP

| Tipo app | MISP `Attribute.type` | Categoría |
|---|---|---|
| `ipv4-addr` / `ipv6-addr` | `ip-src` o `ip-dst` (configurable) | Network activity |
| `domain-name` | `domain` | Network activity |
| `url` | `url` | Network activity |
| `file` | `md5` / `sha1` / `sha256` / `sha512` (por longitud) | Payload delivery |
| `email-addr` | `email-src` | Payload delivery |
| `user-account` | `username` | Network activity |
| `windows-registry-key` | `regkey` | Persistence mechanism |
| `mac-addr` | `mac-address` | Network activity |
| `autonomous-system` | `AS` (sin prefijo `AS`) | Network activity |

```js
function hashMispType(value) {
    const len = value.length;
    if (len === 32) return 'md5';
    if (len === 40) return 'sha1';
    if (len === 64) return 'sha256';
    if (len === 128) return 'sha512';
    return 'text';
}
```

### 5.3 Dirección de IP configurable

Control `#misp-ip-direction` con valores `ip-dst` (def.), `ip-src`, `both`.

```js
case 'ipv4-addr':
case 'ipv6-addr': {
    const dirs = ipDirection === 'both' ? ['ip-src', 'ip-dst'] : [ipDirection || 'ip-dst'];
    dirs.forEach(t => attrs.push({ ...base, type: t, category: 'Network activity' }));
    break;
}
```

### 5.4 TLP → distribución MISP + tags

```js
const MISP_TLP_DISTRIBUTION = {
    white: '3', // All communities
    green: '2', // Connected communities
    amber: '1', // This community only
    red:   '0'  // Your organisation only
};
```

Los tags incluyen siempre `tlp:<nivel>` más las etiquetas libres del formulario.

### 5.5 Split / merged

```js
if (format === 'split') {
    const byType = {};
    allAttributes.forEach(a => { (byType[a.type] = byType[a.type] || []).push(a); });
    Object.keys(byType).forEach(type => {
        const event = buildMISPEvent(byType[type]);
        downloadFile(JSON.stringify(event, null, 2),
            `misp_${type}_${getTimestamp()}.json`, 'application/json');
    });
} else {
    const event = buildMISPEvent(allAttributes);
    downloadFile(JSON.stringify(event, null, 2),
        `misp_event_${getTimestamp()}.json`, 'application/json');
}
```

> `comment` de cada atributo = `ioc.description`. `to_ids: true` por defecto.

---

## 6. Flujo de UI (dónde se disparan)

- Paso 2: `#btn-export-ids` → `exportToTXT()`.
- Paso 3: `#btn-export-csv` → `exportToCSV()`; `#btn-export-misp` →
  `showStep(4)`; `#btn-export-stix` → `showStep(4)`.
- Paso 4: `#btn-generate-stix` → `exportToSTIX()`; `#btn-generate-misp` →
  `exportToMISP()`.

La descripción (`state.extractedIOCs[i].description`) se rellena desde el
contexto del reporte o con la acción masiva del paso 3, y alimenta los tres
formatos.

---

## 7. Reutilización en futuros proyectos

Checklist para incorporar estos exportadores:

1. **Modelo de datos**: usa objetos `{ value, type, description }`.
2. **Utilidades**: copia `downloadFile()` y `getTimestamp()`.
3. **TXT**: `values.map(v => v.value).join('\n')`.
4. **STIX**:
   - Copia `generateSTIXPattern()` y añade un mapa `type → marking-definition`.
   - Para validación server-side, copia `export.php::generateSTIX()`.
   - Ofrece split (por tipo) o merged.
5. **MISP**:
   - Copia `MISP_TLP_DISTRIBUTION`, `hashMispType()`, `mispAttributesForIOC()` y
     `buildMISPEvent()`.
   - Ajusta el mapeo de tipos a los que maneje tu proyecto.
   - Expón una opción de dirección de IP si aplica.
6. **Consistencia**: la descripción debe viajar a `comment` (MISP) y
   `description` (STIX).

### Buenas prácticas / pitfalls

- **Escapado**: en CSV usa comillas dobles y duplica `"`.
- **JSON legible**: `JSON.stringify(x, null, 2)`; en PHP
  `json_encode($x, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)`.
- **Sin dependencias**: todo es Vanilla JS + PHP nativo (apto para hosting
  compartido).
- **No cachear**: los endpoints de exportación envían
  `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`.
- **UUID v4** para STIX (`generateUUID()`), no reutilizar IDs.
- **Fechas** en STIX en UTC formato `YYYY-MM-DDTHH:MM:SSZ` (sin milisegundos).
- **STIX `valid_until`** = `valid_from` + días de validez; `confidence` 0-100.
- **MISP `distribution`** ligada al TLP evita fugas de información.
- El vocabulario `indicator_types` de STIX es **abierto**: se pueden usar
  valores `x-...` si se necesita extender.

---

*Documento generado a partir del código de `public_html/` (2026-10-09).*
