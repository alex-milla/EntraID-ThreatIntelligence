# Guía de integración — APIs de Microsoft Security para informes y reportes

Guía práctica y completa para extraer desde una aplicación web, sin entrar al portal: informes de Threat Intelligence con IOCs, alertas, incidentes, vulnerabilidades de los equipos, Secure Score y hunting programático — incluidos los patrones para generar **reportes mensuales, trimestrales y anuales**.

Todo lo marcado *(verificado)* se probó con éxito en un tenant real durante la construcción de esta guía (12/10/2026).

**Estado actual del proyecto:** app Entra ID `ThreatIntel-ReportPuller` (client ID `<sanitizado>`) con secreto de cliente y `ThreatIntelligence.Read.All` concedido.

> ⚠️ Regla de oro: el secreto de cliente vive **solo en el backend** (variable de entorno / Key Vault). Nunca en el frontend. Todas las llamadas se hacen servidor → API.

---

## 1. Mapa general: qué API usar para cada cosa

| # | Dato | API | Base URL | Permiso (application) | Licencia requerida |
|---|---|---|---|---|---|
| 1 | Informes TI + IOCs | Graph Threat Intelligence | `graph.microsoft.com/v1.0/security/threatIntelligence` | `ThreatIntelligence.Read.All` | Defender XDR **o** Microsoft Sentinel (incluida, sin coste extra) |
| 2 | Intel global de CVEs | Graph Threat Intelligence | ídem `/threatIntelligence/vulnerabilities` | `ThreatIntelligence.Read.All` | ídem |
| 3 | Incidentes (con alertas) | Graph security | `graph.microsoft.com/v1.0/security/incidents` | `SecurityIncident.Read.All` | Defender XDR |
| 4 | Alertas | Graph security | `graph.microsoft.com/v1.0/security/alerts_v2` | `SecurityAlert.Read.All` | Defender XDR |
| 5 | Inventario de equipos | Defender for Endpoint | `api.security.microsoft.com/api/machines` | `Machine.Read.All` | Defender for Endpoint P1/P2 o Defender for Business |
| 6 | Vulnerabilidades por equipo | Defender for Endpoint (TVM) | `api.security.microsoft.com/api/vulnerabilities/machinesVulnerabilities` | `Vulnerability.Read.All` | Defender for Endpoint P2 / Defender Vulnerability Management |
| 7 | Export de assessments (snapshots/delta) | Defender for Endpoint (TVM) | `api.security.microsoft.com/api/machines/...` | `Vulnerability.Read.All` / `Software.Read.All` | ídem |
| 8 | Secure Score | Graph | `graph.microsoft.com/v1.0/security/secureScores` | `SecurityEvents.Read.All` | Microsoft 365 (E3/E5, etc.) |
| 9 | Advanced hunting (KQL programático) | Graph | `graph.microsoft.com/v1.0/security/runHuntingQuery` | `ThreatHunting.Read.All` | Defender XDR |

> Nota: la API antigua de advanced hunting (`api.security.microsoft.com/api/advancedhunting/run`) está en retirada desde enero de 2026 — Microsoft redirige a la versión de Graph (fila 9).

---

## 2. Licencias (requisitos oficiales)

Según [Microsoft Defender XDR prerequisites](https://learn.microsoft.com/defender-xdr/prerequisites), **cualquiera de estas licencias** da acceso a Microsoft Defender (portal unificado) sin coste adicional:

- Microsoft 365 E5 o A5
- Microsoft 365 E3 con el add-on **Microsoft Defender Suite**
- Microsoft 365 E3 con el add-on **Enterprise Mobility + Security E5**
- Microsoft 365 A3 con el add-on **A5 Security**
- Windows 10/11 Enterprise E5 o A5
- Enterprise Mobility + Security (EMS) E5 o A5
- Office 365 E5 o A5
- Microsoft Defender for Endpoint
- Microsoft Defender for IoT (protección Enterprise IoT)

Clientes **sin E5** también pueden usar Defender XDR si tienen: Defender for Endpoint, Defender for Identity, Defender for Cloud Apps o Defender for Office 365 Plan 2 ([FAQ oficial](https://learn.microsoft.com/defender-xdr/m365d-enable-faq)).

Por producto:

- **Defender for Endpoint**: Plan 1, Plan 2 o Defender for Business. M365 E5 / E5 Security incluyen Plan 2. Las APIs de vulnerabilidades (TVM) en profundidad requieren Plan 2 o Defender Vulnerability Management.
- **Threat Intelligence API**: incluida con Defender XDR **o Sentinel**, sin licencia aparte (según nota en [threatIntelligence resource](https://learn.microsoft.com/graph/api/resources/security-threatintelligence?view=graph-rest-1.0)). *(Verificado: los artículos/IOCs funcionan incluso en un tenant de pruebas sin Defender.)*
- **Secure Score**: incluido con las licencias M365 correspondientes; el acceso a datos se gestiona con Defender Unified RBAC (categoría *Security posture → Exposure Management (read)*).

**Implicación práctica:** en el tenant de pruebas (sin Defender) solo funcionan las filas 1, 2 y 8 de la tabla del punto 1. En el tenant de producción (con Defender) funcionan todas.

---

## 3. Autenticación

### 3.1 Flujo client credentials (servicio a servicio, sin usuario)

```http
POST https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id={clientId}
&client_secret={clientSecret}
&scope={recurso}/.default
```

### 3.2 Dos audiences — el gotcha más importante

| API | Audience (`scope` del token) |
|---|---|
| Graph (filas 1–4, 8, 9) | `https://graph.microsoft.com/.default` |
| Defender for Endpoint (filas 5–7) | `https://api.securitycenter.microsoft.com/.default` (heredado). Si un endpoint de `api.security.microsoft.com` te devuelve `403 Forbidden` con token de Graph, es el audience: pide el token con este recurso. |

El token dura 1 h (`expires_in: 3600`). **Cachea** y renueva a los ~55 min.

### 3.3 Errores de auth

- `AADSTS7000215` → enviaste el *Secret ID* en vez del *Value*, o el Value tiene salto de línea.
- `AADSTS90002` → tenant ID incorrecto (no es el Object ID).

### 3.4 Helper Node.js (backend) con caché, reintentos y audiences

```js
const TOKEN_CACHE = {};

async function getToken(scope) {
  const now = Date.now();
  if (TOKEN_CACHE[scope]?.token && now < TOKEN_CACHE[scope].expiresAt) return TOKEN_CACHE[scope].token;
  const res = await fetch(`https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      scope,
    }),
  });
  if (!res.ok) throw new Error(`Token error: ${await res.text()}`);
  const d = await res.json();
  TOKEN_CACHE[scope] = { token: d.access_token, expiresAt: now + (d.expires_in - 300) * 1000 };
  return d.access_token;
}

async function callApi(url, scope, opts = {}, tries = 3) {
  const res = await fetch(url, {
    ...opts,
    headers: { Authorization: `Bearer ${await getToken(scope)}`, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (res.status === 429 && tries > 1) { // throttling
    await new Promise(r => setTimeout(r, (Number(res.headers.get("Retry-After")) || 10) * 1000));
    return callApi(url, scope, opts, tries - 1);
  }
  if (!res.ok) throw new Error(`${url} → ${res.status}: ${await res.text()}`);
  return res.json();
}

// Graph
const graph = (path, opts) => callApi(`https://graph.microsoft.com/v1.0/${path}`, "https://graph.microsoft.com/.default", opts);
// Defender for Endpoint
const mde = (path, opts) => callApi(`https://api.security.microsoft.com/${path}`, "https://api.securitycenter.microsoft.com/.default", opts);
```

---

## 4. Threat Intelligence: informes completos + IOCs *(verificado)*

### 4.1 Endpoints

| Operación | Endpoint |
|---|---|
| Listar artículos | `GET /security/threatIntelligence/articles?$select=id,title,createdDateTime,lastUpdatedDateTime` |
| Artículo completo | `GET /security/threatIntelligence/articles/{id}` |
| IOCs de un artículo | `GET /security/threatIntelligence/articles/{id}/indicators` |
| Perfiles de actores | `GET /security/threatIntelligence/intelProfiles` |
| Perfil completo | `GET /security/threatIntelligence/intelProfiles/{id}` |
| IOCs de un actor | `GET /security/threatIntelligence/intelProfiles/{id}/indicators` |
| CVE global (severidad, CVSS, EPSS, exploits) | `GET /security/threatIntelligence/vulnerabilities/{cveId}` |

Además la API expone datos de enriquecimiento: hosts, componentes, cookies, DNS pasivo, trackers, certificados SSL, WHOIS — útiles para pivotar sobre un IOC desde tu app.

### 4.2 Modelo de datos

Artículo (`article`): `title`, `createdDateTime`, `lastUpdatedDateTime`, `summary.content`, **`body.content` (informe completo, 2.000–7.000+ caracteres)**, `tags`, `isFeatured`.

Indicador (`articleIndicator` / `intelligenceProfileIndicator`): hereda `id` + `source` (`microsoftDefenderThreatIntelligence` | `openSourceIntelligence` | `public`) y relación `artifact` con el artefacto observado (IP, host/dominio, URL, hash, email…).

### 4.3 Gotchas verificados en pruebas reales

1. La propiedad es **`createdDateTime`** — no existe `publishedDateTime` (`BadRequest` si la pides).
2. **`$top` no permitido** en `/articles/{id}/indicators` (`invalidRequest`). Ante cualquier parámetro OData rechazado: quítalo y pagina vía `@odata.nextLink`.
3. **`$filter` por fecha**: no lo asumas; trae la colección y **filtra en el cliente** por `lastUpdatedDateTime ?? createdDateTime`.
4. **IOCs por artículo muy variables**: en una semana real, de 18 artículos solo 11 tenían IOCs (2–25 cada uno). Maneja colecciones vacías y `value` nulo.
5. Paginación: si la respuesta trae `@odata.nextLink`, sigue ese enlace exacto (ya lleva los parámetros).

### 4.4 Informe de la mañana *(verificado)*

```js
async function dailyTIReport(sinceHours = 24) {
  const list = await graph("security/threatIntelligence/articles?$select=id,title,createdDateTime,lastUpdatedDateTime");
  const since = Date.now() - sinceHours * 3600 * 1000;
  const recent = (list.value ?? []).filter(a =>
    Date.parse(a.lastUpdatedDateTime ?? a.createdDateTime) >= since);

  return Promise.all(recent.map(async a => {
    const [full, iocs] = await Promise.all([
      graph(`security/threatIntelligence/articles/${a.id}`),
      graph(`security/threatIntelligence/articles/${a.id}/indicators`).catch(() => ({ value: [] })),
    ]);
    return {
      title: full.title, published: full.createdDateTime, updated: full.lastUpdatedDateTime,
      tags: full.tags, summary: full.summary?.content, body: full.body?.content,
      iocs: iocs.value ?? [],
    };
  }));
}
```

---

## 5. Alertas e incidentes (Defender XDR)

### 5.1 Incidentes — `GET /security/incidents`

- Permiso app: `SecurityIncident.Read.All` (leer) / `SecurityIncident.ReadWrite.All`. Delegado: roles *Security Reader*, *Global Reader*, *Security Operator*, *Security Administrator*.
- OData: `$count`, `$filter`, `$skip`, `$top`, `$expand`.
- `$filter` soportado en: **`assignedTo`, `classification`, `createdDateTime`, `determination`, `lastUpdateDateTime`, `severity`, `status`**.
- `$expand=alerts` → incidentes con todas sus alertas (incl. evidencia, MITRE techniques, severidad, servicio).
- Propiedades útiles para informes: `displayName`, `severity` (low/medium/high/informational), `status` (active/inProgress/resolved/awaitingAction/redirected), `classification` (truePositive/falsePositive/…), `determination`, `createdDateTime`, `lastUpdateDateTime`, `comments`, `customTags`, `recommendedActions`.
- Paginación con `@odata.nextLink`.

```http
GET /v1.0/security/incidents?$filter=createdDateTime ge 2026-10-11T00:00:00Z
    and createdDateTime lt 2026-10-12T00:00:00Z
    &$expand=alerts&$count=true
```

### 5.2 Alertas sueltas — `GET /security/alerts_v2`

- Permiso app: `SecurityAlert.Read.All` (mínimo privilegio) / `SecurityAlert.ReadWrite.All`.
- OData: `$count`, `$filter`, `$skip`, `$top`.
- `$filter` soportado en: **`assignedTo`, `classification`, `determination`, `createdDateTime`, `lastUpdateDateTime`, `severity`, `serviceSource`, `status`**.
- Campos estrella para visualizar: `title`, `threatDisplayName`, `threatFamilyName`, `category`, `detectionSource`, `serviceSource` (microsoftDefenderForEndpoint, microsoftDefenderForOffice365, microsoftDefenderForIdentity, microsoftDefenderForCloudApps…), `mitreTechniques`, `evidence`, `firstActivityDateTime`, `lastActivityDateTime`, `incidentId`.

### 5.3 Retención y frecuencia

Los incidentes están disponibles "dentro del rango de tiempo de la política de retención de tu entorno". Para dashboards en (semi)tiempo real, puedes sondear cada pocos minutos con `$filter=lastUpdateDateTime ge ...`, o usar **webhooks / suscripciones** de Graph (change notifications) para no sondear.

---

## 6. Equipos y vulnerabilidades (Defender for Endpoint / TVM)

Base: `https://api.security.microsoft.com`. Audience del token: ver §3.2.

### 6.1 Inventario — `GET /api/machines`

- Permiso app: `Machine.Read.All`.
- OData: `$filter` en `computerDnsName`, `id`, `version`, `deviceValue`, `aadDeviceId`, `machineTags`, `lastSeen`, `exposureLevel`, `onboardingStatus`, `lastIpAddress`, `healthStatus`, `osPlatform`, `riskScore`, `rbacGroupId`; `$top` máx 10.000; `$skip`.
- Rate: 100 llamadas/min, 1.500/h.
- Campos clave: `computerDnsName`, `osPlatform`, `healthStatus`, `riskScore`, `exposureLevel`, `lastSeen`, `machineTags`, `rbacGroupId`.

### 6.2 Vulnerabilidades por equipo — `GET /api/vulnerabilities/machinesVulnerabilities`

- Permiso app: `Vulnerability.Read.All`.
- Devuelve todas las vulnerabilidades de la organización **por equipo y software** (CVE, severidad, KB de corrección si existe).
- `$filter` en: `id`, `cveId`, `machineId`, `fixingKbId`, `productName`, `productVersion`, `severity`, `productVendor`; `$top` máx 10.000; `$skip`.
- Complementos: `GET /api/machines/{machineId}/vulnerabilities` (vulns de un equipo, 50 llamadas/min) y `GET /api/vulnerabilities/{cveId}/machineReferences` (equipos afectados por un CVE).
- `GET /api/vulnerabilities` → catálogo global de CVEs con `cvssV3`, `severity`, `publicExploit`, `exploitVerified`, `exploitInKit`, `EPSS`, `exposedMachines` (cuántos equipos tuyos están expuestos), `publishedOn`, `updatedOn` — muy potente para informes.

### 6.3 Export de assessments (snapshots grandes y deltas)

Para volúmenes grandes hay dos mecanismos ([export assessment methods](https://learn.microsoft.com/defender-endpoint/api/get-assessment-methods-properties)):

- **JSON (paginado con `@odata.nextLink`)**: recomendado para < 100.000 equipos.
- **Vía archivos**: la API devuelve URLs SAS de Azure Storage con el snapshot completo (GZIP + JSON multilínea; `sasValidHours` máx 24 h). Recomendado para > 100.000 equipos.
- **Delta export**: solo los cambios desde un `sinceTime` (consultable hasta 14 días atrás). El snapshot *full* de vulnerabilidades por equipo se refresca **cada 6 horas**; el `GET` lee el último snapshot, no dispara generación.

Endpoints: `GET /api/machines/SoftwareVulnerabilitiesByMachine` (JSON), `GET /api/machines/SoftwareVulnerabilitiesExport` (files), delta con `sinceTime`. Inventarios análogos: software (`SoftwareInventoryByMachine`, permiso `Software.Read.All`), hardware/firmware (`HardwareFirmwareInventoryByMachine`), certificados (`certificateAssessmentExport`, `Vulnerability.Read.All`).

⚠️ **Para reportes mensuales/trimestrales/anuales de vulnerabilidades**: la API solo da el snapshot **actual** (no guarda histórico). Tu app debe almacenar snapshots periódicos (p. ej. semanal full + diario delta) para poder construir tendencias.

### 6.4 Rate limits típicos (TVM)

- Export por archivos: 5 llamadas/min, 20/h.
- Vulnerabilidades de un equipo: 50 llamadas/min, 1.500/h.
- Hardware/firmware JSON: 30/min, 1.000/h.

---

## 7. Secure Score (evolución de la postura)

- `GET /security/secureScores` — una entrada **por periodo** con `currentScore`, `maxScore`, `activeUserCount`, `licensedUserCount`, `enabledServices`, `averageComparativeScores`. Ideal para gráficas de tendencia mensual/anual.
- `GET /security/secureScores/{id}` y `GET /security/secureScoreControlProfiles` — detalle por control.
- Permiso app: `SecurityEvents.Read.All` (admin consent obligatorio).
- Nota: el acceso de usuarios se gestiona con Defender Unified RBAC (*Security posture → Exposure Management (read)*).

---

## 8. Advanced hunting programático (KQL)

- **Recomendado (Graph):** `POST /security/runHuntingQuery` con `{"Query": "<KQL>"}`. Permiso app: **`ThreatHunting.Read.All`**.
- KQL sobre el [schema de advanced hunting](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables): `AlertInfo`, `AlertEvidence`, `DeviceProcessEvents`, `EmailEvents`, `IdentityLogonEvents`, etc.
- Cuotas: datos de los últimos **30 días**, máx **100.000 filas** por query, ≥45 llamadas/min por tenant, bloqueo por CPU si se supera la cuota (respuesta `429`), timeout de query ~3 min.
- La API heredada `api.security.microsoft.com/api/advancedhunting/run` (permiso `AdvancedHunting.Read.All`) está en retirada desde enero 2026 — migra a Graph.

**Para reportes periódicos**, hunting solo cubre 30 días: ejecuta y **almacena** los resultados agregados con la frecuencia que necesites (diaria/semanal) y compón el mensual/trimestral/anual desde tu base de datos.

```js
const monthlyTopAlerts = await graph("security/runHuntingQuery", {
  method: "POST",
  body: JSON.stringify({
    Query: `AlertInfo
      | where Timestamp >= datetime(2026-09-01) and Timestamp < datetime(2026-10-01)
      | summarize Cnt = count() by Title, Severity
      | top 20 by Cnt`,
  }),
});
```

---

## 9. Patrones de consulta para reportes mensuales / trimestrales / anuales

### 9.1 Ventanas de tiempo con `$filter`

Filtro genérico OData (funciona en `incidents` y `alerts_v2`, propiedades `createdDateTime`/`lastUpdateDateTime`):

```http
GET /v1.0/security/incidents?$filter=createdDateTime ge {inicio} and createdDateTime lt {fin}&$count=true
```

Genera `{inicio}`/`{fin}` en UTC ISO (`2026-10-01T00:00:00Z`). Ejemplos:

| Periodo | Ventana |
|---|---|
| Diario (informe de la mañana) | `[ayer 00:00, hoy 00:00)` |
| Mensual | `[1er día 00:00, 1er día mes siguiente 00:00)` |
| Trimestral | `[1 jul, 1 oct)` |
| Anual | `[1 ene, 1 ene año siguiente)` |

### 9.2 Paginación completa (para volúmenes grandes)

```js
async function fetchAll(path, scope = "graph") {
  const out = [];
  let url = scope === "graph" ? `https://graph.microsoft.com/v1.0/${path}` : path;
  while (url) {
    const page = scope === "graph" ? await graph(path.includes("v1.0/") ? "" : "") : null;
    // Graph devuelve @odata.nextLink absoluto: síguelo directamente
    const res = await fetch(url, { headers: { Authorization: `Bearer ${await getToken("https://graph.microsoft.com/.default")}` } });
    const d = await res.json();
    out.push(...(d.value ?? []));
    url = d["@odata.nextLink"];
  }
  return out;
}
```

> Graph pagina con `@odata.nextLink`; mientras haya `nextLink`, sigue el enlace tal cual (no rehagas el query string).

### 9.3 Estrategia por tipo de dato

| Dato | ¿La API guarda histórico? | Estrategia para mensual/trimestral/anual |
|---|---|---|
| Incidentes/alertas | Sí, según retención del tenant | Query directa con `$filter` por ventana. Para evitar re-leer todo, guarda `id`+`lastUpdateDateTime` y re-consulta solo los actualizados |
| Informes TI (artículos/IOCs) | Sí (`createdDateTime`, `lastUpdatedDateTime`) | Query directa por fecha; para el cruce con tu red, archiva IOCs diarios |
| Vulnerabilidades por equipo | **No** (solo snapshot actual) | Snapshots programados (full semanal + delta diario) guardados por tu app |
| Secure Score | Sí (una entrada por periodo) | `GET /security/secureScores` y selecciona los periodos |
| Hunting (raw events) | Solo 30 días | Queries agregadas diarias/semanales → tu BD → composición mensual/anual |

### 9.4 Idea de pipeline de reporte periódico

```
┌─ Diario (cron 06:00) ──────────────────────────────┐
│ 1. Artículos TI nuevos + IOCs        → BD propia   │
│ 2. Incidentes/alertas del día        → BD propia   │
│ 3. Delta de vulnerabilidades         → BD propia   │
│ 4. Hunting: agregados del día        → BD propia   │
└────────────────────────────────────────────────────┘
┌─ Mensual/Trimestral/Anual ─────────────────────────┐
│ Composición desde tu BD:                            │
│  • Incidentes por severidad/estado/tendencia        │
│  • Top amenazas detectadas (hunting agregado)       │
│  • Evolución de vulnerabilidades y Secure Score     │
│  • Cruce IOCs ↔ incidentes ("¿nos afectó?")          │
│  • Informes TI del periodo archivados               │
└────────────────────────────────────────────────────┘
```

---

## 10. Permisos y consentimiento: checklist resumida

Todos son **application permissions** (requieren **admin consent**):

| Permiso | Habilita | Admin consent |
|---|---|---|
| `ThreatIntelligence.Read.All` | Informes TI, IOCs, CVEs, intel profiles ✅ (ya concedido) | Sí |
| `SecurityIncident.Read.All` | Incidentes (y sus alertas con `$expand`) | Sí |
| `SecurityAlert.Read.All` | Alertas `alerts_v2` | Sí |
| `Machine.Read.All` | Inventario de equipos | Sí |
| `Vulnerability.Read.All` | Vulnerabilidades TVM, export assessments, certificados | Sí |
| `Software.Read.All` | Inventario de software/hardware | Sí |
| `SecurityEvents.Read.All` | Secure Score | Sí |
| `ThreatHunting.Read.All` | runHuntingQuery (KQL) | Sí |

Delegados equivalentes (si algún día añades login de usuario): `SecurityIncident.Read.All`, `SecurityAlert.Read.All`… con roles Entra *Security Reader / Security Operator / Security Administrator*.

---

## 11. Seguridad y operación

- **Secreto**: variable de entorno o Key Vault; rotación programada (anota la fecha de expiración del secreto). `AADSTS7000215` en producción = secreto caducado/rotado.
- **Mínimo privilegio**: concede solo los permisos de las vistas que uses. `ThreatIntelligence.Read.All` es de solo lectura; `Vulnerability.Read.All`/`Machine.Read.All` también.
- **Throttling**: maneja `429` + `Retry-After` en todas las llamadas (helper en §3.4).
- **Multi-tenant** (si la app atiende a varios clientes): registra la app como "Accounts in any organizational directory" y consentimiento por tenant con `GET /{tenantId}/adminconsent`; patrón documentado para MSSPs.
- **Verificación en el portal de Defender** (tenant de producción): Settings → Endpoints → APIs habilitado; revisa si hay restricciones RBAC/grupos de dispositivos que excluyan a la app.

---

## 12. Referencias oficiales

- [Graph Threat Intelligence overview](https://learn.microsoft.com/graph/api/resources/security-threatintelligence-overview?view=graph-rest-1.0) · [article resource](https://learn.microsoft.com/graph/api/resources/security-article?view=graph-rest-1.0) · [article indicators](https://learn.microsoft.com/graph/api/security-article-list-indicators?view=graph-rest-1.0) · [intelProfiles + indicators](https://learn.microsoft.com/graph/api/security-intelligenceprofile-list-indicators?view=graph-rest-1.0)
- [List incidents](https://learn.microsoft.com/graph/api/security-list-incidents?view=graph-rest-1.0) · [List alerts_v2](https://learn.microsoft.com/graph/api/security-list-alerts_v2?view=graph-rest-1.0)
- [runHuntingQuery (Graph)](https://learn.microsoft.com/graph/api/security-security-runhuntingquery?view=graph-rest-1.0) · [Advanced hunting schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables) · [API heredada en retirada](https://learn.microsoft.com/defender-xdr/api-advanced-hunting)
- [List machines](https://learn.microsoft.com/defender-endpoint/api/get-machines) · [Vulnerabilities by machine](https://learn.microsoft.com/defender-endpoint/api/get-all-vulnerabilities-by-machines) · [Vulnerability resource](https://learn.microsoft.com/defender-endpoint/api/vulnerability) · [Export assessments](https://learn.microsoft.com/defender-endpoint/api/get-assessment-methods-properties) · [Software vulnerabilities export](https://learn.microsoft.com/defender-endpoint/api/get-assessment-software-vulnerabilities)
- [List secureScores](https://learn.microsoft.com/graph/api/security-list-securescores?view=graph-rest-1.0) · [Secure Score](https://learn.microsoft.com/defender-xdr/microsoft-secure-score)
- [Defender XDR prerequisites (licencias)](https://learn.microsoft.com/defender-xdr/prerequisites) · [FAQ licencias](https://learn.microsoft.com/defender-xdr/m365d-enable-faq)
- [Graph permissions reference](https://learn.microsoft.com/graph/permissions-reference) · [Threat analytics](https://learn.microsoft.com/defender-xdr/threat-analytics)