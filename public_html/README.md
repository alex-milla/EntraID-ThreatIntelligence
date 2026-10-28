# ============================================================
# README — EntraID Threat Intelligence Platform
# ============================================================

Plataforma web multi-tenant para extracción de datos de Microsoft Graph
(Microsoft Defender XDR, Threat Intelligence, Secure Score, etc.) con
almacenamiento SQLite y arquitectura modular.

## Requisitos

- PHP 8.1+ con extensiones: `pdo_sqlite`, `curl`, `openssl`, `mbstring`, `json`
- Hosting compartido con Apache + mod_rewrite
- Cuenta de Microsoft Entra ID con app registrada (multi-tenant)

## Instalación

1. **Subir archivos** a `public_html/` en tu hosting.

2. **Configurar entorno:**
   ```bash
   cp .env.example .env
   # Editar .env y configurar:
   #   - ENCRYPTION_KEY (genera con: php -r "echo base64_encode(random_bytes(32));")
   #   - SESSION_SECRET
   #   - APP_URL (URL pública de la app)
   ```

3. **Permisos:**
   ```bash
   chmod 750 storage/
   chmod 640 .env
   ```

4. **Acceder** a la app. Usuario por defecto: `admin` / `admin`
   (cambiar inmediatamente).

5. **Configurar tenants** en Admin → Tenants. Cada tenant necesita:
   - Tenant ID (Directory ID de Entra)
   - Client ID (Application ID de la app registrada)
   - Client Secret (Value, no el Secret ID)
   - Permisos de aplicación concedidos (admin consent)

6. **Configurar cron** (opcional, para sincronización automática):
   ```
   0 * * * * php /ruta/public_html/cron/sync.php >> /ruta/storage/cron.log 2>&1
   ```

7. **Catálogo CVE (opcional)**: en Admin → APIs → *Fuentes públicas de CVEs*
   puedes guardar la API key de NVD y probar NVD/CISA KEV/EPSS. El catálogo
   se guarda en `storage/cve.sqlite` (`CVE_DB_PATH` en `.env`), separado de la
   base de datos principal. La descarga se lanza desde **Seguridad → CVE →
   Catálogo → Actualizar catálogo**: usa el modo incremental si ya hay catálogo
   y **Reconstruir** para volver a descargarlo completo. Tras cada actualización
   se sincronizan también **CISA KEV** y **EPSS**; el botón **KEV / EPSS**
   permite actualizarlos sin tocar NVD. El progreso se muestra en el badge
   **CVE** del sidebar en cualquier pantalla.
   El catálogo permite filtrar por grupo, por software, por «Solo mis
   productos», KEV y EPSS mínimo, y ordenar por CVSS, EPSS o KEV. La vista
   **Mi software** muestra por producto los CVEs, KEV y EPSS altos que le
   afectan.
   La pestaña **Informes** genera informes preventivos por todo el inventario,
   un grupo o un software, con periodo de 7/30/90 días o histórico. Ordena por
   KEV &gt; EPSS &gt; CVSS, permite filtrar por severidad, KEV y EPSS mínimo,
   y exporta a CSV o a PDF mediante la impresión del navegador.
   En **Mi software** puedes buscar CPE en NVD, añadir varios CPE por producto
   y lanzar un backfill automático al guardar. Si el hosting no permite el worker
   en segundo plano, usa **Continuar** para procesar tramos manualmente.
   Si CISA bloquea la IP del hosting (HTTP 403), KEV usa automáticamente el
   mirror oficial de GitHub (`cisagov/kev-data`).

8. **Cron CVE** (opcional): sincroniza el catálogo incremental y actualiza
   KEV/EPSS sin depender del navegador. Ejecuta una vez al día:
   ```
   php /ruta/public_html/cron/cve-sync.php --mode=auto --max-seconds=240 >> /ruta/public_html/storage/cve-cron.log 2>&1
   ```
   Si la primera carga completa no termina en una ejecución, el proceso queda
   en estado parcial y la siguiente ejecución lo reanuda. Añade `--report` para
   generar además un informe de los últimos 7 días:
   ```
   php /ruta/public_html/cron/cve-sync.php --report --report-period=7d
   ```
   También puede llamarse por URL con `CRON_TOKEN`:
   ```
   https://tu-dominio.com/cron/cve-sync.php?token=TU_CRON_TOKEN&report=1
   ```
   Opciones de informe: `--report-scope=all|group|software`,
   `--report-group=ID`, `--report-software=ID`,
   `--report-period=7d|30d|90d|all`, `--report-severity=Critical`,
   `--report-kev=1` y `--report-epss=0.10`.

9. **Cron Vulnrichment SSVC** (opcional): rellena los puntos SSVC de CISA
   (`Exploitation`, `Automatable`, `Technical Impact`) de los CVEs asignados a
   informes y de los que casan con el inventario. Ejecuta una vez al día o cada
   pocas horas; es incremental y respeta una caché de 30 días:
   ```
   php /ruta/public_html/cron/cve-vulnrichment.php --limit=200 >> /ruta/public_html/storage/cve-vulnrichment.log 2>&1
   ```
   Sin este cron, la ficha y el análisis de grupo siguen funcionando: usan la
   caché disponible o una estimación marcada como «estimado». También admite
   `?token=TU_CRON_TOKEN` y `--force=1`.

10. **Cron ThreatFox** (opcional): ingesta diaria de IOCs de abuse.ch en la base
    local del módulo **IOCs ThreatFox**. Requiere una Auth-Key gratuita de
    <https://auth.abuse.ch/>: se configura en **Administración → APIs** (se
    guarda cifrada) o con `THREATFOX_AUTH_KEY` en el `.env`, que tiene prioridad:
    ```
    php /ruta/public_html/cron/threatfox-ingest.php --days=1 >> /ruta/public_html/storage/threatfox-cron.log 2>&1
    ```
    Es idempotente: reingestar nunca duplica. Añade `--purge` para borrar los
    IOCs con más de 6 meses (la fuente los expira) y `--backfill` para forzar el
    histórico completo desde CLI. También admite `?token=TU_CRON_TOKEN`.
    El módulo arranca con datos si copias una base ya poblada en
    `storage/threatfox.sqlite`; si no existe, se crea vacía con la primera
    ingesta. Desde la interfaz también se puede lanzar la ingesta y la descarga
    completa (~6 meses) por bloques.

## Arquitectura modular

Cada herramienta es un módulo independiente en `modules/{nombre}/`:

| Módulo | Descripción | Permisos Graph |
|---|---|---|
| `graph_connector` | Gestión de conexión y tenants | — |
| `threat_intelligence` | Informes TI, IOCs, CVEs | `ThreatIntelligence.Read.All` |
| `incidents` | Incidentes y alertas | `SecurityIncident.Read.All`, `SecurityAlert.Read.All` |
| `vulnerabilities` | Equipos y vulnerabilidades (TVM) | `Machine.Read.All`, `Vulnerability.Read.All` |
| `cve` | Catálogo público de CVEs e inventario de software (NVD/KEV/EPSS) | — |
| `secure_score` | Evolución del Secure Score | `SecurityEvents.Read.All` |
| `hunting` | Consultas KQL (Advanced Hunting) | `ThreatHunting.Read.All` |
| `threatfox` | IOCs de abuse.ch (ThreatFox): consulta, ingesta y export STIX/MISP | — |
| `reports` | Generación de reportes periódicos | — (usa datos almacenados) |
| `llm` | Análisis con modelos de lenguaje | — (usa API del proveedor) |
| `export` | Exportación STIX 2.1, MISP, CSV, TXT | — |

### Añadir un nuevo módulo

1. Crear directorio `modules/mi_modulo/`
2. Crear `modules/mi_modulo/module.php` con clase `Module_MiModulo extends BaseModule`
3. Implementar los métodos de `ModuleInterface`
4. El módulo se registra automáticamente en la BD al primer arranque

## Seguridad

- **Secretos cifrados:** los `client_secret` de los tenants se cifran con
  AES-256-CBC antes de almacenarse en SQLite. La clave vive en `.env`.
- **CSRF:** todas las peticiones POST/DELETE requieren token CSRF.
- **Sesiones seguras:** cookies HttpOnly, SameSite=Strict, regeneración periódica.
- **.htaccess:** bloquea acceso a `.env`, `storage/`, `config/`, `includes/`, etc.
- **SQL:** todas las consultas usan prepared statements (PDO).
- **XSS:** todo output se escapa con `e()` (htmlspecialchars).
- **Headers:** CSP, X-Frame-Options, X-Content-Type-Options, etc.

## Estructura de directorios

```
public_html/
├── .htaccess              # Seguridad y rewrite
├── .env.example           # Plantilla de configuración
├── .gitignore
├── index.php              # Front controller
├── cve-worker.php         # Worker de descarga del catálogo NVD
├── config/
│   ├── config.php         # Constantes y carga de .env
│   ├── database.php       # Esquema SQLite + clase Database
│   └── bootstrap.php      # Inicialización
├── includes/
│   ├── auth.php           # Autenticación de usuarios
│   ├── csrf.php           # Protección CSRF
│   ├── encryption.php     # AES-256-CBC
│   ├── session.php        # Gestión de sesiones
│   ├── router.php         # Router
│   ├── helpers.php        # Funciones auxiliares
│   ├── graph_client.php   # Cliente Microsoft Graph
│   ├── cve_database.php   # Base SQLite del catálogo CVE
│   ├── cve_client.php     # Cliente NVD/KEV/EPSS
│   ├── cve_sync.php       # Motor de descarga y matching
│   ├── tenant_manager.php # CRUD de tenants
│   └── module_manager.php # Gestor de módulos
├── modules/               # Módulos (uno por herramienta)
│   ├── module_interface.php
│   ├── graph_connector/
│   ├── threat_intelligence/
│   ├── incidents/
│   ├── vulnerabilities/
│   ├── cve/
│   ├── secure_score/
│   ├── hunting/
│   ├── reports/
│   ├── llm/
│   └── export/
├── admin/
│   └── index.php          # Controlador del panel admin
├── api/
│   └── index.php          # API REST
├── assets/
│   ├── css/style.css
│   └── js/app.js
├── views/
│   ├── layout/            # Header, sidebar, footer
│   ├── admin/             # Vistas del panel admin
│   ├── modules/           # Vistas de módulos
│   └── errors/            # 404, 500
├── storage/               # PROTEGIDO por .htaccess
│   ├── .htaccess
│   ├── database.sqlite    # (se crea automáticamente)
│   ├── cache/             # Caché de tokens
│   └── exports/           # Archivos exportados
└── cron/
    ├── sync.php           # Sincronización programada
    ├── cve-sync.php       # Sincronización CVE + KEV/EPSS + informes
    └── cve-vulnrichment.php # Puntos SSVC de CISA Vulnrichment
```

## Licencia

Uso interno. Copyright (c) 2026.
