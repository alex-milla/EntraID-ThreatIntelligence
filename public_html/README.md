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
   Catálogo → Descargar catálogo**. El progreso se muestra también en el badge
   **CVE** del sidebar en cualquier pantalla. Si el hosting no permite el worker
   en segundo plano, usa **Continuar** para procesar tramos manualmente.
   Si CISA bloquea la IP del hosting (HTTP 403), KEV usa automáticamente el
   mirror oficial de GitHub (`cisagov/kev-data`).

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
    └── sync.php           # Sincronización programada
```

## Licencia

Uso interno. Copyright (c) 2026.
