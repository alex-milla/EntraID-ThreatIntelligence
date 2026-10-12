# EntraID Threat Intelligence Platform

Plataforma web modular para la extracción de datos de ciberseguridad desde Microsoft Graph (multi-tenant) con generación de reportes periódicos, exportación STIX/MISP y asistencia LLM.

Diseñada para **hosting compartido con PHP** (7.4+ / probada en 8.4) y **SQLite**, sin dependencias de Composer ni build step.

## Estructura

```
public_html/                 # Aplicación
    ├── index.php             # Front controller
    ├── admin/                # Panel de administración
    ├── api/                  # API REST
    ├── config/               # Configuración, .env, esquema SQLite
    ├── includes/             # Router, auth, cifrado AES-256, cliente Graph
    ├── modules/              # Módulos (una herramienta por directorio)
    │   ├── graph_connector/    # Conexión/test de tenants
    │   ├── threat_intelligence/ # IOCs, intel profiles, CVEs
    │   ├── incidents/          # Incidentes de seguridad
    │   ├── vulnerabilities/   # TVM (vulnerabilidades de equipos)
    │   ├── secure_score/       # Secure Score
    │   ├── hunting/           # Advanced Hunting (KQL)
    │   ├── reports/           # Reportes periódicos (diario → anual)
    │   ├── llm/               # Asistencia LLM (OpenAI/Anthropic/Ollama/Azure)
    │   └── export/           # Exportación STIX 2.1 / MISP / CSV / TXT
    ├── views/                # Plantillas PHP
    ├── assets/               # CSS/JS
    ├── storage/              # SQLite, caché y exports (protegido)
    └── cron/                 # Sincronización programada
```

## Seguridad

- Secretos de tenants cifrados con **AES-256-CBC** en la base de datos
- Credenciales solo en `.env` (nunca en texto plano en el código)
- Protección CSRF, sesiones seguras, control de roles (admin/analista/visor)
- `storage/` denegado vía `.htaccess`

## Instalación

Ver `public_html/INSTRUCCIONES-DESPLIEGUE.md`. Resumen:

1. Subir el contenido de `public_html/` al hosting
2. Ejecutar `/setup.php` (verifica requisitos, genera `.env` con claves, crea la BD)
3. Probar `.htaccess` (limpio) o modo sin rewrite (`FORCE_NO_REWRITE=true`)
4. Login `admin`/`admin` → cambiar contraseña
5. **Borrar `setup.php` y `diagnostic.php` del servidor**

## Estado

Funcional en hosting compartido. El módulo Graph Connector permite registrar múltiples tenants (o grupos multitenant de una misma empresa) con sus datos siempre separados.
