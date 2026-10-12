# Instrucciones de despliegue — graph.cibersecurity.io

## Paso 1: Subir archivos

Sube TODO el contenido de `public_html/` a la raíz de tu hosting.

Archivos clave que DEBES subir:
```
├── .htaccess.recommended   ← renómbralo a .htaccess (ver Paso 3)
├── .htaccess.minimal       ← alternativa si .recommended da 403
├── .env.example            ← referencia (no lo uses directamente)
├── index.php               ← front controller
├── setup.php               ← EJECUTAR PRIMERO (luego borrar)
├── diagnostic.php          ← solo si hay problemas (luego borrar)
├── admin/index.php         ← panel admin (routing propio)
├── api/index.php           ← API REST (routing propio)
├── config/                 ← configuración
├── includes/               ← clases y helpers
├── modules/                ← módulos de la aplicación
├── views/                  ← plantillas HTML
├── assets/                 ← CSS, JS, imágenes
├── storage/                ← BD y caché (proteger con permisos)
│   ├── cache/
│   └── exports/
└── cron/sync.php           ← sincronización programada
```

## Paso 2: Ejecutar setup.php (OBLIGATORIO)

1. Abre en el navegador: `http://graph.cibersecurity.io/setup.php`
2. El script:
   - Verifica PHP >= 7.4 y extensiones (pdo_sqlite, curl, openssl, mbstring, json, session)
   - Crea los directorios `storage/cache/` y `storage/exports/`
   - Genera el archivo `.env` con claves seguras aleatorias (ENCRYPTION_KEY, SESSION_SECRET)
   - Inicializa la base de datos SQLite con todas las tablas
   - Registra los módulos y crea el usuario admin
3. Si todo sale verde → continúa al Paso 3
4. Si hay errores rojos → corrígelos primero (ver "Solución de problemas")
5. **BORRA `setup.php` del servidor** (seguridad)

## Paso 3: Configurar .htaccess (elige UNA opción)

Tienes 3 versiones. Pruébalas en este orden:

### Opción A: .htaccess.recommended (RECOMENDADA)
```bash
# En el servidor, renombra:
mv .htaccess.recommended .htaccess
```
- Tiene seguridad (bloquea .env, storage/, config/, etc.)
- Sin directivas problemáticas (no usa php_flag, Options -Indexes)
- Prueba: `http://graph.cibersecurity.io/admin/login`
  - Si funciona → LISTO, URLs limpias
  - Si da 403 → pasa a Opción B
  - Si da 404 → pasa a Opción C

### Opción B: .htaccess.minimal (ULTRA BÁSICA)
```bash
# En el servidor, renombra:
mv .htaccess.minimal .htaccess
```
- Solo tiene RewriteEngine (sin seguridad adicional)
- Máxima compatibilidad
- Prueba: `http://graph.cibersecurity.io/admin/login`
  - Si funciona → LISTO (pero añade protección manual a storage/)
  - Si da 403 → pasa a Opción C
  - Si da 404 → mod_rewrite no disponible, pasa a Opción C

### Opción C: Sin .htaccess (MODO COMPATIBILIDAD TOTAL)
```bash
# En el servidor, asegúrate de que NO hay .htaccess:
rm .htaccess
# o renómbralo:
mv .htaccess .htaccess.disabled
```
1. Edita el archivo `.env` en el servidor y añade:
   ```
   FORCE_NO_REWRITE=true
   ```
2. Las URLs cambiarán automáticamente a:
   - Login: `http://graph.cibersecurity.io/admin/index.php/login`
   - Dashboard: `http://graph.cibersecurity.io/admin/index.php`
   - API: `http://graph.cibersecurity.io/api/index.php/tenants`
3. **IMPORTANTE:** Protege manualmente el directorio `storage/`:
   - En cPanel: marca `storage/` como "no listable" y deniega acceso web
   - O sube un `.htaccess` SOLO en `storage/` con: `Require all denied`

## Paso 4: Primer acceso

1. Ve a la URL de login según tu opción:
   - Opción A/B: `http://graph.cibersecurity.io/admin/login`
   - Opción C: `http://graph.cibersecurity.io/admin/index.php/login`
2. Inicia sesión con:
   - **Usuario:** `admin`
   - **Contraseña:** `admin`
3. **Cambia la contraseña inmediatamente** (el sistema te obligará)

## Paso 5: Configurar el primer tenant

1. Ve a **Admin → Tenants → Nuevo tenant**
2. Rellena:
   - **Nombre:** ej. "Empresa Pepito"
   - **Slug:** ej. "empresa-pepito" (se genera automático)
   - **Tenant ID:** el GUID de tu tenant de Azure AD (Directory ID)
   - **Client ID:** el Application (client) ID de tu app registration
   - **Client Secret:** el secret generado en Azure Portal
   - **Permisos:** selecciona los que necesites (ThreatIntelligence, Incidentes, etc.)
3. Guarda → el secret se cifra automáticamente con AES-256
4. Prueba la conexión desde el módulo Graph Connector

## Paso 6: Verificar diagnóstico (solo si algo falla)

```
http://graph.cibersecurity.io/diagnostic.php
```

Te dice exactamente qué falla. **BÓRRALO después de usarlo.**

## Solución de problemas

| Síntoma | Causa probable | Solución |
|---------|---------------|----------|
| 403 Forbidden | .htaccess bloqueado | Usa .htaccess.minimal o Opción C |
| 500 Internal Server Error | Falta .env, permisos, o extensión PHP | Ejecuta setup.php o diagnostic.php |
| 404 en /admin/login | mod_rewrite no habilitado | Opción C (FORCE_NO_REWRITE=true) |
| Pantalla en blanco | Error PHP oculto | Pon APP_DEBUG=true en .env temporalmente |
| No puedo escribir en storage/ | Permisos incorrectos | chmod 755 en storage/, storage/cache/, storage/exports/ |
| .env accesible vía web | Falta protección | Añade .htaccess o renombra .env a .env.local |
| Error de cifrado | ENCRYPTION_KEY vacía | Ejecuta setup.php para generar claves |

## Seguridad — Checklist post-instalación

- [ ] Borrar `setup.php` del servidor
- [ ] Borrar `diagnostic.php` del servidor
- [ ] Cambiar contraseña del usuario `admin`
- [ ] Verificar que `.env` NO es accesible: probar `http://graph.cibersecurity.io/.env` → debe dar 403/404
- [ ] Verificar que la BD no es descargable: `http://graph.cibersecurity.io/storage/database.sqlite` → debe dar 403/404
- [ ] `APP_DEBUG=false` en `.env`
- [ ] `APP_URL` en `.env` coincide con tu dominio real (http vs https)

## Configurar cron (sincronización automática)

```bash
# Vía CLI (si el hosting lo permite)
php /ruta/completa/public_html/cron/sync.php

# Vía web (con token del .env)
http://graph.cibersecurity.io/cron/sync.php?token=TU_CRON_TOKEN
```

Frecuencia recomendada: cada hora (`0 * * * *`)

## Estructura de URLs según modo

| Modo | Login | Dashboard | API Tenants |
|------|-------|-----------|-------------|
| A/B (con rewrite) | `/admin/login` | `/admin` | `/api/tenants` |
| C (sin rewrite) | `/admin/index.php/login` | `/admin/index.php` | `/api/index.php/tenants` |
