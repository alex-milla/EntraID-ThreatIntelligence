<?php
/**
 * Configuración general de la aplicación.
 * Carga variables desde .env y define constantes globales.
 */

declare(strict_types=1);

// ============================================================
// Carga de variables de entorno desde .env
// ============================================================

function loadEnv(string $path): array
{
    if (!file_exists($path)) {
        return [];
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $env = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        if (!str_contains($line, '=')) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);
        // Quitar comillas
        if (strlen($value) >= 2) {
            $first = $value[0];
            $last = $value[strlen($value) - 1];
            if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) {
                $value = substr($value, 1, -1);
            }
        }
        $env[$key] = $value;
        // También como variable de entorno real
        if (!getenv($key)) {
            putenv("$key=$value");
        }
        $_ENV[$key] = $value;
    }
    return $env;
}

// ============================================================
// Definición de rutas
// ============================================================

define('ROOT_PATH', dirname(__DIR__));
define('CONFIG_PATH', ROOT_PATH . '/config');
define('INCLUDES_PATH', ROOT_PATH . '/includes');
define('MODULES_PATH', ROOT_PATH . '/modules');
define('VIEWS_PATH', ROOT_PATH . '/views');
define('STORAGE_PATH', ROOT_PATH . '/storage');
define('CACHE_PATH', STORAGE_PATH . '/cache');
define('EXPORTS_PATH', STORAGE_PATH . '/exports');
define('ASSETS_PATH', ROOT_PATH . '/assets');

// ============================================================
// Cargar .env
// ============================================================

$envFile = ROOT_PATH . '/.env';
$env = loadEnv($envFile);

// ============================================================
// Constantes de aplicación
// ============================================================

define('APP_NAME', $env['APP_NAME'] ?? 'EntraID Threat Intelligence');
define('APP_ENV', $env['APP_ENV'] ?? 'production');
define('APP_DEBUG', ($env['APP_DEBUG'] ?? 'false') === 'true');
define('APP_URL', rtrim($env['APP_URL'] ?? '', '/'));
define('APP_TIMEZONE', $env['APP_TIMEZONE'] ?? 'Europe/Madrid');

// Versión instalada (fuente única: fichero VERSION)
$appVersionFile = ROOT_PATH . '/VERSION';
define('APP_VERSION', is_file($appVersionFile) ? (trim((string)@file_get_contents($appVersionFile)) ?: '0.0.0') : '0.0.0');

// Seguridad
define('ENCRYPTION_KEY', $env['ENCRYPTION_KEY'] ?? '');
define('SESSION_SECRET', $env['SESSION_SECRET'] ?? bin2hex(random_bytes(32)));

// Base de datos
define('DB_PATH', ROOT_PATH . '/' . ($env['DB_PATH'] ?? 'storage/database.sqlite'));

// Catálogo público de CVEs (base de datos independiente, opcional)
define('CVE_DB_PATH', ROOT_PATH . '/' . ($env['CVE_DB_PATH'] ?? 'storage/cve.sqlite'));

// Fuentes públicas de CVEs
define('CVE_NVD_URL', 'https://services.nvd.nist.gov/rest/json/cves/2.0');
define('CVE_CPE_URL', 'https://services.nvd.nist.gov/rest/json/cpes/2.0');
define('CVE_KEV_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
define('CVE_KEV_FALLBACK_URL', 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json');
define('CVE_EPSS_CSV_URL', 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz');
define('CVE_NVD_API_KEY', $env['NVD_API_KEY'] ?? '');
define('CVE_NVD_PAGE_SIZE', 2000);
define('CVE_SYNC_BUDGET', 25);
define('CVE_SYNC_STALE', 180);
define('CVE_SYNC_WATCHDOG', 900);
define('CVE_CRON_ACTIVE_GRACE', 45);
define('CVE_REPORT_MAX_ROWS', 5000);
// NVD API 2.0: 5 peticiones/30 s sin API key y 50/30 s con API key.
define('CVE_NVD_RATE_WINDOW', 30);
define('CVE_NVD_RATE_MAX', 0); // 0 = automático según la API key
define('CVE_SYNC_MAX_RETRIES', 4);
define('CVE_NVD_MAX_PAGE_SIZE', 2000);
define('CVE_PAGE_SIZE_MEMORY_GUARD', 268435456); // <256M => página de 1000
// Tramos de la descarga continua por web (segundos por petición HTTP).
define('CVE_STEP_SECONDS', 45);
define('CVE_STEP_SECONDS_MAX', 90);

// LLM
define('LLM_PROVIDER', $env['LLM_PROVIDER'] ?? '');
define('LLM_API_KEY', $env['LLM_API_KEY'] ?? '');
define('LLM_API_URL', $env['LLM_API_URL'] ?? '');
define('LLM_MODEL', $env['LLM_MODEL'] ?? '');
define('LLM_MAX_TOKENS', (int)($env['LLM_MAX_TOKENS'] ?? 2048));

// Cron
define('CRON_TOKEN', $env['CRON_TOKEN'] ?? '');
define('CRON_SYNC_INTERVAL', (int)($env['CRON_SYNC_INTERVAL'] ?? 3600));

// ============================================================
// Detectar si mod_rewrite está disponible
// ============================================================

$hasRewrite = false;
if (function_exists('apache_get_modules')) {
    $hasRewrite = in_array('mod_rewrite', apache_get_modules());
} else {
    // REDIRECT_URL solo existe cuando Apache reescribió la petición actual.
    // PATH_INFO NO indica rewrite: aparece también al entrar por /admin/index.php/login
    $hasRewrite = isset($_SERVER['REDIRECT_URL']);
}
// Permitir forzar modo sin rewrite desde .env
$forceNoRewrite = ($env['FORCE_NO_REWRITE'] ?? 'false') === 'true';
define('HAS_MOD_REWRITE', $hasRewrite && !$forceNoRewrite);

// ============================================================
// Configuración de zona horaria y errores
// ============================================================

date_default_timezone_set(APP_TIMEZONE);

if (APP_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    // E_STRICT fue eliminado en PHP 8.0; sus avisos ahora son E_DEPRECATED/E_WARNING
    error_reporting(E_ALL & ~E_DEPRECATED);
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    ini_set('error_log', STORAGE_PATH . '/php_errors.log');
}

// ============================================================
// Constantes de Microsoft Graph
// ============================================================

define('GRAPH_AUTHORITY_BASE', 'https://login.microsoftonline.com/');
define('GRAPH_TOKEN_PATH', '/oauth2/v2.0/token');
define('GRAPH_BASE_URL', 'https://graph.microsoft.com/v1.0/');
define('GRAPH_SCOPE', 'https://graph.microsoft.com/.default');

// Defender for Endpoint (audience diferente)
define('MDE_BASE_URL', 'https://api.security.microsoft.com/');
define('MDE_SCOPE', 'https://api.security.microsoft.com/.default');

// Token cache: 55 minutos (el token dura 1h)
define('TOKEN_CACHE_TTL', 55 * 60);

// ============================================================
// Permisos de aplicación disponibles por módulo
// ============================================================

define('GRAPH_PERMISSIONS', [
    'ThreatIntelligence.Read.All' => 'Informes TI, IOCs, CVEs, intel profiles',
    'SecurityIncident.Read.All'   => 'Incidentes de seguridad',
    'SecurityAlert.Read.All'      => 'Alertas de seguridad (alerts_v2)',
    'Machine.Read.All'            => 'Inventario de equipos (Defender for Endpoint)',
    'Vulnerability.Read.All'      => 'Vulnerabilidades TVM',
    'Software.Read.All'           => 'Inventario de software/hardware',
    'SecurityEvents.Read.All'     => 'Secure Score',
    'ThreatHunting.Read.All'      => 'Advanced Hunting (KQL)',
]);

// ============================================================
// Mapeo TLP para STIX
// ============================================================

define('TLP_MARKINGS', [
    'white' => 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    'green' => 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    'amber' => 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    'red'   => 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
]);

// Mapeo TLP para MISP distribution
define('MISP_TLP_DISTRIBUTION', [
    'white' => '3', // All communities
    'green' => '2', // Connected communities
    'amber' => '1', // This community only
    'red'   => '0', // Your organisation only
]);

// ============================================================
// Sectores (filtro de Threat Intelligence por sector)
// label => palabras clave que se buscan en título/resumen/cuerpo/tags
// ============================================================

define('SECTORS', [
    'Finanzas'    => ['financial', 'finance', 'bank', 'banking', 'fintech', 'payment', 'insurance'],
    'Salud'       => ['health', 'hospital', 'medical', 'pharma', 'clinic'],
    'Energía'     => ['energy', 'oil', 'gas', 'utility', 'utilities', 'power grid', 'electric', 'nuclear'],
    'Gobierno'    => ['government', 'public sector', 'ministry', 'federal', 'state-sponsored', 'military', 'defense'],
    'Manufactura' => ['manufactur', 'industrial', 'factory', 'scada', 'operational technology', 'plc'],
    'Educación'   => ['university', 'education', 'school', 'academic'],
    'Retail'      => ['retail', 'e-commerce', 'ecommerce', 'commerce', 'point of sale'],
    'Tecnología'  => ['technology', 'software', 'saas', 'cloud', 'developer', 'npm', 'open source', 'supply chain'],
    'Telecom'     => ['telecom', 'isp', 'mobile network', '5g'],
]);

// Mapeo del campo "industry" de Microsoft Graph (/organization) a un sector de arriba
define('SECTOR_INDUSTRY_MAP', [
    'financ'     => 'Finanzas',
    'bank'       => 'Finanzas',
    'insurance'  => 'Finanzas',
    'health'     => 'Salud',
    'energy'     => 'Energía',
    'utilit'     => 'Energía',
    'oil'        => 'Energía',
    'gas'        => 'Energía',
    'government' => 'Gobierno',
    'public'     => 'Gobierno',
    'manufactur' => 'Manufactura',
    'industrial' => 'Manufactura',
    'educat'     => 'Educación',
    'retail'     => 'Retail',
    'commerce'   => 'Retail',
    'technolog'  => 'Tecnología',
    'software'   => 'Tecnología',
    'information'=> 'Tecnología',
    'telecom'    => 'Telecom',
]);

// ============================================================
// Threat Intelligence — taxonomía canónica de "targets" (MDTI)
// Industrias y regiones tal y como las expone el portal de Microsoft
// (Intel explorer → Target industries / Target regions).
// ============================================================

define('TI_TARGET_INDUSTRIES', [
    'Education',
    'Other business entities',
    'Financial Services',
    'Information Technology',
    'Government Agencies & Services',
    'Critical Manufacturing',
    'Healthcare & public health',
    'Communications infrastructure',
    'Transportation Systems',
    'Consumer Retail',
    'Energy',
    'Water & Wastewater System',
    'Commercial Facilities',
    'Food and Agriculture',
    'Inter-Governmental Organization',
    'Non-Government Organization',
    'Digital, Print and Broadcast Media',
    'Natural Resources',
    'Defense Industrial Base',
    'Emergency Services',
    'Private Consumer Accounts',
    'Political and other groups',
    'Government Facilities',
]);

define('TI_TARGET_REGIONS', [
    'Central America and the Caribbean',
    'Central Asia',
    'East Asia',
    'Eastern Europe',
    'Middle East',
    'North Africa',
    'North America',
    'Northern Europe',
    'Oceania',
    'South America',
    'Sub-Saharan Africa',
    'Western Europe',
]);

// Regiones adicionales que Graph puede devolver (no canónicas): se siguen
// tratando como región y se conservan para no perder información.
define('TI_TARGET_REGION_EXTRAS', [
    'Central Europe',
    'Southern Europe',
    'South Asia',
    'Southeast Asia',
    'Africa',
    'Europe',
    'Asia',
    'Latin America',
    'Middle East and North Africa',
]);

// Ingesta inicial de indicadores de Threat Intelligence.
define('TI_INDICATORS_FULL_LIMIT', 20000); // máximo total de la carga inicial
define('TI_INDICATORS_FULL_DAYS', 90);     // solo indicadores con actividad reciente

// Sincronización en segundo plano (job encadenado vía PHP-FPM).
define('SYNC_JOB_BUDGET', 35);        // segundos de trabajo por ejecución del worker
define('SYNC_JOB_MAX_SECONDS', 1800); // tope total de un job (30 min)
define('SYNC_JOB_STALE', 90);         // segundos sin actualizar => se relanza el worker
define('SYNC_JOB_WATCHDOG', 300);     // segundos sin avanzar => el job se marca como error

// Seguridad de accesos (detección de fuerza bruta).
define('LOGIN_BRUTE_THRESHOLD', 10);  // fallos por IP en la ventana => IP sospechosa
define('LOGIN_BRUTE_WINDOW_MIN', 60); // ventana de detección (minutos)
define('LOGIN_RETENTION_DAYS', 90);   // retención de los registros de acceso
