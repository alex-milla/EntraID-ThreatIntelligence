<?php
/**
 * Helpers — funciones auxiliares globales.
 */

declare(strict_types=1);

if (!function_exists('e')) {
    /**
     * Escapa HTML para prevenir XSS.
     */
    function e(?string $value): string
    {
        return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

if (!function_exists('env')) {
    /**
     * Obtiene una variable de entorno con valor por defecto.
     */
    function env(string $key, mixed $default = null): mixed
    {
        $value = $_ENV[$key] ?? getenv($key);
        if ($value === false || $value === null) {
            return $default;
        }
        return $value;
    }
}

if (!function_exists('json_response')) {
    /**
     * Envía una respuesta JSON y termina.
     */
    function json_response(mixed $data, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
        $json = json_encode($data, $flags);
        if ($json === false) {
            $json = json_encode(
                ['error' => 'No se pudo serializar la respuesta: ' . json_last_error_msg()],
                JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
            );
        }
        echo $json;
        exit;
    }
}

if (!function_exists('json_response_continue')) {
    /**
     * Envía una respuesta JSON y **cierra la respuesta al cliente** sin
     * terminar el script (fastcgi_finish_request o flush). El trabajo pesado
     * puede seguir en este mismo proceso: es el patrón de cve-worker.php y
     * evita depender de una petición HTTP a uno mismo.
     */
    function json_response_continue(mixed $data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

        $json = json_encode(
            $data,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
        );
        echo $json === false ? '{"success":false,"error":"No se pudo serializar la respuesta"}' : $json;

        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
            return;
        }
        while (ob_get_level() > 0) {
            @ob_end_flush();
        }
        @flush();
    }
}

if (!function_exists('redirect')) {
    /**
     * Redirige a una URL.
     */
    function redirect(string $url, int $status = 302): never
    {
        header("Location: $url", true, $status);
        exit;
    }
}

if (!function_exists('asset_url')) {
    /**
     * Genera URL para un asset estático.
     */
    function asset_url(string $path): string
    {
        return APP_URL . '/assets/' . ltrim($path, '/');
    }
}

if (!function_exists('base_url')) {
    /**
     * Genera URL base de la aplicación.
     * Compatible con y sin mod_rewrite.
     */
    function base_url(string $path = ''): string
    {
        $path = trim($path, '/');
        $base = rtrim(APP_URL, '/');

        // Con mod_rewrite: URLs limpias
        if (defined('HAS_MOD_REWRITE') && HAS_MOD_REWRITE) {
            return $base . ($path !== '' ? '/' . $path : '');
        }

        // Sin mod_rewrite: usar PATH_INFO
        if (str_starts_with($path, 'admin/') || $path === 'admin') {
            $subPath = $path === 'admin' ? '' : substr($path, 6);
            return $base . '/admin/index.php' . ($subPath !== '' ? '/' . ltrim($subPath, '/') : '');
        }
        if (str_starts_with($path, 'api/') || $path === 'api') {
            $subPath = $path === 'api' ? '' : substr($path, 4);
            return $base . '/api/index.php' . ($subPath !== '' ? '/' . ltrim($subPath, '/') : '');
        }
        // Raíz y otras rutas (módulos incluidos): estilo PATH_INFO
        if ($path === '') {
            return $base . '/';
        }
        return $base . '/index.php/' . $path;
    }
}

if (!function_exists('format_date')) {
    /**
     * Formatea una fecha ISO a formato legible.
     */
    function format_date(?string $date, string $format = 'd/m/Y H:i'): string
    {
        if (empty($date)) {
            return '—';
        }
        $ts = strtotime($date);
        return $ts === false ? '—' : date($format, $ts);
    }
}

if (!function_exists('format_db_date')) {
    /**
     * Formatea una fecha guardada por SQLite (UTC, sin zona) en hora local.
     * Evita el desfase de 1-2 h de interpretar «datetime('now')» como local.
     */
    function format_db_date(?string $date, string $format = 'd/m/Y H:i'): string
    {
        if ($date === null || trim($date) === '') {
            return '—';
        }
        $value = trim($date);
        if (!str_contains($value, 'T') && !str_ends_with($value, 'Z')) {
            $value .= ' UTC';
        }
        $ts = strtotime($value);
        return $ts === false ? '—' : date($format, $ts);
    }
}

if (!function_exists('time_ago')) {
    /**
     * Convierte una fecha a "hace X tiempo".
     */
    function time_ago(?string $date): string
    {
        if (empty($date)) {
            return '—';
        }
        $ts = strtotime($date);
        if ($ts === false) {
            return '—';
        }
        $diff = time() - $ts;
        if ($diff < 60) return 'hace ' . $diff . 's';
        if ($diff < 3600) return 'hace ' . floor($diff / 60) . ' min';
        if ($diff < 86400) return 'hace ' . floor($diff / 3600) . ' h';
        if ($diff < 604800) return 'hace ' . floor($diff / 86400) . ' días';
        return format_date($date);
    }
}

if (!function_exists('truncate')) {
    /**
     * Trunca un texto con elipsis.
     */
    function truncate(?string $text, int $length = 100, string $suffix = '...'): string
    {
        if ($text === null) return '';
        $len = function_exists('mb_strlen') ? mb_strlen($text) : strlen($text);
        if ($len <= $length) return $text;
        $cut = function_exists('mb_substr') ? mb_substr($text, 0, $length) : substr($text, 0, $length);
        return $cut . $suffix;
    }
}

if (!function_exists('defang_ioc')) {
    /**
     * "Defanging" para informes seguros: en direcciones IP y dominios cambia el
     * ÚLTIMO punto por "[.]" (p. ej. 203.0.113.45 -> 203.0.113[.]45,
     * evil.example.com -> evil.example[.]com). El resto de tipos se devuelven igual.
     */
    function defang_ioc(string $value, string $type = ''): string
    {
        $value = trim($value);
        if ($value === '') return $value;
        $t = strtolower($type);
        $isIp  = str_contains($t, 'ip') || (bool)filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        $isDom = str_contains($t, 'domain') || (bool)preg_match('/^([a-z0-9\-]+\.)+[a-z]{2,}$/i', $value);
        if ($isIp || $isDom) {
            $pos = strrpos($value, '.');
            if ($pos !== false) {
                return substr($value, 0, $pos) . '[.]' . substr($value, $pos + 1);
            }
        }
        return $value;
    }
}

if (!function_exists('ti_normalize_target')) {
    /**
     * Normaliza un texto de "target" para compararlo de forma robusta:
     * minúsculas, sin acentos y con espacios colapsados.
     */
    function ti_normalize_target(string $value): string
    {
        $value = trim($value);
        if ($value === '') {
            return '';
        }
        // Transliterar primero (quita acentos) y luego pasar a minúsculas:
        // así funciona incluso sin mbstring y sin corromper UTF-8.
        if (function_exists('iconv')) {
            $ascii = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $value);
            if ($ascii !== false && $ascii !== '') {
                $value = $ascii;
            }
        }
        $value = function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value);
        // Normalizar a solo [a-z0-9] y espacios: elimina acentos residuales,
        // signos de puntuación y guiones (idéntico en vocabulario y entrada).
        $value = preg_replace('/[^a-z0-9]+/', ' ', $value) ?? $value;
        $value = preg_replace('/\s+/', ' ', $value) ?? $value;
        return trim($value);
    }
}

if (!function_exists('ti_target_region_map')) {
    /**
     * Mapa normalizado => nombre canónico de región (canónicas + extras).
     */
    function ti_target_region_map(): array
    {
        static $map = null;
        if ($map !== null) {
            return $map;
        }
        $map = [];
        foreach (array_merge(TI_TARGET_REGIONS, TI_TARGET_REGION_EXTRAS) as $r) {
            $map[ti_normalize_target((string)$r)] = (string)$r;
        }
        return $map;
    }
}

if (!function_exists('ti_target_industry_map')) {
    /**
     * Mapa normalizado => nombre canónico de industria (MDTI).
     */
    function ti_target_industry_map(): array
    {
        static $map = null;
        if ($map !== null) {
            return $map;
        }
        $map = [];
        foreach (TI_TARGET_INDUSTRIES as $i) {
            $map[ti_normalize_target((string)$i)] = (string)$i;
        }
        return $map;
    }
}

if (!function_exists('ti_parse_targets')) {
    /**
     * Separa los "targets" de un intelProfile de Graph en industrias, regiones
     * y sub-industrias, usando la taxonomía canónica de MDTI.
     *
     * - "Industry: SubIndustry"  -> industria canónica (+ sub-industria)
     * - Región conocida          -> región canónica
     * - Desconocido              -> se conserva como industria (no se pierde)
     *
     * @return array{industries:string[],regions:string[],subindustries:string[]}
     */
    function ti_parse_targets(array $targets): array
    {
        $regMap = ti_target_region_map();
        $indMap = ti_target_industry_map();

        $industries = [];
        $regions = [];
        $subindustries = [];

        foreach ($targets as $t) {
            $raw = trim((string)(is_array($t) ? ($t['value'] ?? $t['name'] ?? '') : $t));
            if ($raw === '') {
                continue;
            }

            if (str_contains($raw, ':')) {
                [$left, $right] = array_map('trim', explode(':', $raw, 2));
                if ($left !== '') {
                    $industries[$indMap[ti_normalize_target($left)] ?? $left] = true;
                }
                if ($right !== '') {
                    $subindustries[$right] = true;
                }
                continue;
            }

            $norm = ti_normalize_target($raw);
            if (isset($regMap[$norm])) {
                $regions[$regMap[$norm]] = true;
                continue;
            }
            if (isset($indMap[$norm])) {
                $industries[$indMap[$norm]] = true;
                continue;
            }
            $industries[$raw] = true;
        }

        return [
            'industries'    => array_keys($industries),
            'regions'       => array_keys($regions),
            'subindustries' => array_keys($subindustries),
        ];
    }
}

if (!function_exists('severity_badge_class')) {
    /**
     * Devuelve clases CSS para un badge de severidad.
     */
    function severity_badge_class(?string $severity): string
    {
        return match (strtolower($severity ?? '')) {
            'critical', 'high', 'informational' => match (strtolower($severity ?? '')) {
                'critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
                'high'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
                default    => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
            },
            'medium' => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
            'low'    => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
            default  => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
        };
    }
}

if (!function_exists('cvss_badge_class')) {
    /**
     * Devuelve clases CSS para un badge de CVSS.
     */
    function cvss_badge_class(?float $cvss): string
    {
        if ($cvss === null) return 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400';
        if ($cvss >= 9.0) return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300';
        if ($cvss >= 7.0) return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300';
        if ($cvss >= 4.0) return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300';
        return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
    }
}

if (!function_exists('generate_uuid')) {
    /**
     * Genera un UUID v4.
     */
    function generate_uuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}

if (!function_exists('slugify')) {
    /**
     * Convierte un texto en slug URL-safe.
     */
    function slugify(string $text): string
    {
        $text = function_exists('mb_strtolower') ? mb_strtolower(trim($text), 'UTF-8') : strtolower(trim($text));
        $text = preg_replace('/[^a-z0-9\x{00C0}-\x{00FF}]+/u', '-', $text);
        $text = trim($text ?? '', '-');
        return $text !== '' ? $text : 'tenant-' . substr(md5($text . time()), 0, 8);
    }
}

if (!function_exists('safe_json_decode')) {
    /**
     * Decodifica JSON de forma segura.
     */
    function safe_json_decode(?string $json, mixed $default = null): mixed
    {
        if (empty($json)) return $default;
        $decoded = json_decode($json, true);
        return json_last_error() === JSON_ERROR_NONE ? $decoded : $default;
    }
}

if (!function_exists('flash')) {
    /**
     * Gestiona mensajes flash de sesión.
     */
    function flash(?string $key = null, mixed $value = null): mixed
    {
        if ($key === null) {
            // Obtener todos y limpiar
            $messages = $_SESSION['flash'] ?? [];
            unset($_SESSION['flash']);
            return $messages;
        }
        if ($value === null) {
            // Obtener uno
            $msg = $_SESSION['flash'][$key] ?? null;
            unset($_SESSION['flash'][$key]);
            return $msg;
        }
        // Establecer
        $_SESSION['flash'][$key] = $value;
        return null;
    }
}

if (!function_exists('old_input')) {
    /**
     * Recupera valor antiguo de un formulario (post-redirect-get).
     */
    function old_input(?string $key = null, mixed $default = ''): mixed
    {
        $old = $_SESSION['old_input'] ?? [];
        if ($key === null) return $old;
        $value = $old[$key] ?? $default;
        return $value;
    }
}

if (!function_exists('set_old_input')) {
    /**
     * Guarda los datos de un formulario para el siguiente request.
     */
    function set_old_input(array $data): void
    {
        $_SESSION['old_input'] = $data;
    }
}

if (!function_exists('clear_old_input')) {
    function clear_old_input(): void
    {
        unset($_SESSION['old_input']);
    }
}

if (!function_exists('is_ajax')) {
    /**
     * Detecta si la petición es AJAX.
     */
    function is_ajax(): bool
    {
        return !empty($_SERVER['HTTP_X_REQUESTED_WITH'])
            && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    }
}

if (!function_exists('release_session_lock')) {
    /**
     * Libera el bloqueo del fichero de sesión para que otras peticiones de la
     * MISMA sesión no esperen durante tareas largas (sync de Graph, análisis
     * IA…). Debe llamarse DESPUÉS de validar CSRF y de leer el usuario, y no
     * debe escribirse en la sesión a partir de ahí.
     */
    function release_session_lock(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
    }
}

if (!function_exists('background_request')) {
    /**
     * Lanza una petición HTTP "fire-and-forget" (no espera la respuesta) para
     * encadenar trabajos en segundo plano. Devuelve true si consiguió abrir la
     * conexión. No requiere curl (usa sockets).
     */
    function background_request(string $url): bool
    {
        $p = parse_url($url);
        if (empty($p['host'])) {
            return false;
        }
        $scheme = strtolower($p['scheme'] ?? 'http');
        $host   = (string)$p['host'];
        $port   = (int)($p['port'] ?? ($scheme === 'https' ? 443 : 80));
        $path   = ($p['path'] ?? '/') . (isset($p['query']) ? '?' . $p['query'] : '');
        $transport = ($scheme === 'https') ? 'ssl://' : '';

        $fp = @fsockopen($transport . $host, $port, $errno, $errstr, 2.0);
        if (!$fp) {
            return false;
        }
        stream_set_blocking($fp, false);
        $req = "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n"
             . "User-Agent: EntraID-TI-Worker\r\nAccept: */*\r\n\r\n";
        @fwrite($fp, $req);
        @fclose($fp);
        return true;
    }
}

if (!function_exists('client_ip')) {
    /**
     * Obtiene la IP del cliente de forma segura.
     */
    function client_ip(): string
    {
        $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                return trim($ips[0]);
            }
        }
        return '0.0.0.0';
    }
}

if (!function_exists('icon')) {
    /**
     * Icono Material Icons por ligadura.
     *
     * @param string $name  Nombre del icono (p. ej. "search", "warning").
     * @param int    $size  Tamaño canónico: 12, 14, 16, 18, 20, 24, 32.
     * @param string $class Clases extra.
     */
    function icon(string $name, int $size = 18, string $class = ''): string
    {
        $sizes = [12, 14, 16, 18, 20, 24, 32];
        if (!in_array($size, $sizes, true)) {
            $size = 18;
        }

        return '<i class="material-icons icon-' . $size . ($class !== '' ? ' ' . e($class) : '') . '"'
            . ' aria-hidden="true">' . e($name) . '</i>';
    }
}

if (!function_exists('getModuleIcon')) {
    /**
     * Icono de un módulo (Material Icons).
     * Mantiene el nombre histórico del helper para no romper llamadas existentes.
     */
    function getModuleIcon(string $name): string
    {
        $icons = [
            'plug'           => 'extension',
            'file-text'      => 'description',
            'alert-triangle' => 'warning',
            'bug'            => 'bug_report',
            'radar'          => 'radar',
            'gauge'          => 'speed',
            'search'         => 'search',
            'bar-chart-3'    => 'bar_chart',
            'brain'          => 'psychology',
            'download'       => 'download',
            'shield'         => 'shield',
            'users'          => 'group',
        ];

        return icon($icons[$name] ?? 'shield', 18);
    }
}

if (!function_exists('log_activity')) {
    /**
     * Registra una actividad en el log.
     */
    function log_activity(string $action, array $context = [], ?int $userId = null): void
    {
        $logFile = STORAGE_PATH . '/activity.log';
        $entry = [
            'timestamp' => date('c'),
            'action'    => $action,
            'user_id'   => $userId ?? (Auth::id() ?? null),
            'ip'        => client_ip(),
            'context'   => $context,
        ];
        file_put_contents($logFile, json_encode($entry, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
    }
}

if (!function_exists('app_log')) {
    /**
     * Log estructurado de la aplicación (JSONL en storage/app.log).
     * Nunca lanza excepciones: un fallo al escribir no debe tumbar la petición.
     */
    function app_log(string $level, string $channel, string $message, array $context = []): void
    {
        try {
            $logFile = STORAGE_PATH . '/app.log';

            // Rotación simple al superar 2 MB.
            if (is_file($logFile) && (int)@filesize($logFile) > 2097152) {
                @rename($logFile, STORAGE_PATH . '/app.log.1');
            }

            $userId = null;
            try {
                if (class_exists('Auth') && Auth::check()) {
                    $userId = Auth::id();
                }
            } catch (Throwable $e) {
                $userId = null;
            }

            $entry = [
                'timestamp' => date('c'),
                'level'     => strtolower($level),
                'channel'   => $channel,
                'message'   => $message,
                'user_id'   => $userId,
                'context'   => app_log_redact($context),
            ];

            $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            if ($line === false) {
                $line = json_encode(['timestamp' => date('c'), 'level' => $level, 'channel' => $channel, 'message' => $message]);
            }
            @file_put_contents($logFile, $line . "\n", FILE_APPEND | LOCK_EX);
        } catch (Throwable $e) {
            // Silencio deliberado.
        }
    }
}

if (!function_exists('app_log_redact')) {
    /**
     * Oculta secretos y recorta valores largos antes de escribir en el log.
     */
    function app_log_redact(array $context, int $depth = 0): array
    {
        if ($depth > 4) {
            return ['…' => 'demasiada profundidad'];
        }

        $out = [];
        foreach ($context as $key => $value) {
            if (is_string($key) && preg_match('/key|token|secret|password|authorization|cookie/i', $key)) {
                $out[$key] = '[redactado]';
                continue;
            }
            if (is_array($value)) {
                $out[$key] = app_log_redact($value, $depth + 1);
            } elseif (is_string($value)) {
                $out[$key] = truncate($value, 2000);
            } elseif (is_bool($value) || is_int($value) || is_float($value) || $value === null) {
                $out[$key] = $value;
            } else {
                $out[$key] = truncate((string)$value, 500);
            }
        }

        return $out;
    }
}

if (!function_exists('setting_get')) {
    /**
     * Lee un valor de la tabla `settings`. Si está marcado como cifrado,
     * lo descifra con AES-256. Devuelve $default si no existe o está vacío.
     */
    function setting_get(string $key, mixed $default = null): mixed
    {
        try {
            $row = Database::fetchOne(
                "SELECT setting_value, is_encrypted FROM settings WHERE setting_key = ?",
                [$key]
            );
        } catch (Throwable $e) {
            return $default;
        }
        if (!$row) {
            return $default;
        }
        $val = $row['setting_value'];
        if (!empty($row['is_encrypted']) && $val !== null && $val !== '') {
            try {
                $val = Encryption::decryptCombined($val);
            } catch (Throwable $e) {
                return $default;
            }
        }
        return ($val === null || $val === '') ? $default : $val;
    }
}

if (!function_exists('setting_set')) {
    /**
     * Guarda (INSERT OR REPLACE) un valor en la tabla `settings`.
     * Si $encrypted, se cifra con AES-256 (recomendado para API keys).
     */
    function setting_set(string $key, ?string $value, bool $encrypted = false): void
    {
        $stored = ($value === null) ? '' : $value;
        if ($encrypted && $stored !== '') {
            $stored = Encryption::encryptCombined($stored);
        }
        Database::query(
            "INSERT OR REPLACE INTO settings (setting_key, setting_value, is_encrypted, updated_at)
             VALUES (?, ?, ?, datetime('now'))",
            [$key, $stored, $encrypted ? 1 : 0]
        );
    }
}

if (!function_exists('llm_profile_list')) {
    /**
     * Lista de perfiles de IA (varios proveedores guardados a la vez).
     */
    function llm_profile_list(): array
    {
        try {
            return Database::fetchAll("SELECT * FROM llm_profiles ORDER BY is_default DESC, name");
        } catch (Throwable $e) {
            return [];
        }
    }
}

if (!function_exists('llm_profile_get')) {
    /**
     * Devuelve un perfil con la API key ya descifrada (o null).
     */
    function llm_profile_get(?int $id): ?array
    {
        if (!$id || $id <= 0) {
            return null;
        }
        try {
            $p = Database::fetchOne("SELECT * FROM llm_profiles WHERE id = ?", [$id]);
        } catch (Throwable $e) {
            return null;
        }
        if (!$p) {
            return null;
        }
        $p['api_key'] = '';
        if (!empty($p['api_key_encrypted'])) {
            try {
                $p['api_key'] = Encryption::decryptCombined($p['api_key_encrypted']);
            } catch (Throwable $e) {
                $p['api_key'] = '';
            }
        }
        return $p;
    }
}

if (!function_exists('llm_profile_is_small')) {
    /**
     * ¿El perfil es un modelo local pequeño (≤ 4B)? Se usa para avisar de que
     * ciertas tareas (planes de remediación) piden más capacidad.
     */
    function llm_profile_is_small(?array $profile): bool
    {
        if ($profile === null) {
            return false;
        }
        $provider = strtolower((string)($profile['provider'] ?? ''));
        if (!in_array($provider, ['ollama', 'ollama_cloud', 'custom'], true)) {
            return false;
        }
        $model = strtolower(trim((string)($profile['model'] ?? '')));
        if ($model === '') {
            return false;
        }
        // 1b, 1.7b, 2b, 3b, 4b… (no confundir con q4_k_m ni con 20b)
        if (preg_match('/(?:^|[^0-9.])(\d+(?:\.\d+)?)\s*b(?:[^a-z0-9]|$)/i', $model, $m) === 1) {
            return (float)$m[1] <= 4.0;
        }
        return false;
    }
}

if (!function_exists('llm_profile_default')) {
    /**
     * Perfil predeterminado (o null si no hay ninguno).
     */
    function llm_profile_default(): ?array
    {
        try {
            $row = Database::fetchOne("SELECT id FROM llm_profiles ORDER BY is_default DESC, id LIMIT 1");
        } catch (Throwable $e) {
            return null;
        }
        return $row ? llm_profile_get((int)$row['id']) : null;
    }
}

if (!function_exists('llm_profile_save')) {
    /**
     * Crea o actualiza un perfil de IA. Si $data['api_key'] viene vacío en una
     * edición, se conserva la clave existente.
     */
    function llm_profile_save(array $data, ?int $id = null): int
    {
        $name = trim((string)($data['name'] ?? '')) ?: 'Perfil';
        $provider = strtolower(trim((string)($data['provider'] ?? '')));
        $apiUrl = trim((string)($data['api_url'] ?? ''));
        $model = trim((string)($data['model'] ?? ''));
        $maxTokens = max(1, min(128000, (int)($data['max_tokens'] ?? 2048)));
        // Ventana de contexto del modelo (0 = desconocida / autodetectar).
        $contextTokens = max(0, min(1048576, (int)($data['context_tokens'] ?? 0)));
        // Timeout de cada llamada (segundos).
        $timeout = max(10, min(3600, (int)($data['timeout'] ?? 120)));

        $key = trim((string)($data['api_key'] ?? ''));
        $keyEnc = null;
        if ($key !== '') {
            $keyEnc = Encryption::encryptCombined($key);
        }

        if ($id && $id > 0) {
            $sets = "name = ?, provider = ?, api_url = ?, model = ?, max_tokens = ?, context_tokens = ?, timeout = ?, updated_at = datetime('now')";
            $params = [$name, $provider, $apiUrl, $model, $maxTokens, $contextTokens, $timeout];
            if ($keyEnc !== null) {
                $sets .= ", api_key_encrypted = ?";
                $params[] = $keyEnc;
            }
            $params[] = $id;
            Database::update("UPDATE llm_profiles SET $sets WHERE id = ?", $params);
            return $id;
        }

        return Database::insert(
            "INSERT INTO llm_profiles (name, provider, api_url, model, max_tokens, context_tokens, timeout, api_key_encrypted)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [$name, $provider, $apiUrl, $model, $maxTokens, $contextTokens, $timeout, $keyEnc]
        );
    }
}

if (!function_exists('llm_profile_set_default')) {
    function llm_profile_set_default(int $id): void
    {
        Database::query("UPDATE llm_profiles SET is_default = 0");
        Database::query("UPDATE llm_profiles SET is_default = 1 WHERE id = ?", [$id]);
    }
}

if (!function_exists('llm_profile_delete')) {
    function llm_profile_delete(int $id): void
    {
        Database::query("DELETE FROM llm_profiles WHERE id = ?", [$id]);
    }
}

if (!function_exists('llm_migrate_legacy_profile')) {
    /**
     * Migración única: si no hay perfiles pero sí la config única antigua,
     * la convierte en un perfil "Principal" (para no perder Mistral, etc.).
     */
    function llm_migrate_legacy_profile(): void
    {
        try {
            $count = (int)(Database::fetchOne("SELECT COUNT(*) AS c FROM llm_profiles")['c'] ?? 0);
        } catch (Throwable $e) {
            return;
        }
        if ($count > 0) {
            return;
        }
        $provider = (string)(setting_get('llm_provider') ?? LLM_PROVIDER);
        if ($provider === '') {
            return;
        }
        $id = llm_profile_save([
            'name'       => 'Principal',
            'provider'   => $provider,
            'api_url'    => (string)(setting_get('llm_api_url') ?? LLM_API_URL),
            'model'      => (string)(setting_get('llm_model') ?? LLM_MODEL),
            'max_tokens' => (int)(setting_get('llm_max_tokens') ?? LLM_MAX_TOKENS),
            'api_key'    => (string)(setting_get('llm_api_key') ?? LLM_API_KEY),
        ]);
        llm_profile_set_default($id);
    }
}

if (!function_exists('llm_task_profile')) {
    /**
     * Perfil configurado para una tarea concreta (o null = predeterminado).
     */
    function llm_task_profile(string $task): ?int
    {
        $id = (int)(setting_get('llm_task_' . $task) ?? 0);
        return $id > 0 ? $id : null;
    }
}

if (!function_exists('llm_cfg_from_input')) {
    /**
     * Resuelve la config de LLM a partir de una petición de prueba/verificación.
     * Si se edita un perfil (id) o se indica uno (profile_id) y no llega una
     * API key nueva, se usa la clave GUARDADA de ese perfil (no la del
     * predeterminado, que era un bug de la pantalla de prueba).
     */
    function llm_cfg_from_input(array $input): array
    {
        $formId = (int)($input['id'] ?? 0);
        $pid = (int)($input['profile_id'] ?? 0);
        $srcId = $formId > 0 ? $formId : $pid;

        $override = [];
        if ($srcId > 0) {
            $p = llm_profile_get($srcId);
            if ($p) {
                $override = [
                    'provider'   => (string)$p['provider'],
                    'api_url'    => (string)$p['api_url'],
                    'model'      => (string)$p['model'],
                    'api_key'    => (string)$p['api_key'],
                    'max_tokens' => (int)$p['max_tokens'],
                    'context_tokens' => (int)($p['context_tokens'] ?? 0),
                    'timeout'    => (int)($p['timeout'] ?? 120),
                ];
            }
        }

        $provider = strtolower(trim((string)($input['provider'] ?? $input['llm_provider'] ?? '')));
        if ($provider !== '') { $override['provider'] = $provider; }
        $model = trim((string)($input['model'] ?? $input['llm_model'] ?? ''));
        if ($model !== '') { $override['model'] = $model; }
        $url = trim((string)($input['api_url'] ?? $input['llm_api_url'] ?? ''));
        if ($url !== '') { $override['api_url'] = $url; }
        $key = trim((string)($input['api_key'] ?? $input['llm_api_key'] ?? ''));
        if ($key !== '') { $override['api_key'] = $key; }
        if (isset($input['context_tokens']) && $input['context_tokens'] !== '') {
            $override['context_tokens'] = max(0, (int)$input['context_tokens']);
        }
        if (isset($input['timeout']) && $input['timeout'] !== '') {
            $override['timeout'] = max(10, min(3600, (int)$input['timeout']));
        }

        return $override;
    }
}

if (!function_exists('llm_actions_list')) {
    /** Lista de acciones rápidas (editables), opcionalmente filtradas por ámbito. */
    function llm_actions_list(bool $onlyActive = false, ?string $scope = null): array
    {
        try {
            $where = [];
            $params = [];
            if ($onlyActive) { $where[] = 'is_active = 1'; }
            if ($scope !== null && $scope !== '') { $where[] = 'scope = ?'; $params[] = $scope; }

            $sql = "SELECT * FROM llm_actions";
            if ($where) { $sql .= ' WHERE ' . implode(' AND ', $where); }
            $sql .= " ORDER BY position, id";

            return $params ? Database::fetchAll($sql, $params) : Database::fetchAll($sql);
        } catch (Throwable $e) {
            return [];
        }
    }
}

if (!function_exists('llm_action_get')) {
    function llm_action_get(int $id): ?array
    {
        if ($id <= 0) { return null; }
        try {
            $a = Database::fetchOne("SELECT * FROM llm_actions WHERE id = ?", [$id]);
        } catch (Throwable $e) {
            return null;
        }
        return $a ?: null;
    }
}

if (!function_exists('llm_action_save')) {
    function llm_action_save(array $data, ?int $id = null): int
    {
        $label = trim((string)($data['label'] ?? '')) ?: 'Acción';
        $prompt = trim((string)($data['prompt'] ?? ''));
        $position = (int)($data['position'] ?? 0);
        $active = !empty($data['is_active']) ? 1 : 0;
        $scope = trim((string)($data['scope'] ?? '')) ?: 'tenant';

        if ($id && $id > 0) {
            // El ámbito no se cambia al editar.
            Database::update(
                "UPDATE llm_actions SET label = ?, prompt = ?, position = ?, is_active = ?, updated_at = datetime('now') WHERE id = ?",
                [$label, $prompt, $position, $active, $id]
            );
            return $id;
        }
        return Database::insert(
            "INSERT INTO llm_actions (label, prompt, position, is_active, scope) VALUES (?, ?, ?, ?, ?)",
            [$label, $prompt, $position, $active, $scope]
        );
    }
}

if (!function_exists('llm_action_delete')) {
    function llm_action_delete(int $id): void
    {
        Database::query("DELETE FROM llm_actions WHERE id = ?", [$id]);
    }
}

if (!function_exists('llm_config')) {
    /**
     * Configuración efectiva del LLM.
     * Orden: perfil indicado → perfil predeterminado → configuración única (compat) → .env.
     */
    function llm_config(?int $profileId = null): array
    {
        $p = $profileId ? llm_profile_get($profileId) : null;
        if ($p === null) {
            $p = llm_profile_default();
        }
        if ($p !== null) {
            return [
                'provider'   => strtolower((string)$p['provider']),
                'api_key'    => (string)$p['api_key'],
                'api_url'    => (string)$p['api_url'],
                'model'      => (string)$p['model'],
                'max_tokens' => (int)$p['max_tokens'],
                'context_tokens' => (int)($p['context_tokens'] ?? 0),
                'timeout'    => (int)($p['timeout'] ?? 120),
            ];
        }

        // Compat: configuración única antigua / constantes .env
        return [
            'provider'   => strtolower((string)(setting_get('llm_provider') ?? LLM_PROVIDER)),
            'api_key'    => (string)(setting_get('llm_api_key') ?? LLM_API_KEY),
            'api_url'    => (string)(setting_get('llm_api_url') ?? LLM_API_URL),
            'model'      => (string)(setting_get('llm_model') ?? LLM_MODEL),
            'max_tokens' => (int)(setting_get('llm_max_tokens') ?? LLM_MAX_TOKENS),
            'context_tokens' => (int)(setting_get('llm_context_tokens') ?? 0),
            'timeout'    => (int)(setting_get('llm_timeout') ?? 120),
        ];
    }
}

if (!function_exists('render_markdown')) {
    /**
     * Convierte Markdown a HTML de forma segura (Parsedown en modo seguro:
     * el HTML crudo de la fuente se escapa). Si el parser no está disponible,
     * devuelve el texto escapado en un <pre>.
     */
    function render_markdown(?string $markdown): string
    {
        $md = (string)($markdown ?? '');
        if (trim($md) === '') {
            return '';
        }

        $parserFile = INCLUDES_PATH . '/parsedown.php';
        if (is_file($parserFile)) {
            require_once $parserFile;
            if (class_exists('Parsedown')) {
                $p = new Parsedown();
                $p->setSafeMode(true);
                $html = $p->text($md);
                // Enlaces externos: abrir en pestaña nueva y sin referrer
                $html = preg_replace(
                    '/<a href="(https?:\/\/[^"]+)"/i',
                    '<a href="$1" target="_blank" rel="noopener noreferrer"',
                    $html
                );
                return $html;
            }
        }

        // Fallback seguro
        return '<pre class="whitespace-pre-wrap">' . e($md) . '</pre>';
    }
}

if (!function_exists('normalize_ai_markdown')) {
    /**
     * Normaliza la respuesta Markdown de un LLM.
     *
     * Algunos modelos envuelven todo el informe en un fence ```markdown ... ```
     * y Parsedown lo pinta como bloque de código: el usuario ve el Markdown sin
     * procesar. Aquí se elimina el fence que envuelve TODO el texto y se
     * equilibran los fences sueltos; los bloques de código internos se
     * conservan.
     */
    function normalize_ai_markdown(?string $markdown): string
    {
        $md = str_replace(["\r\n", "\r"], "\n", (string)($markdown ?? ''));
        $md = trim($md);
        if ($md === '') {
            return '';
        }

        // 1) Envoltorio de todo el texto. Solo se considera envoltorio si la
        //    etiqueta es markdown/md, o si no hay etiqueta y el contenido
        //    parece un documento (un ```kql es un bloque de código real).
        if (preg_match('/^(`{3,}|~{3,})[ \t]*([a-zA-Z0-9_+.\-]*)[ \t]*\n(.*?)\n?\1[ \t]*$/usi', $md, $m) === 1) {
            $info  = strtolower((string)$m[2]);
            $inner = (string)$m[3];
            $docish = preg_match('/^#{1,6}\s/m', $inner) === 1
                || preg_match('/^(?:[-*+]\s|\|[^|\n]*\|[^|\n]*\|)/m', $inner) === 1
                || str_contains($inner, '```');
            if (in_array($info, ['markdown', 'md'], true) || ($info === '' && $docish)) {
                $md = trim($inner);
            }
        }

        // 2) Fence de apertura al principio (envoltorio sin cerrar): se quita
        //    con el mismo criterio que el punto 1.
        $lines = explode("\n", $md);
        if ($lines !== [] && preg_match('/^\s*(`{3,}|~{3,})[ \t]*([a-zA-Z0-9_+.\-]*)[ \t]*$/', $lines[0], $fm) === 1) {
            $info = strtolower((string)$fm[2]);
            $rest = implode("\n", array_slice($lines, 1));
            $docish = preg_match('/^#{1,6}\s/m', $rest) === 1
                || preg_match('/^(?:[-*+]\s|\|[^|\n]*\|[^|\n]*\|)/m', $rest) === 1;
            $isWrapper = in_array($info, ['markdown', 'md'], true)
                || ($info === '' && $docish);
            if ($isWrapper) {
                array_shift($lines);
            }
        }

        // 3) Equilibrado: si un tipo de fence queda con una apertura sin
        //    pareja, se quita la última línea de ese tipo (si era el cierre del
        //    envoltorio, se descarta; si era una apertura, evita que el resto
        //    del texto quede dentro de un bloque de código).
        foreach (['`', '~'] as $marker) {
            $positions = [];
            foreach ($lines as $i => $line) {
                if (preg_match('/^\s*' . preg_quote($marker, '/') . '{3,}/', $line) === 1) {
                    $positions[] = $i;
                }
            }
            if (count($positions) % 2 === 1) {
                $last = (int)array_pop($positions);
                unset($lines[$last]);
                $lines = array_values($lines);
            }
        }

        return trim(implode("\n", $lines));
    }
}

if (!function_exists('ai_balance_fences')) {
    /**
     * Equilibra los bloques de código de un documento largo (típico de una
     * traducción por partes: un bloque mal cerrado se traga lo que viene
     * después). Una apertura sin cierre se elimina; un cierre sin apertura se
     * descarta. Los bloques de código legítimos (apertura + cierre) no se tocan.
     */
    function ai_balance_fences(?string $markdown): string
    {
        $md = str_replace(["\r\n", "\r"], "\n", (string)($markdown ?? ''));
        if (trim($md) === '') {
            return '';
        }

        $lines = explode("\n", $md);
        $out = [];
        $open = null;

        foreach ($lines as $line) {
            if (preg_match('/^\s*(`{3,}|~{3,})/', $line, $m) === 1) {
                $marker = substr($m[1], 0, 1);
                if ($open === null) {
                    $open = $marker;
                    $out[] = $line;
                    continue;
                }
                if ($open === $marker) {
                    $open = null;
                    $out[] = $line;
                    continue;
                }
                // Cierre de otro tipo: se descarta.
                continue;
            }
            $out[] = $line;
        }

        // Queda una apertura sin cerrar: se elimina su línea.
        if ($open !== null) {
            for ($i = count($out) - 1; $i >= 0; $i--) {
                if (preg_match('/^\s*(`{3,}|~{3,})/', $out[$i]) === 1) {
                    array_splice($out, $i, 1);
                    break;
                }
            }
        }

        return implode("\n", $out);
    }
}

if (!function_exists('ai_strip_residues')) {
    /**
     * Limpia los residuos que dejan los modelos pequeños: prefijos de
     * «Aquí tienes la traducción…», vallas sueltas y separadores `===` (que en
     * Markdown convertirían el párrafo anterior en un título gigante).
     */
    function ai_strip_residues(?string $markdown): string
    {
        $md = str_replace(["\r\n", "\r"], "\n", (string)($markdown ?? ''));
        $md = trim($md);
        if ($md === '') {
            return '';
        }

        // Prefijos típicos en la primera línea («Aquí tienes la traducción…»).
        $lines = explode("\n", $md);
        if ($lines !== []) {
            $first = trim((string)$lines[0]);
            $probe = trim((string)(preg_replace('/[*_`#>\s]+/u', ' ', $first) ?? $first));
            $isPrefix = preg_match('/^(?:aqu[ií]|here|traducci[óo]n|translation|versi[óo]n\s+traducida)\b/iu', $probe) === 1
                && (str_ends_with($probe, ':') || preg_match('/^(?:aqu[ií]|here)\b/iu', $probe) === 1);
            if ($isPrefix) {
                array_shift($lines);
                if (isset($lines[0]) && trim((string)$lines[0]) === '') {
                    array_shift($lines);
                }
                $md = implode("\n", $lines);
            }
        }

        // Vallas sueltas de envoltorio al principio: solo si son explícitas
        // (```markdown / ```md) o si el contenido es claramente un documento.
        // Así no se toca un bloque de código que empiece el texto.
        if (preg_match('/^(`{3,}|~{3,})[ \t]*([a-zA-Z0-9_+.\-]*)[ \t]*\n/', $md, $m) === 1) {
            $info = strtolower((string)$m[2]);
            $rest = (string)substr($md, strlen($m[0]));
            $isExplicit = in_array($info, ['markdown', 'md'], true);
            $looksDoc = preg_match('/^#{1,6}\s/m', $rest) === 1
                || preg_match('/^(?:[-*+]\s|\|[^|\n]*\|[^|\n]*\|)/m', $rest) === 1;
            if ($isExplicit || $looksDoc) {
                $md = $rest;
                $md = preg_replace('/\n+`{3,}[ \t]*$/', '', $md) ?? $md;
                $md = preg_replace('/\n+~{3,}[ \t]*$/', '', $md) ?? $md;
            }
        }

        // Separadores `===` → `---` (con línea en blanco delante para que sea
        // una regla horizontal y no un título).
        $lines = explode("\n", $md);
        $out = [];
        foreach ($lines as $line) {
            if (preg_match('/^[ \t]*={3,}[ \t]*$/', $line) === 1) {
                if ($out !== [] && trim((string)end($out)) !== '') {
                    $out[] = '';
                }
                $out[] = '---';
                continue;
            }
            $out[] = $line;
        }

        return trim(implode("\n", $out));
    }
}

if (!function_exists('ai_clean_prose')) {
    /**
     * Saneado de un fragmento de PROSA traducido por la IA.
     *
     * Un fragmento de prosa no puede contener bloques de código (van aparte),
     * así que si el modelo lo ha envuelto en vallas se quitan sin riesgo.
     * No se usa con bloques de código reales.
     */
    function ai_clean_prose(?string $markdown): string
    {
        $md = str_replace(["\r\n", "\r"], "\n", (string)($markdown ?? ''));
        $md = trim($md);
        if ($md === '') {
            return '';
        }

        // Valla de apertura (cualquiera) y su cierre.
        if (preg_match('/^(`{3,}|~{3,})[^\n]*\n/', $md, $m) === 1) {
            $md = (string)substr($md, strlen($m[0]));
        }
        $md = preg_replace('/\n?(`{3,}|~{3,})[ \t]*$/', '', $md) ?? $md;

        $md = ai_strip_residues($md);
        return trim($md);
    }
}

if (!function_exists('ai_clean_markdown')) {
    /**
     * Saneado completo del Markdown devuelto por una IA: desenvuelve el
     * fence global, equilibra los bloques de código y quita los residuos
     * típicos de los modelos pequeños.
     */
    function ai_clean_markdown(?string $markdown): string
    {
        $md = normalize_ai_markdown((string)($markdown ?? ''));
        if (trim($md) === '') {
            return '';
        }
        $md = ai_balance_fences($md);
        $md = ai_strip_residues($md);
        return trim($md);
    }
}

if (!function_exists('render_ai_markdown')) {
    /**
     * Normaliza y renderiza Markdown de IA de forma segura.
     */
    function render_ai_markdown(?string $markdown): string
    {
        $normalized = ai_clean_markdown($markdown);
        if ($normalized === '') {
            return '';
        }
        $html = render_markdown($normalized);

        // Red de seguridad: si aún queda un bloque de código cuyo contenido es
        // claramente un documento Markdown, se renderiza como Markdown.
        //  - Fence explícito ```markdown: basta con un encabezado.
        //  - Bloque sin etiqueta: se exige un documento claro (varios
        //    encabezados, listas/tabla y tamaño), para no tocar código real.
        if (preg_match_all(
            '/<pre><code(?: class="language-(markdown|md)")?>(.*?)<\/code><\/pre>/is',
            $html,
            $blocks,
            PREG_SET_ORDER
        ) > 0) {
            foreach ($blocks as $block) {
                $explicit = !empty($block[1]);
                $inner = html_entity_decode((string)($block[2] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8');
                $len = function_exists('mb_strlen') ? mb_strlen($inner) : strlen($inner);
                $headings = preg_match_all('/^#{1,6}\s/m', $inner);
                $hasListOrTable = preg_match('/^(?:[-*+]\s|\|[^|\n]*\|[^|\n]*\|)/m', $inner) === 1;
                $looksDoc = $explicit
                    ? $headings >= 1
                    : ($headings >= 2 && $len > 500 && $hasListOrTable);
                if ($looksDoc) {
                    $html = str_replace((string)$block[0], render_markdown($inner), $html);
                }
            }
        }

        return $html;
    }
}

if (!function_exists('plan_checklist_key')) {
    /**
     * Clave estable de un elemento de checklist del plan (v0.3.22).
     *
     * Se deriva del texto normalizado y del número de repetición dentro del
     * plan, para que dos elementos iguales no compartan estado.
     */
    function plan_checklist_key(string $text, int $occurrence = 0): string
    {
        $normalized = strtolower(trim((string)preg_replace('/\s+/u', ' ', $text)));
        return substr(sha1($normalized . '#' . $occurrence), 0, 20);
    }
}

if (!function_exists('plan_checklist_items')) {
    /**
     * Extrae los elementos marcables de un plan Markdown, en orden.
     *
     * @return array<int, array{key: string, text: string, default: bool}>
     */
    function plan_checklist_items(?string $plan): array
    {
        $markdown = normalize_ai_markdown($plan);
        if (trim($markdown) === '') {
            return [];
        }
        $lines = preg_split('/\R/u', $markdown) ?: [];
        $items = [];
        $occurrences = [];
        foreach ($lines as $line) {
            if (preg_match('/^\s*[-*]\s+\[([ xX])\]\s+(.+?)\s*$/u', $line, $m) !== 1) {
                continue;
            }
            $text = trim((string)$m[2]);
            $normalized = strtolower($text);
            $occurrence = (int)($occurrences[$normalized] ?? 0);
            $occurrences[$normalized] = $occurrence + 1;
            $items[] = [
                'key'     => plan_checklist_key($text, $occurrence),
                'text'    => $text,
                'default' => strtolower((string)$m[1]) === 'x',
            ];
        }
        return $items;
    }
}

if (!function_exists('render_plan_with_checklist')) {
    /**
     * Renderiza un plan Markdown convirtiendo `- [ ]` / `- [x]` en
     * checkboxes reales sin perder el resto del Markdown (v0.3.22).
     *
     * `$checks` es un mapa item_key => 0|1 con el estado guardado. Si un
     * elemento no tiene fila, manda el estado escrito en el propio plan.
     */
    function render_plan_with_checklist(?string $plan, int $taskId, array $checks = []): string
    {
        $markdown = normalize_ai_markdown($plan);
        if (trim($markdown) === '') {
            return '';
        }

        $lines = preg_split('/\R/u', $markdown) ?: [];
        $hasChecklist = false;
        foreach ($lines as $line) {
            if (preg_match('/^\s*[-*]\s+\[[ xX]\]\s+\S/u', $line) === 1) {
                $hasChecklist = true;
                break;
            }
        }
        if (!$hasChecklist) {
            return render_ai_markdown($markdown);
        }

        $html = '';
        $buffer = [];
        $occurrences = [];
        $flush = static function () use (&$buffer, &$html): void {
            if ($buffer === []) {
                return;
            }
            $chunk = implode("\n", $buffer);
            $buffer = [];
            if (trim($chunk) !== '') {
                $html .= render_markdown($chunk);
            }
        };

        foreach ($lines as $line) {
            if (preg_match('/^\s*[-*]\s+\[([ xX])\]\s+(.+?)\s*$/u', $line, $m) === 1) {
                $flush();
                $text = trim((string)$m[2]);
                $normalized = strtolower($text);
                $occurrence = (int)($occurrences[$normalized] ?? 0);
                $occurrences[$normalized] = $occurrence + 1;
                $key = plan_checklist_key($text, $occurrence);
                $checked = array_key_exists($key, $checks)
                    ? (int)$checks[$key] === 1
                    : strtolower((string)$m[1]) === 'x';

                $html .= '<label class="flex items-start gap-2 py-0.5 text-[11px] cursor-pointer">'
                    . '<input type="checkbox" data-plan-check data-task-id="' . $taskId . '"'
                    . ' data-item-key="' . e($key) . '"' . ($checked ? ' checked' : '')
                    . ' class="mt-0.5 accent-brand-500">'
                    . '<span' . ($checked ? ' class="line-through text-ink-soft"' : '') . '>'
                    . e($text)
                    . '</span></label>';
                continue;
            }
            $buffer[] = $line;
        }
        $flush();

        return $html;
    }
}

