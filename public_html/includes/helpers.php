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

if (!function_exists('getModuleIcon')) {
    /**
     * Obtiene el SVG de un icono por nombre (usado en el sidebar).
     */
    function getModuleIcon(string $name): string
    {
        $icons = [
            'plug'          => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244"/></svg>',
            'file-text'     => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>',
            'alert-triangle'=> '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>',
            'bug'           => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/></svg>',
            'gauge'         => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
            'search'        => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>',
            'bar-chart-3'   => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 3v18h18M18 17V9m-5 8V5m-5 12v-4"/></svg>',
            'brain'         => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>',
            'download'      => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>',
            'shield'        => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>',
            'users'         => '<svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z"/></svg>',
        ];
        return $icons[$name] ?? $icons['shield'];
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

if (!function_exists('llm_config')) {
    /**
     * Configuración efectiva del LLM: primero la guardada en la BD
     * (Admin → APIs), con fallback a las constantes de .env.
     */
    function llm_config(): array
    {
        return [
            'provider'   => strtolower((string)(setting_get('llm_provider') ?? LLM_PROVIDER)),
            'api_key'    => (string)(setting_get('llm_api_key') ?? LLM_API_KEY),
            'api_url'    => (string)(setting_get('llm_api_url') ?? LLM_API_URL),
            'model'      => (string)(setting_get('llm_model') ?? LLM_MODEL),
            'max_tokens' => (int)(setting_get('llm_max_tokens') ?? LLM_MAX_TOKENS),
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
