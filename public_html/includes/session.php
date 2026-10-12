<?php
/**
 * Session — Gestión avanzada de sesiones.
 */

declare(strict_types=1);

class Session
{
    /**
     * Obtiene un valor de la sesión.
     */
    public static function get(string $key, mixed $default = null): mixed
    {
        return $_SESSION[$key] ?? $default;
    }

    /**
     * Establece un valor en la sesión.
     */
    public static function set(string $key, mixed $value): void
    {
        $_SESSION[$key] = $value;
    }

    /**
     * Comprueba si existe una clave.
     */
    public static function has(string $key): bool
    {
        return isset($_SESSION[$key]);
    }

    /**
     * Elimina una clave de la sesión.
     */
    public static function remove(string $key): void
    {
        unset($_SESSION[$key]);
    }

    /**
     * Destruye toda la sesión.
     */
    public static function destroy(): void
    {
        $_SESSION = [];

        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params['path'], $params['domain'],
                $params['secure'], $params['httponly']
            );
        }

        session_destroy();
    }

    /**
     * Regenera el ID de sesión.
     */
    public static function regenerate(): void
    {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }

    /**
     * Obtiene el tiempo restante de la sesión.
     */
    public static function ttl(): int
    {
        if (!isset($_SESSION['created'])) {
            return 0;
        }
        $elapsed = time() - $_SESSION['created'];
        $maxlifetime = (int)ini_get('session.gc_maxlifetime');
        return max(0, $maxlifetime - $elapsed);
    }
}
