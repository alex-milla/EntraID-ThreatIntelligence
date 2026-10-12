<?php
/**
 * CSRF — Protección contra Cross-Site Request Forgery.
 */

declare(strict_types=1);

class Csrf
{
    private const TOKEN_KEY = '_csrf_token';
    private const TOKEN_TTL = 7200; // 2 horas

    /**
     * Genera (o recupera) el token CSRF de la sesión.
     */
    public static function token(): string
    {
        if (!isset($_SESSION[self::TOKEN_KEY])) {
            $_SESSION[self::TOKEN_KEY] = [
                'value'     => bin2hex(random_bytes(32)),
                'expires_at' => time() + self::TOKEN_TTL,
            ];
        } elseif (time() > $_SESSION[self::TOKEN_KEY]['expires_at']) {
            // Token expirado, regenerar
            $_SESSION[self::TOKEN_KEY] = [
                'value'     => bin2hex(random_bytes(32)),
                'expires_at' => time() + self::TOKEN_TTL,
            ];
        }
        return $_SESSION[self::TOKEN_KEY]['value'];
    }

    /**
     * Genera el campo hidden para formularios.
     */
    public static function field(): string
    {
        return '<input type="hidden" name="csrf_token" value="' . e(self::token()) . '">';
    }

    /**
     * Valida el token CSRF de la petición actual.
     */
    public static function validate(?string $token = null): bool
    {
        $token = $token ?? ($_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');

        if (empty($token) || !isset($_SESSION[self::TOKEN_KEY])) {
            return false;
        }

        // Token expirado
        if (time() > $_SESSION[self::TOKEN_KEY]['expires_at']) {
            return false;
        }

        return hash_equals($_SESSION[self::TOKEN_KEY]['value'], $token);
    }

    /**
     * Valida y lanza excepción si falla (para APIs).
     */
    public static function validateOrFail(): void
    {
        if (!self::validate()) {
            json_response(['error' => 'Token CSRF inválido o expirado'], 403);
        }
    }

    /**
     * Middleware: valida CSRF en peticiones POST/PUT/DELETE.
     */
    public static function middleware(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            // Excepciones: endpoints de API con token propio
            $uri = $_SERVER['REQUEST_URI'] ?? '';
            if (str_contains($uri, '/api/') && self::hasValidApiToken()) {
                return;
            }
            self::validateOrFail();
        }
    }

    /**
     * Verifica si hay un token de API válido en la petición.
     */
    private static function hasValidApiToken(): bool
    {
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!str_starts_with($header, 'Bearer ')) {
            return false;
        }
        $token = substr($header, 7);
        $hash = hash('sha256', $token);
        $row = Database::fetchOne(
            "SELECT id FROM api_tokens WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > datetime('now'))",
            [$hash]
        );
        return $row !== null;
    }
}
