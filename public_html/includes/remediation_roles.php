<?php
/**
 * remediation_roles.php — roles del flujo CVE Desk (F3).
 *
 * Tabla propia (`remediation_roles`) para no tocar `users.role`. Si no hay
 * ninguna fila configurada, todo el mundo mantiene el comportamiento actual
 * (analista). Solo se restringe cuando el administrador asigna roles.
 */

declare(strict_types=1);

final class RemediationRoles
{
    public const ROLES = ['analista', 'aprobador', 'lector'];

    /** @var array<int,string>|null */
    private static ?array $map = null;

    /** @var bool|null */
    private static ?bool $configured = null;

    public static function labels(): array
    {
        return [
            'analista'  => 'Analista',
            'aprobador' => 'Aprobador',
            'lector'    => 'Lectura',
        ];
    }

    /** @return array<int,string> user_id => rol */
    public static function all(): array
    {
        if (self::$map !== null) {
            return self::$map;
        }
        self::$map = [];
        try {
            foreach (Database::fetchAll("SELECT user_id, rol FROM remediation_roles") as $row) {
                self::$map[(int)$row['user_id']] = (string)$row['rol'];
            }
        } catch (Throwable $e) {
            self::$map = [];
        }
        return self::$map;
    }

    public static function isConfigured(): bool
    {
        if (self::$configured !== null) {
            return self::$configured;
        }
        self::$configured = self::all() !== [];
        return self::$configured;
    }

    public static function roleFor(int $userId): string
    {
        if ($userId <= 0) {
            return 'analista';
        }
        $user = Database::fetchOne("SELECT role FROM users WHERE id = ?", [$userId]);
        if ($user !== null && (string)($user['role'] ?? '') === 'admin') {
            return 'admin';
        }
        $role = self::all()[$userId] ?? 'analista';
        return in_array($role, self::ROLES, true) ? $role : 'analista';
    }

    public static function canWrite(int $userId): bool
    {
        $role = self::roleFor($userId);
        if ($role === 'admin') {
            return true;
        }
        if (!self::isConfigured()) {
            return true;
        }
        return $role !== 'lector';
    }

    public static function canApproveRisk(int $userId): bool
    {
        $role = self::roleFor($userId);
        if ($role === 'admin') {
            return true;
        }
        if (!self::isConfigured()) {
            return true;
        }
        return $role === 'aprobador';
    }

    public static function assign(int $userId, string $role): bool
    {
        if ($userId <= 0 || !in_array($role, self::ROLES, true)) {
            return false;
        }
        Database::query(
            "INSERT INTO remediation_roles (user_id, rol, updated_at)
             VALUES (?, ?, datetime('now'))
             ON CONFLICT(user_id) DO UPDATE SET rol = excluded.rol, updated_at = datetime('now')",
            [$userId, $role]
        );
        self::$map = null;
        self::$configured = null;
        return true;
    }
}
