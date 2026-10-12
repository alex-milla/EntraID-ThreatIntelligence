<?php
/**
 * Auth — Autenticación de usuarios del panel de administración.
 */

declare(strict_types=1);

class Auth
{
    private const SESSION_USER_KEY = 'auth_user_id';
    private const SESSION_LOGIN_TIME = 'auth_login_time';
    private const MAX_LOGIN_TIME = 7200; // 2 horas

    /**
     * Intenta iniciar sesión.
     */
    public static function attempt(string $username, string $password): bool
    {
        $user = Database::fetchOne(
            "SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1",
            [trim($username), trim($username)]
        );

        if (!$user) {
            // Delay para prevenir timing attacks
            usleep(random_int(100000, 300000));
            return false;
        }

        if (!Encryption::verifyPassword($password, $user['password_hash'])) {
            return false;
        }

        // Actualizar último login
        Database::update(
            "UPDATE users SET last_login_at = datetime('now'), updated_at = datetime('now') WHERE id = ?",
            [$user['id']]
        );

        // Guardar en sesión
        Session::regenerate();
        Session::set(self::SESSION_USER_KEY, (int)$user['id']);
        Session::set(self::SESSION_LOGIN_TIME, time());
        Session::set('auth_user', [
            'id'           => (int)$user['id'],
            'username'     => $user['username'],
            'email'        => $user['email'],
            'display_name' => $user['display_name'],
            'role'         => $user['role'],
        ]);

        log_activity('auth.login', ['username' => $user['username']]);
        return true;
    }

    /**
     * Cierra la sesión.
     */
    public static function logout(): void
    {
        $userId = self::id();
        log_activity('auth.logout', [], $userId);
        Session::destroy();
    }

    /**
     * Comprueba si hay un usuario autenticado.
     */
    public static function check(): bool
    {
        if (!Session::has(self::SESSION_USER_KEY)) {
            return false;
        }

        // Verificar expiración de sesión
        $loginTime = Session::get(self::SESSION_LOGIN_TIME, 0);
        if (time() - $loginTime > self::MAX_LOGIN_TIME) {
            self::logout();
            return false;
        }

        return true;
    }

    /**
     * Obtiene el ID del usuario actual.
     */
    public static function id(): ?int
    {
        return Session::get(self::SESSION_USER_KEY);
    }

    /**
     * Obtiene los datos del usuario actual.
     */
    public static function user(): ?array
    {
        if (!self::check()) {
            return null;
        }
        return Session::get('auth_user');
    }

    /**
     * Comprueba si el usuario actual es admin.
     */
    public static function isAdmin(): bool
    {
        $user = self::user();
        return $user !== null && $user['role'] === 'admin';
    }

    /**
     * Requiere autenticación (redirige a login si no hay sesión).
     */
    public static function require(): void
    {
        if (!self::check()) {
            flash('error', 'Debes iniciar sesión para acceder a esta página.');
            set_old_input(['username' => $_POST['username'] ?? '']);
            redirect(base_url('admin/login'));
        }
    }

    /**
     * Requiere rol de administrador.
     */
    public static function requireAdmin(): void
    {
        self::require();
        if (!self::isAdmin()) {
            flash('error', 'No tienes permisos para acceder a esta página.');
            redirect(base_url('admin'));
        }
    }

    /**
     * Cambia la contraseña del usuario actual.
     */
    public static function changePassword(int $userId, string $currentPassword, string $newPassword): array
    {
        $user = Database::fetchOne("SELECT * FROM users WHERE id = ?", [$userId]);
        if (!$user) {
            return ['success' => false, 'error' => 'Usuario no encontrado'];
        }

        if (!Encryption::verifyPassword($currentPassword, $user['password_hash'])) {
            return ['success' => false, 'error' => 'La contraseña actual es incorrecta'];
        }

        if (strlen($newPassword) < 8) {
            return ['success' => false, 'error' => 'La nueva contraseña debe tener al menos 8 caracteres'];
        }

        $hash = Encryption::hashPassword($newPassword);
        Database::update(
            "UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = datetime('now') WHERE id = ?",
            [$hash, $userId]
        );

        log_activity('auth.password_changed', [], $userId);
        return ['success' => true];
    }

    /**
     * Crea un nuevo usuario (solo admin).
     */
    public static function createUser(array $data): array
    {
        $errors = [];

        if (empty($data['username'])) $errors[] = 'El usuario es obligatorio';
        if (empty($data['email']) || !filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'El email no es válido';
        }
        if (empty($data['password']) || strlen($data['password']) < 8) {
            $errors[] = 'La contraseña debe tener al menos 8 caracteres';
        }
        if (!in_array($data['role'] ?? 'user', ['admin', 'user'], true)) {
            $errors[] = 'Rol no válido';
        }

        if (!empty($errors)) {
            return ['success' => false, 'errors' => $errors];
        }

        // Verificar unicidad
        $exists = Database::fetchOne(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            [$data['username'], $data['email']]
        );
        if ($exists) {
            return ['success' => false, 'errors' => ['El usuario o email ya existe']];
        }

        $hash = Encryption::hashPassword($data['password']);
        $id = Database::insert(
            "INSERT INTO users (username, email, password_hash, display_name, role, must_change_password)
             VALUES (?, ?, ?, ?, ?, ?)",
            [
                trim($data['username']),
                trim($data['email']),
                $hash,
                $data['display_name'] ?? null,
                $data['role'] ?? 'user',
                !empty($data['must_change_password']) ? 1 : 0,
            ]
        );

        log_activity('user.created', ['user_id' => $id, 'username' => $data['username']]);
        return ['success' => true, 'user_id' => $id];
    }

    /**
     * Edita un usuario existente (solo admin).
     * El username no se modifica. La contraseña es opcional (vacía = no cambiar);
     * si se establece, el usuario deberá cambiarla en su próximo login.
     */
    public static function updateUser(int $userId, array $data, ?int $actorId = null): array
    {
        $user = Database::fetchOne("SELECT * FROM users WHERE id = ?", [$userId]);
        if (!$user) {
            return ['success' => false, 'errors' => ['Usuario no encontrado']];
        }

        $errors = [];

        // Email
        $email = trim((string)($data['email'] ?? ''));
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'El email no es válido';
        } else {
            $dup = Database::fetchOne(
                "SELECT id FROM users WHERE email = ? AND id != ?",
                [$email, $userId]
            );
            if ($dup) {
                $errors[] = 'El email ya está en uso por otro usuario';
            }
        }

        // Rol
        $role = (string)($data['role'] ?? $user['role']);
        if (!in_array($role, ['admin', 'user'], true)) {
            $errors[] = 'Rol no válido';
        }

        // Nadie cambia su propio rol (evita auto-bloqueo por descuido)
        if ($actorId !== null && $actorId === $userId && $role !== $user['role']) {
            $errors[] = 'No puedes cambiar tu propio rol';
        }

        // El sistema siempre debe tener al menos un admin
        if ($user['role'] === 'admin' && $role !== 'admin') {
            $adminCount = (int)(Database::fetchOne(
                "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND id != ?",
                [$userId]
            )['c'] ?? 0);
            if ($adminCount < 1) {
                $errors[] = 'No puedes quitar el último administrador del sistema';
            }
        }

        // Contraseña nueva (opcional)
        $newPassword = (string)($data['password'] ?? '');
        if ($newPassword !== '' && strlen($newPassword) < 8) {
            $errors[] = 'La nueva contraseña debe tener al menos 8 caracteres';
        }

        if (!empty($errors)) {
            return ['success' => false, 'errors' => $errors];
        }

        // Si se establece contraseña nueva, forzar cambio en el próximo login
        $mustChange = !empty($data['must_change_password']) || $newPassword !== '';

        $sets = "email = ?, display_name = ?, role = ?, must_change_password = ?, updated_at = datetime('now')";
        $params = [
            $email,
            trim((string)($data['display_name'] ?? '')) ?: null,
            $role,
            $mustChange ? 1 : 0,
        ];
        if ($newPassword !== '') {
            $sets .= ', password_hash = ?';
            $params[] = Encryption::hashPassword($newPassword);
        }
        $params[] = $userId;

        Database::update("UPDATE users SET $sets WHERE id = ?", $params);

        log_activity('user.updated', [
            'user_id'       => $userId,
            'password_set'  => $newPassword !== '',
            'role'          => $role,
        ], $actorId);

        return ['success' => true];
    }
}
