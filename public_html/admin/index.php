<?php
/**
 * Admin — Panel de administración principal.
 * Funciona con o sin mod_rewrite (routing propio basado en PATH_INFO/REQUEST_URI).
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/bootstrap.php';

// ============================================================
// Detectar la sub-ruta de admin (compatible con y sin mod_rewrite)
// ============================================================

function getAdminPath(): string
{
    // Opción 1: PATH_INFO (sin mod_rewrite: /admin/index.php/login)
    if (!empty($_SERVER['PATH_INFO'])) {
        $p = trim($_SERVER['PATH_INFO'], '/');
        // /admin/index.php o /admin/index.php/index.php → dashboard
        return ($p === '' || $p === 'index.php') ? '' : $p;
    }

    // Opción 2: REQUEST_URI (con mod_rewrite: /admin/login -> admin/index.php)
    $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';

    // Quitar APP_URL si está en subdirectorio
    $appPath = parse_url(APP_URL, PHP_URL_PATH) ?? '';
    if ($appPath && $appPath !== '/' && str_starts_with($uri, $appPath)) {
        $uri = substr($uri, strlen($appPath));
    }

    if (preg_match('#^/admin(/.*)?$#', $uri, $matches)) {
        $p = trim($matches[1] ?? '', '/');
        // /admin y /admin/index.php son el dashboard, no una sub-ruta
        return ($p === '' || $p === 'index.php') ? '' : $p;
    }

    // Opción 3: parámetro _path (fallback universal)
    if (!empty($_GET['_path'])) {
        $p = trim($_GET['_path'], '/');
        return ($p === '' || $p === 'index.php') ? '' : $p;
    }

    return '';
}

// ============================================================
// Controlador del panel de administración
// ============================================================

class AdminController
{
    /**
     * Página de login (pública).
     */
    public static function login(): void
    {
        if (Auth::check()) {
            redirect(base_url('admin'));
        }

        $error = flash('error');

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            Csrf::validateOrFail();
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';

            if (empty($username) || empty($password)) {
                flash('error', 'Todos los campos son obligatorios');
                set_old_input(['username' => $username]);
                redirect(base_url('admin/login'));
            }

            if (Auth::attempt($username, $password)) {
                clear_old_input();
                $user = Auth::user();
                if (!empty($user['must_change_password'])) {
                    flash('warning', 'Debes cambiar tu contraseña antes de continuar.');
                    redirect(base_url('admin/change-password'));
                }
                redirect(base_url('admin'));
            }

            flash('error', 'Credenciales inválidas');
            set_old_input(['username' => $username]);
            redirect(base_url('admin/login'));
        }

        // Vista de login (pantalla completa, sin layout)
        $data = ['error' => $error, 'old' => old_input()];
        extract($data);
        require VIEWS_PATH . '/admin/login.php';
    }

    /**
     * Cerrar sesión.
     */
    public static function logout(): void
    {
        Auth::logout();
        redirect(base_url('admin/login'));
    }

    /**
     * Dashboard principal.
     */
    public static function dashboard(): void
    {
        Auth::require();

        $tenants = TenantManager::getAll();
        $groups = TenantManager::getGroups();
        $modules = ModuleManager::getActiveModules();

        // Estadísticas globales
        $totalStats = [
            'tenants'       => count($tenants),
            'activeTenants' => count(array_filter($tenants, fn($t) => $t['is_active'])),
            'modules'       => count($modules),
            'reports'       => (int)(Database::fetchOne("SELECT COUNT(*) as cnt FROM reports")['cnt'] ?? 0),
        ];

        // Últimas sincronizaciones
        $recentSyncs = Database::fetchAll(
            "SELECT s.*, t.name as tenant_name
             FROM sync_log s
             JOIN tenants t ON s.tenant_id = t.id
             ORDER BY s.started_at DESC LIMIT 10"
        );

        // Tenants con stats
        $tenantStats = [];
        foreach ($tenants as $t) {
            $tenantStats[$t['id']] = TenantManager::getStats($t['id']);
        }

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/dashboard.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Gestión de tenants (lista).
     */
    public static function tenants(): void
    {
        Auth::requireAdmin();

        $tenants = TenantManager::getAll();
        $groups = TenantManager::getGroups();

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/tenants.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Crear/editar tenant.
     */
    public static function tenantEdit(): void
    {
        Auth::requireAdmin();

        $id = (int)($_GET['id'] ?? 0);
        $tenant = $id ? TenantManager::getById($id) : null;
        $isEdit = $tenant !== null;
        $groups = TenantManager::getGroups();
        $error = flash('error');
        $success = flash('success');

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            Csrf::validateOrFail();
            $data = [
                'name'           => $_POST['name'] ?? '',
                'slug'           => $_POST['slug'] ?? '',
                'tenant_id'      => $_POST['tenant_id'] ?? '',
                'client_id'      => $_POST['client_id'] ?? '',
                'client_secret'  => $_POST['client_secret'] ?? '',
                'permissions'    => $_POST['permissions'] ?? [],
                'is_active'      => !empty($_POST['is_active']),
            ];

            if ($isEdit) {
                // En edición, el secret es opcional (solo si se proporciona)
                if (empty($data['client_secret'])) {
                    unset($data['client_secret']);
                }
                $result = TenantManager::update($id, $data);
            } else {
                $result = TenantManager::create($data);
            }

            if ($result['success']) {
                // Asignar a grupos
                $groupIds = $_POST['groups'] ?? [];
                if ($isEdit) {
                    Database::query("DELETE FROM tenant_group_members WHERE tenant_id = ?", [$id]);
                }
                $newId = $isEdit ? $id : $result['tenant_id'];
                foreach ($groupIds as $gid) {
                    TenantManager::addTenantToGroup($newId, (int)$gid);
                }

                flash('success', $isEdit ? 'Tenant actualizado correctamente' : 'Tenant creado correctamente');
                redirect(base_url('admin/tenants'));
            }

            flash('error', implode(', ', $result['errors'] ?? ['Error desconocido']));
            set_old_input($_POST);
            redirect(base_url('admin/tenant/edit' . ($isEdit ? "?id=$id" : '')));
        }

        $tenantGroups = $isEdit ? Database::fetchAll(
            "SELECT group_id FROM tenant_group_members WHERE tenant_id = ?",
            [$id]
        ) : [];
        $tenantGroupIds = array_column($tenantGroups, 'group_id');

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/tenant_edit.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Eliminar tenant (POST).
     */
    public static function tenantDelete(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        if (TenantManager::delete($id)) {
            flash('success', 'Tenant eliminado correctamente');
        } else {
            flash('error', 'Error al eliminar el tenant');
        }
        redirect(base_url('admin/tenants'));
    }

    /**
     * Activar/desactivar tenant.
     */
    public static function tenantToggle(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        TenantManager::toggleActive($id);
        redirect(base_url('admin/tenants'));
    }

    /**
     * Gestión de usuarios.
     */
    public static function users(): void
    {
        Auth::requireAdmin();

        $users = Database::fetchAll("SELECT id, username, email, display_name, role, last_login_at, created_at, must_change_password FROM users ORDER BY username");
        $error = flash('error');
        $success = flash('success');

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/users.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Crear usuario.
     */
    public static function userCreate(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        if (($_POST['password'] ?? '') !== ($_POST['password_confirm'] ?? '')) {
            flash('error', 'La contraseña y su confirmación no coinciden');
            redirect(base_url('admin/users'));
        }

        $result = Auth::createUser([
            'username'             => $_POST['username'] ?? '',
            'email'                => $_POST['email'] ?? '',
            'password'             => $_POST['password'] ?? '',
            'display_name'         => $_POST['display_name'] ?? '',
            'role'                 => $_POST['role'] ?? 'user',
            'must_change_password' => !empty($_POST['must_change_password']),
        ]);

        if ($result['success']) {
            flash('success', 'Usuario creado correctamente');
        } else {
            flash('error', implode(', ', $result['errors'] ?? ['Error desconocido']));
        }
        redirect(base_url('admin/users'));
    }

    /**
     * Editar usuario existente (solo admin).
     * Editarse a uno mismo exige la contraseña actual como verificación extra.
     */
    public static function userEdit(): void
    {
        Auth::requireAdmin();

        $id = (int)($_GET['id'] ?? 0);
        $user = $id ? Database::fetchOne("SELECT * FROM users WHERE id = ?", [$id]) : null;
        if (!$user) {
            flash('error', 'Usuario no encontrado');
            redirect(base_url('admin/users'));
        }

        $isSelf = ($id === Auth::id());
        $error = flash('error');

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            Csrf::validateOrFail();

            // Confirmación de la nueva contraseña (si se rellena)
            $newPassword = (string)($_POST['password'] ?? '');
            $confirm = (string)($_POST['password_confirm'] ?? '');
            if ($newPassword !== $confirm) {
                flash('error', 'La nueva contraseña y su confirmación no coinciden');
                redirect(base_url('admin/user/edit?id=' . $id));
            }

            // Verificación extra al editarse a uno mismo
            if ($isSelf && !Encryption::verifyPassword($_POST['current_password'] ?? '', $user['password_hash'])) {
                flash('error', 'Debes introducir tu contraseña actual correctamente');
                redirect(base_url('admin/user/edit?id=' . $id));
            }

            try {
                $result = Auth::updateUser($id, [
                    'username'             => $_POST['username'] ?? $user['username'],
                    'email'                => $_POST['email'] ?? '',
                    'display_name'         => $_POST['display_name'] ?? '',
                    'role'                 => $_POST['role'] ?? $user['role'],
                    'password'             => $newPassword,
                    'must_change_password' => !empty($_POST['must_change_password']),
                ], Auth::id());
            } catch (Throwable $e) {
                log_activity('user.update_error', ['user_id' => $id, 'error' => $e->getMessage()]);
                flash('error', 'Error del servidor al guardar: ' . $e->getMessage());
                redirect(base_url('admin/user/edit?id=' . $id));
            }

            if ($result['success']) {
                // Verificación post-escritura de la contraseña
                if ($newPassword !== '') {
                    $freshHash = Database::fetchOne("SELECT password_hash FROM users WHERE id = ?", [$id]);
                    if (!$freshHash || !Encryption::verifyPassword($newPassword, $freshHash['password_hash'])) {
                        log_activity('user.password_verify_failed', ['user_id' => $id]);
                        flash('error', 'La contraseña no quedó guardada correctamente (verificación post-escritura fallida). Revisa el log de actividad.');
                        redirect(base_url('admin/user/edit?id=' . $id));
                    }
                }

                if ($isSelf) {
                    // El admin conoce la contraseña que acaba de ponerse:
                    // no forzarle otro cambio en el próximo login
                    Database::update("UPDATE users SET must_change_password = 0 WHERE id = ?", [$id]);

                    // Refrescar la sesión con los datos nuevos
                    $fresh = Database::fetchOne("SELECT * FROM users WHERE id = ?", [$id]);
                    Session::set('auth_user', [
                        'id'           => $id,
                        'username'     => $fresh['username'],
                        'email'        => $fresh['email'],
                        'display_name' => $fresh['display_name'],
                        'role'         => $fresh['role'],
                    ]);
                }
                // Feedback explícito sobre la contraseña
                flash('success', $newPassword !== ''
                    ? 'Usuario actualizado. Contraseña modificada correctamente.'
                    : 'Usuario actualizado. La contraseña NO se ha modificado.');
                redirect(base_url('admin/users'));
            }

            flash('error', implode(', ', $result['errors']));
            redirect(base_url('admin/user/edit?id=' . $id));
        }

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/user_edit.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Eliminar usuario.
     */
    public static function userDelete(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        if ($id === Auth::id()) {
            flash('error', 'No puedes eliminar tu propio usuario');
            redirect(base_url('admin/users'));
        }

        Database::query("DELETE FROM users WHERE id = ?", [$id]);
        flash('success', 'Usuario eliminado');
        redirect(base_url('admin/users'));
    }

    /**
     * Gestión de módulos (activar/desactivar).
     */
    public static function modules(): void
    {
        Auth::requireAdmin();

        $allModules = Database::fetchAll("SELECT * FROM modules ORDER BY module_key");
        $success = flash('success');
        $error = flash('error');

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/modules.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Activar/desactivar módulo.
     */
    public static function moduleToggle(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $key = $_POST['module_key'] ?? '';
        $action = $_POST['action'] ?? 'activate';

        if ($action === 'activate') {
            ModuleManager::activate($key);
            flash('success', "Módulo $key activado");
        } else {
            ModuleManager::deactivate($key);
            flash('success', "Módulo $key desactivado");
        }

        redirect(base_url('admin/modules'));
    }

    /**
     * Configuración global.
     */
    public static function settings(): void
    {
        Auth::requireAdmin();

        $success = flash('success');
        $error = flash('error');

        // Obtener settings actuales (no sensibles)
        $settings = Database::fetchAll("SELECT setting_key, setting_value, is_encrypted FROM settings");
        $settingsMap = [];
        foreach ($settings as $s) {
            $settingsMap[$s['setting_key']] = $s;
        }

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/settings.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Guardar configuración.
     */
    public static function settingsSave(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        foreach ($_POST['settings'] ?? [] as $key => $value) {
            $isEncrypted = !empty($_POST['encrypted'][$key]) ? 1 : 0;
            $storedValue = $value;

            if ($isEncrypted && !empty($value)) {
                $storedValue = Encryption::encryptCombined($value);
            }

            Database::query(
                "INSERT OR REPLACE INTO settings (setting_key, setting_value, is_encrypted, updated_at)
                 VALUES (?, ?, ?, datetime('now'))",
                [$key, $storedValue, $isEncrypted]
            );
        }

        flash('success', 'Configuración guardada correctamente');
        redirect(base_url('admin/settings'));
    }

    /**
     * Panel de configuración de APIs (LLM: OpenAI, Anthropic, Azure, Ollama, Gemini).
     */
    public static function apis(): void
    {
        Auth::requireAdmin();

        $success = flash('success');
        $error = flash('error');
        $cfg = llm_config();
        $keySet = $cfg['api_key'] !== '';

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/apis.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Guarda la configuración de APIs.
     * La API key se guarda cifrada (AES-256) y solo se actualiza si se envía.
     */
    public static function apisSave(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $allowed = ['', 'openai', 'anthropic', 'azure', 'ollama', 'gemini', 'mistral', 'custom'];
        $provider = strtolower(trim((string)($_POST['llm_provider'] ?? '')));
        if (!in_array($provider, $allowed, true)) {
            $provider = '';
        }

        setting_set('llm_provider', $provider);
        setting_set('llm_api_url', trim((string)($_POST['llm_api_url'] ?? '')));
        setting_set('llm_model', trim((string)($_POST['llm_model'] ?? '')));

        // Max tokens: si se deja vacío, usar el valor por defecto (no 1)
        $mtRaw = trim((string)($_POST['llm_max_tokens'] ?? ''));
        $maxTokens = ($mtRaw === '') ? 2048 : max(1, min(128000, (int)$mtRaw));
        setting_set('llm_max_tokens', (string)$maxTokens);

        // La API key nunca se muestra en el formulario: solo se actualiza si viene una nueva,
        // salvo que se marque explícitamente "borrar".
        $key = trim((string)($_POST['llm_api_key'] ?? ''));
        $clear = !empty($_POST['llm_api_key_clear']);
        if ($key !== '' && ENCRYPTION_KEY === '') {
            flash('error', 'No se puede guardar la API key: falta ENCRYPTION_KEY en el .env.');
            redirect(base_url('admin/apis'));
        }
        if ($key !== '') {
            setting_set('llm_api_key', $key, true);
        } elseif ($clear) {
            setting_set('llm_api_key', '', true);
        }

        log_activity('settings.apis_saved', ['provider' => $provider]);
        flash('success', 'Configuración de APIs guardada correctamente');
        redirect(base_url('admin/apis'));
    }

    /**
     * Prueba la conexión con el proveedor LLM configurado (respuesta JSON).
     */
    public static function apisTest(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $module = ModuleManager::get('llm');
        if (!$module) {
            json_response(['success' => false, 'error' => 'El módulo LLM no está activo'], 400);
        }

        $override = [];
        $provider = strtolower(trim((string)($input['llm_provider'] ?? '')));
        if ($provider !== '') { $override['provider'] = $provider; }
        $url = trim((string)($input['llm_api_url'] ?? ''));
        if ($url !== '') { $override['api_url'] = $url; }
        $model = trim((string)($input['llm_model'] ?? ''));
        if ($model !== '') { $override['model'] = $model; }
        $key = trim((string)($input['llm_api_key'] ?? ''));
        if ($key !== '') { $override['api_key'] = $key; }

        json_response($module->testConnection($override));
    }

    /**
     * Actualizaciones del sistema desde GitHub (solo admin).
     * GET: estado (versión instalada vs última release, backups).
     * POST: install / restore (CSRF + backup automático + PRG).
     */
    public static function updates(): void
    {
        Auth::requireAdmin();
        require_once INCLUDES_PATH . '/updater.php';

        $cfg = updater_config();
        $error = flash('error');
        $success = flash('success');

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            Csrf::validateOrFail();
            @set_time_limit(300);
            ignore_user_abort(true);

            $action = $_POST['action'] ?? '';
            try {
                if ($action === 'install') {
                    $force = !empty($_POST['force']);
                    $release = updater_latest_release($cfg);

                    if (!$release['ok']) {
                        flash('error', 'No se pudo consultar GitHub: ' . $release['error']);
                    } else {
                        $installed = updater_installed_version();
                        if (!$force && version_compare($installed, $release['version'], '>=')) {
                            flash('error', "Ya estás al día (v$installed >= v{$release['version']}). Usa la reinstalación forzada si lo necesitas.");
                        } else {
                            $result = updater_run_update($cfg, $release);
                            log_activity($result['success'] ? 'system.updated' : 'system.update_failed', [
                                'version' => $release['version'],
                                'message' => $result['message'],
                            ]);
                            flash($result['success'] ? 'success' : 'error', $result['message']);
                        }
                    }
                } elseif ($action === 'restore') {
                    $name = (string)($_POST['backup'] ?? '');
                    if (!preg_match('/^backup_\d{8}_\d{6}(_\d+)?$/', $name)) {
                        flash('error', 'Nombre de backup inválido');
                    } else {
                        $backupDir = realpath($cfg['backup_base'] . '/' . $name);
                        $realBase = realpath($cfg['backup_base']);
                        if ($backupDir === false || $realBase === false || !str_starts_with($backupDir, $realBase)) {
                            flash('error', 'Backup no encontrado');
                        } else {
                            $res = updater_restore_backup($backupDir, ROOT_PATH, $cfg);
                            log_activity('system.restored', ['backup' => $name]);
                            flash('success', "Restaurado $name ({$res['restored']} ficheros). Backup del estado previo: " . basename($res['pre']['dir']));
                        }
                    }
                } else {
                    flash('error', 'Acción no válida');
                }
            } catch (Throwable $e) {
                flash('error', 'Error durante la operación: ' . $e->getMessage());
            }

            redirect(base_url('admin/updates'));
        }

        // GET: estado del sistema
        $installedVersion = updater_installed_version();
        $release = updater_latest_release($cfg);
        $backups = updater_list_backups($cfg);

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/update.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Cambio de contraseña obligatorio.
     */
    public static function changePassword(): void
    {
        Auth::require();

        $error = flash('error');
        $success = flash('success');

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            Csrf::validateOrFail();

            if (($_POST['new_password'] ?? '') !== ($_POST['new_password_confirm'] ?? '')) {
                flash('error', 'La nueva contraseña y su confirmación no coinciden');
                redirect(base_url('admin/change-password'));
            }

            $result = Auth::changePassword(
                Auth::id(),
                $_POST['current_password'] ?? '',
                $_POST['new_password'] ?? ''
            );

            if ($result['success']) {
                flash('success', 'Contraseña actualizada correctamente');
                redirect(base_url('admin'));
            }
            flash('error', $result['error']);
            redirect(base_url('admin/change-password'));
        }

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/change_password.php';
        require VIEWS_PATH . '/layout/footer.php';
    }
}

// ============================================================
// ROUTING — Despachar la petición al método correspondiente
// ============================================================

$adminPath = getAdminPath();
$httpMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Middleware CSRF global
Csrf::middleware();

// Tabla de rutas: método HTTP => [ruta => método del controlador]
$adminRoutes = [
    'GET' => [
        ''                 => 'dashboard',
        'dashboard'        => 'dashboard',
        'login'            => 'login',
        'logout'           => 'logout',
        'tenants'          => 'tenants',
        'tenant/edit'      => 'tenantEdit',
        'users'            => 'users',
        'user/edit'        => 'userEdit',
        'modules'          => 'modules',
        'settings'         => 'settings',
        'apis'             => 'apis',
        'updates'          => 'updates',
        'change-password'  => 'changePassword',
    ],
    'POST' => [
        'login'            => 'login',
        'tenant/edit'      => 'tenantEdit',
        'tenant/delete'    => 'tenantDelete',
        'tenant/toggle'    => 'tenantToggle',
        'user/create'      => 'userCreate',
        'user/delete'      => 'userDelete',
        'user/edit'        => 'userEdit',
        'module/toggle'    => 'moduleToggle',
        'settings/save'    => 'settingsSave',
        'apis/save'        => 'apisSave',
        'apis/test'        => 'apisTest',
        'updates'          => 'updates',
        'change-password'  => 'changePassword',
    ],
];

// Buscar la ruta
if (isset($adminRoutes[$httpMethod][$adminPath])) {
    $action = $adminRoutes[$httpMethod][$adminPath];
    AdminController::$action();
    return;
}

// Ruta no encontrada
http_response_code(404);
echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>404</title></head><body>';
echo '<h1>404 - Página no encontrada</h1>';
echo '<p>La ruta <code>' . htmlspecialchars($httpMethod . ' /admin/' . $adminPath) . '</code> no existe.</p>';
echo '<p><a href="' . base_url('admin') . '">Volver al dashboard</a></p>';
echo '</body></html>';
