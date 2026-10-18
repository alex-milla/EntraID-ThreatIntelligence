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
                Auth::recordLogin((string)$username, null, false, 'empty');
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

        // Sector a priorizar (tenant activo, últimas 24 h) — información general.
        $sectorPriority = null;
        $priorityTenant = null;
        foreach ($tenants as $t) {
            if (!empty($t['is_active'])) { $priorityTenant = $t; break; }
        }
        if ($priorityTenant && class_exists('Module_ThreatIntelligence')) {
            $tiModule = ModuleManager::get('threat_intelligence');
            if ($tiModule instanceof Module_ThreatIntelligence) {
                try {
                    $to   = gmdate('Y-m-d');
                    $from = gmdate('Y-m-d', strtotime($to) - 86400);
                    $st   = $tiModule->getSectorStats((int)$priorityTenant['id'], ['from' => $from, 'to' => $to]);
                    if (!empty($st['total'])) {
                        $sectorPriority = ['tenant' => $priorityTenant, 'stats' => $st, 'from' => $from, 'to' => $to];
                    }
                } catch (Throwable $e) {
                    $sectorPriority = null;
                }
            }
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
     * Panel de configuración de APIs / perfiles de IA.
     */
    public static function apis(): void
    {
        Auth::requireAdmin();
        llm_migrate_legacy_profile();

        $success = flash('success');
        $error = flash('error');

        $profiles = llm_profile_list();
        $editId = (int)($_GET['edit'] ?? 0);
        $editProfile = $editId ? llm_profile_get($editId) : null;

        $tasks = [
            'summarize_report' => 'Resumen de reporte',
            'classify_iocs'    => 'Clasificar IOCs',
            'extract_iocs'     => 'Extraer IOCs',
            'analyze_incident' => 'Analizar incidente',
            'analyze_tenant'   => 'Analizar tenant (Análisis IA)',
            'analyze_article'  => 'Analizar artículo (Threat Intel)',
            'translate_article'=> 'Traducir artículo (Threat Intel)',
            'cve_report'       => 'Informe de CVE con IA',
            'chat'             => 'Chat / Análisis IA',
        ];
        $taskProfiles = [];
        foreach (array_keys($tasks) as $t) {
            $taskProfiles[$t] = llm_task_profile($t);
        }

        // Fuentes públicas de CVEs (Fase 1).
        $cve = CveClient::config();
        $cve['nvd_key_set'] = setting_get('cve_nvd_api_key', CVE_NVD_API_KEY) !== '';
        $cveState = null;
        $cveCounts = ['catalog' => 0, 'kev' => 0, 'epss' => 0, 'software' => 0, 'groups' => 0, 'matches' => 0];
        $cveError = null;
        try {
            $cveState = CveDatabase::fetchOne("SELECT * FROM cve_sync_state WHERE id = 1");
            if (is_array($cveState)) {
                unset($cveState['token'], $cveState['base_url']);
            }
            $cveCounts = [
                'catalog'  => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_catalog")['c'] ?? 0),
                'kev'      => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_kev")['c'] ?? 0),
                'epss'     => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_epss")['c'] ?? 0),
                'software' => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM software_watchlist")['c'] ?? 0),
                'groups'   => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM software_groups")['c'] ?? 0),
                'matches'  => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_watchlist_match")['c'] ?? 0),
            ];
        } catch (Throwable $e) {
            $cveError = $e->getMessage();
        }

        // Log visible de sincronización (errores y cierres) + tamaño efectivo.
        $cveLog = [];
        $cvePage = [
            'configured' => 0,
            'effective'  => 0,
            'memory'     => 0,
            'degraded'   => false,
            'has_key'    => false,
            'rate_max'   => 5,
            'rate_window'=> 30,
        ];
        try {
            $cveLog = CveDatabase::fetchAll("SELECT * FROM cve_sync_log ORDER BY id DESC LIMIT 15");
            $cvePage = CveSync::pageSizeStatus();
        } catch (Throwable $e) {
            // El panel sigue funcionando aunque el log no esté disponible.
        }

        // Informe automático desde Defender (Fase C).
        $defReport = [
            'enabled'   => setting_get('cve_def_report_enabled', '0') === '1',
            'limit'     => max(1, min(50, (int)setting_get('cve_def_report_limit', '10'))),
            'tenant_id' => (int)setting_get('cve_def_report_tenant', '0'),
            'group_id'  => (int)setting_get('cve_def_report_group', '0'),
            'severity'  => (string)setting_get('cve_def_report_severity', ''),
            'exploited' => setting_get('cve_def_report_exploited', '0') === '1',
            'kev'       => setting_get('cve_def_report_kev', '0') === '1',
            'no_ai'     => setting_get('cve_def_report_no_ai', '0') === '1',
        ];
        $cveGroups = [];
        try {
            $cveGroups = CveDatabase::fetchAll("SELECT id, name FROM software_groups ORDER BY name");
        } catch (Throwable $e) {
            $cveGroups = [];
        }
        $tenants = Database::fetchAll("SELECT id, name FROM tenants ORDER BY name");

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/apis.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Guarda (crea o edita) un perfil de IA. La API key se guarda cifrada
     * (AES-GCM) y solo se actualiza si se envía una nueva.
     */
    public static function apisSave(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        $allowed = ['', 'openai', 'anthropic', 'azure', 'ollama', 'ollama_cloud', 'gemini', 'mistral', 'custom'];
        $provider = strtolower(trim((string)($_POST['provider'] ?? '')));
        if (!in_array($provider, $allowed, true)) {
            $provider = '';
        }

        $name = trim((string)($_POST['name'] ?? ''));
        if ($name === '') {
            $name = $provider !== '' ? ucfirst($provider) : 'Perfil';
        }

        $key = trim((string)($_POST['api_key'] ?? ''));
        $needsKey = $provider !== 'ollama';
        if ($key !== '' && $needsKey && ENCRYPTION_KEY === '') {
            flash('error', 'No se puede guardar la API key: falta ENCRYPTION_KEY en el .env.');
            redirect(base_url('admin/apis'));
        }

        $newId = llm_profile_save([
            'name'       => $name,
            'provider'   => $provider,
            'api_url'    => trim((string)($_POST['api_url'] ?? '')),
            'model'      => trim((string)($_POST['model'] ?? '')),
            'max_tokens' => (int)($_POST['max_tokens'] ?? 2048),
            'api_key'    => $key,
        ], $id ?: null);

        if (!empty($_POST['is_default']) || llm_profile_default() === null) {
            llm_profile_set_default($newId);
        }

        log_activity('settings.api_saved', ['profile_id' => $newId, 'provider' => $provider]);
        flash('success', 'Perfil guardado correctamente');
        redirect(base_url('admin/apis'));
    }

    /**
     * Marca un perfil como predeterminado.
     */
    public static function apisDefault(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0 && llm_profile_get($id) !== null) {
            llm_profile_set_default($id);
            flash('success', 'Perfil predeterminado actualizado');
        }
        redirect(base_url('admin/apis'));
    }

    /**
     * Elimina un perfil de IA.
     */
    public static function apisDelete(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            llm_profile_delete($id);
            flash('success', 'Perfil eliminado');
        }
        redirect(base_url('admin/apis'));
    }

    /**
     * Guarda el mapa "tarea → perfil".
     */
    public static function apisTasks(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        foreach (($_POST['tasks'] ?? []) as $task => $pid) {
            if (is_string($task) && preg_match('/^[a-z_]+$/', $task)) {
                setting_set('llm_task_' . $task, (string)((int)$pid));
            }
        }
        flash('success', 'Modelo por tarea guardado');
        redirect(base_url('admin/apis'));
    }

    /**
     * Guarda la configuración de las fuentes públicas de CVEs.
     */
    public static function cveSave(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $nvdUrl = trim((string)($_POST['nvd_url'] ?? CVE_NVD_URL));
        $kevUrl = trim((string)($_POST['kev_url'] ?? CVE_KEV_URL));
        $kevFallbackUrl = trim((string)($_POST['kev_fallback_url'] ?? ''));
        if ($kevFallbackUrl === '') {
            $kevFallbackUrl = CVE_KEV_FALLBACK_URL;
        }
        $epssUrl = trim((string)($_POST['epss_url'] ?? CVE_EPSS_CSV_URL));

        foreach (['NVD' => $nvdUrl, 'KEV' => $kevUrl, 'KEV (respaldo)' => $kevFallbackUrl, 'EPSS' => $epssUrl] as $label => $url) {
            if (!CveClient::isSafeUrl($url)) {
                flash('error', "La URL de $label no es válida: se requiere HTTPS público.");
                redirect(base_url('admin/apis'));
            }
        }

        $key = trim((string)($_POST['nvd_api_key'] ?? ''));
        $clearKey = !empty($_POST['clear_nvd_key']);
        if ($key !== '' && ENCRYPTION_KEY === '') {
            flash('error', 'No se puede guardar la API key de NVD: falta ENCRYPTION_KEY en el .env.');
            redirect(base_url('admin/apis'));
        }

        $pageSize = (int)($_POST['nvd_page_size'] ?? CVE_NVD_PAGE_SIZE);
        if (!in_array($pageSize, [500, 1000, 2000], true)) {
            $pageSize = CVE_NVD_PAGE_SIZE;
        }
        $scope = (string)($_POST['scope'] ?? 'full');
        if (!in_array($scope, ['full', 'recent', 'kev'], true)) {
            $scope = 'full';
        }
        $recentYears = max(1, min(10, (int)($_POST['recent_years'] ?? 3)));
        $minCvss = max(0.0, min(10.0, (float)($_POST['min_cvss'] ?? 0)));
        $autoSync = !empty($_POST['auto_sync']) ? 1 : 0;
        $interval = max(1, min(168, (int)($_POST['interval_hours'] ?? 24)));

        setting_set('cve_nvd_url', $nvdUrl);
        setting_set('cve_kev_url', $kevUrl);
        setting_set('cve_kev_fallback_url', $kevFallbackUrl);
        setting_set('cve_epss_url', $epssUrl);
        setting_set('cve_nvd_page_size', (string)$pageSize);
        setting_set('cve_scope', $scope);
        setting_set('cve_recent_years', (string)$recentYears);
        setting_set('cve_min_cvss', (string)$minCvss);
        setting_set('cve_auto_sync', (string)$autoSync);
        setting_set('cve_interval_hours', (string)$interval);

        if ($clearKey) {
            setting_set('cve_nvd_api_key', '');
        } elseif ($key !== '') {
            try {
                setting_set('cve_nvd_api_key', $key, true);
            } catch (Throwable $e) {
                flash('error', 'No se pudo cifrar/guardar la API key de NVD: ' . $e->getMessage());
                redirect(base_url('admin/apis'));
            }
        }

        log_activity('cve.settings_saved', [
            'scope'     => $scope,
            'page_size' => $pageSize,
            'auto_sync' => $autoSync,
            'key_set'   => $clearKey ? false : ($key !== '' || setting_get('cve_nvd_api_key', CVE_NVD_API_KEY) !== ''),
        ]);
        flash('success', 'Configuración de fuentes de CVEs guardada.');
        redirect(base_url('admin/apis'));
    }

    /**
     * Guarda la configuración del informe automático desde Defender.
     */
    public static function cveDefenderReportSave(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $enabled = !empty($_POST['def_enabled']) ? '1' : '0';
        $limit = max(1, min(50, (int)($_POST['def_limit'] ?? 10)));
        $tenantId = max(0, (int)($_POST['def_tenant'] ?? 0));
        $groupId = max(0, (int)($_POST['def_group'] ?? 0));
        $severity = (string)($_POST['def_severity'] ?? '');
        if (!in_array($severity, ['', 'Critical', 'High', 'Medium', 'Low'], true)) {
            $severity = '';
        }
        $exploited = !empty($_POST['def_exploited']) ? '1' : '0';
        $kev = !empty($_POST['def_kev']) ? '1' : '0';
        $noAi = !empty($_POST['def_no_ai']) ? '1' : '0';

        if ($tenantId > 0 && Database::fetchOne("SELECT id FROM tenants WHERE id = ?", [$tenantId]) === null) {
            flash('error', 'El tenant seleccionado no existe.');
            redirect(base_url('admin/apis'));
        }
        if ($groupId > 0 && CveDatabase::fetchOne("SELECT id FROM software_groups WHERE id = ?", [$groupId]) === null) {
            flash('error', 'El grupo seleccionado no existe.');
            redirect(base_url('admin/apis'));
        }

        setting_set('cve_def_report_enabled', $enabled);
        setting_set('cve_def_report_limit', (string)$limit);
        setting_set('cve_def_report_tenant', (string)$tenantId);
        setting_set('cve_def_report_group', (string)$groupId);
        setting_set('cve_def_report_severity', $severity);
        setting_set('cve_def_report_exploited', $exploited);
        setting_set('cve_def_report_kev', $kev);
        setting_set('cve_def_report_no_ai', $noAi);

        log_activity('cve.defender_report_saved', [
            'enabled'   => $enabled,
            'limit'     => $limit,
            'tenant_id' => $tenantId,
            'group_id'  => $groupId,
            'severity'  => $severity,
        ]);

        flash('success', 'Configuración del informe automático desde Defender guardada.');
        redirect(base_url('admin/apis'));
    }

    /**
     * Prueba NVD, CISA KEV y EPSS sin descargar el catálogo completo.
     */
    public static function cveTest(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $client = CveClient::fromSettings();
            json_response($client->testAll());
        } catch (Throwable $e) {
            json_response([
                'success' => false,
                'error'   => $e->getMessage(),
            ]);
        }
    }

    /**
     * Estado del catálogo CVE (para el panel de Admin → APIs).
     */
    public static function cveStatus(): void
    {
        Auth::requireAdmin();

        try {
            $state = CveDatabase::fetchOne("SELECT * FROM cve_sync_state WHERE id = 1");
            if (is_array($state)) {
                unset($state['token'], $state['base_url']);
            }
            $counts = [
                'catalog'  => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_catalog")['c'] ?? 0),
                'kev'      => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_kev")['c'] ?? 0),
                'epss'     => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_epss")['c'] ?? 0),
                'software' => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM software_watchlist")['c'] ?? 0),
                'groups'   => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM software_groups")['c'] ?? 0),
                'matches'  => (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_watchlist_match")['c'] ?? 0),
            ];
            json_response(['success' => true, 'state' => $state, 'counts' => $counts]);
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()]);
        }
    }

    /**
     * Prueba la conexión con un proveedor LLM (perfil guardado o valores del formulario).
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

        json_response($module->testConnection(llm_cfg_from_input($input)));
    }

    /**
     * Verifica que la API key de Ollama funciona (lista de modelos).
     */
    public static function apisVerify(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $module = ModuleManager::get('llm');
        if (!$module) {
            json_response(['success' => false, 'error' => 'El módulo LLM no está activo'], 400);
        }

        json_response($module->verifyOllama(llm_cfg_from_input($input)));
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

    /**
     * Panel de Seguridad: intentos de acceso y detección de fuerza bruta.
     */
    public static function security(): void
    {
        Auth::requireAdmin();

        // Purga de registros antiguos (retención).
        try {
            Database::query("DELETE FROM login_attempts WHERE created_at < datetime('now', ?)", ['-' . (int)LOGIN_RETENTION_DAYS . ' days']);
        } catch (Throwable $e) { /* noop */ }

        $filters = [
            'result' => (string)($_GET['result'] ?? ''),   // '' | 'ok' | 'fail'
            'user'   => trim((string)($_GET['user'] ?? '')),
            'ip'     => trim((string)($_GET['ip'] ?? '')),
            'from'   => trim((string)($_GET['from'] ?? '')),
            'to'     => trim((string)($_GET['to'] ?? '')),
        ];
        $page = max(1, (int)($_GET['page'] ?? 1));
        $perPage = 50;

        $where = ['1=1'];
        $params = [];
        if ($filters['result'] === 'ok')   { $where[] = 'success = 1'; }
        if ($filters['result'] === 'fail') { $where[] = 'success = 0'; }
        if ($filters['user'] !== '') { $where[] = 'username LIKE ?'; $params[] = '%' . $filters['user'] . '%'; }
        if ($filters['ip'] !== '')   { $where[] = 'ip LIKE ?'; $params[] = '%' . $filters['ip'] . '%'; }
        if ($filters['from'] !== '') { $where[] = 'date(created_at) >= ?'; $params[] = $filters['from']; }
        if ($filters['to'] !== '')   { $where[] = 'date(created_at) <= ?'; $params[] = $filters['to']; }
        $whereClause = implode(' AND ', $where);

        $total = (int)(Database::fetchOne("SELECT COUNT(*) c FROM login_attempts WHERE $whereClause", $params)['c'] ?? 0);
        $offset = ($page - 1) * $perPage;
        $listParams = $params;
        $listParams[] = $perPage;
        $listParams[] = $offset;
        $attempts = Database::fetchAll(
            "SELECT * FROM login_attempts WHERE $whereClause ORDER BY id DESC LIMIT ? OFFSET ?",
            $listParams
        );

        // Resumen (24 h).
        $summary = Database::fetchOne(
            "SELECT COUNT(*) AS total,
                    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS ok
             FROM login_attempts WHERE created_at >= datetime('now', '-1 day')"
        ) ?? ['total' => 0, 'failed' => 0, 'ok' => 0];

        // IPs sospechosas: fallos en la ventana >= umbral.
        $windowMod = '-' . (int)LOGIN_BRUTE_WINDOW_MIN . ' minutes';
        $threshold = (int)LOGIN_BRUTE_THRESHOLD;
        $suspects = Database::fetchAll(
            "SELECT ip, COUNT(*) AS fails, COUNT(DISTINCT username) AS users, MAX(created_at) AS last_seen
             FROM login_attempts
             WHERE success = 0 AND created_at >= datetime('now', ?)
             GROUP BY ip HAVING fails >= $threshold ORDER BY fails DESC LIMIT 20",
            [$windowMod]
        );

        // Usuarios más atacados (24 h).
        $topUsers = Database::fetchAll(
            "SELECT username, COUNT(*) AS fails
             FROM login_attempts
             WHERE success = 0 AND username IS NOT NULL AND created_at >= datetime('now', '-1 day')
             GROUP BY username ORDER BY fails DESC LIMIT 10"
        );

        $totalPages = max(1, (int)ceil($total / $perPage));

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/security.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Panel de Almacenamiento: ocupación de la BD, del disco del hosting y PHP.
     */
    public static function storage(): void
    {
        Auth::requireAdmin();

        $refresh = !empty($_GET['refresh']);
        // v2: incluye el desglose del catálogo CVE (cve.sqlite). El cambio de
        // clave invalida las estadísticas antiguas cacheadas sin ese bloque.
        $cacheKey = 'storage_stats_cache_v2';
        $stats = null;

        if (!$refresh) {
            $cached = setting_get($cacheKey);
            if (is_string($cached) && $cached !== '') {
                $data = safe_json_decode($cached, null);
                if (is_array($data) && isset($data['ts'], $data['stats']) && (time() - (int)$data['ts']) < 300) {
                    $stats = $data['stats'];
                }
            }
        }

        if ($stats === null) {
            $stats = self::computeStorageStats();
            setting_set($cacheKey, json_encode(['ts' => time(), 'stats' => $stats]));
        }

        $success = flash('success');
        $error = flash('error');

        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/storage.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Calcula las métricas de almacenamiento (BD, disco y PHP).
     */
    private static function computeStorageStats(): array
    {
        $dbPath = DB_PATH;
        $dbSize = is_file($dbPath) ? (int)filesize($dbPath) : 0;
        $walSize = is_file($dbPath . '-wal') ? (int)filesize($dbPath . '-wal') : 0;
        $shmSize = is_file($dbPath . '-shm') ? (int)filesize($dbPath . '-shm') : 0;

        $tables = [];
        $totalRows = 0;
        try {
            foreach (Database::fetchAll("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name") as $t) {
                $name = (string)$t['name'];
                try {
                    $c = (int)Database::fetchOne('SELECT COUNT(*) AS c FROM "' . $name . '"')['c'];
                } catch (Throwable $e) {
                    $c = 0;
                }
                $tables[$name] = $c;
                $totalRows += $c;
            }
        } catch (Throwable $e) {}
        arsort($tables);

        $pageCount = 0;
        $pageSize = 0;
        try { $pageCount = (int)Database::fetchOne("PRAGMA page_count")['page_count']; } catch (Throwable $e) {}
        try { $pageSize = (int)Database::fetchOne("PRAGMA page_size")['page_size']; } catch (Throwable $e) {}

        // Catálogo CVE: base de datos independiente (cve.sqlite), la que más
        // crece con el catálogo NVD. Se mide aparte para poder controlarla.
        $cveDbPath = defined('CVE_DB_PATH') ? CVE_DB_PATH : (STORAGE_PATH . '/cve.sqlite');
        $cveDbSize = is_file($cveDbPath) ? (int)filesize($cveDbPath) : 0;
        $cveWalSize = is_file($cveDbPath . '-wal') ? (int)filesize($cveDbPath . '-wal') : 0;
        $cveShmSize = is_file($cveDbPath . '-shm') ? (int)filesize($cveDbPath . '-shm') : 0;
        $cveTables = [];
        $cveTotalRows = 0;
        $cvePageCount = 0;
        $cvePageSize = 0;

        // Si aún no existe, no se instancia CveDatabase (crearía el fichero y
        // el esquema solo por visitar este panel).
        if ($cveDbSize > 0) {
            try {
                foreach (CveDatabase::fetchAll("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name") as $t) {
                    $name = (string)$t['name'];
                    try {
                        $c = (int)CveDatabase::fetchOne('SELECT COUNT(*) AS c FROM "' . $name . '"')['c'];
                    } catch (Throwable $e) {
                        $c = 0;
                    }
                    $cveTables[$name] = $c;
                    $cveTotalRows += $c;
                }
                arsort($cveTables);
                try { $cvePageCount = (int)CveDatabase::fetchOne("PRAGMA page_count")['page_count']; } catch (Throwable $e) {}
                try { $cvePageSize = (int)CveDatabase::fetchOne("PRAGMA page_size")['page_size']; } catch (Throwable $e) {}
            } catch (Throwable $e) {
                // El panel debe seguir funcionando aunque cve.sqlite esté bloqueada.
            }
        }

        $diskTotal = function_exists('disk_total_space') ? (int)@disk_total_space(ROOT_PATH) : 0;
        $diskFree = function_exists('disk_free_space') ? (int)@disk_free_space(ROOT_PATH) : 0;
        $diskUsed = $diskTotal > 0 ? $diskTotal - $diskFree : 0;

        return [
            'db' => [
                'path' => $dbPath, 'size' => $dbSize, 'wal' => $walSize, 'shm' => $shmSize,
                'page_count' => $pageCount, 'page_size' => $pageSize,
                'tables' => $tables, 'table_count' => count($tables), 'total_rows' => $totalRows,
            ],
            'cve_db' => [
                'path' => $cveDbPath, 'size' => $cveDbSize, 'wal' => $cveWalSize, 'shm' => $cveShmSize,
                'page_count' => $cvePageCount, 'page_size' => $cvePageSize,
                'tables' => $cveTables, 'table_count' => count($cveTables), 'total_rows' => $cveTotalRows,
                'exists' => $cveDbSize > 0,
            ],
            'disk' => ['total' => $diskTotal, 'free' => $diskFree, 'used' => $diskUsed],
            'dirs' => [
                'storage'           => self::dirSize(STORAGE_PATH),
                'storage/backups'   => self::dirSize(STORAGE_PATH . '/backups'),
                'storage/exports'   => self::dirSize(STORAGE_PATH . '/exports'),
                'storage/cache'     => self::dirSize(STORAGE_PATH . '/cache'),
                'storage/cve.sqlite' => $cveDbSize + $cveWalSize + $cveShmSize,
                'app (public_html)' => self::dirSize(ROOT_PATH),
            ],
            'php' => [
                'memory_limit'        => (string)ini_get('memory_limit'),
                'memory_usage'        => memory_get_usage(true),
                'memory_peak'         => memory_get_peak_usage(true),
                'upload_max_filesize' => (string)ini_get('upload_max_filesize'),
                'post_max_size'       => (string)ini_get('post_max_size'),
                'max_execution_time'  => (string)ini_get('max_execution_time'),
                'sapi'                => function_exists('php_sapi_name') ? (string)php_sapi_name() : '—',
                'fastcgi'             => function_exists('fastcgi_finish_request'),
                'curl'                => function_exists('curl_init'),
                'mbstring'            => function_exists('mb_strlen'),
                'openssl'             => function_exists('openssl_encrypt'),
            ],
            'ts' => time(),
        ];
    }

    /**
     * Logs de la aplicación: errores PHP, actividad y log estructurado,
     * con filtros y panel de diagnóstico.
     */
    public static function logs(): void
    {
        Auth::requireAdmin();

        $sources = [
            'app'      => ['label' => 'Aplicación', 'file' => STORAGE_PATH . '/app.log'],
            'php'      => ['label' => 'Errores PHP', 'file' => STORAGE_PATH . '/php_errors.log'],
            'activity' => ['label' => 'Actividad', 'file' => STORAGE_PATH . '/activity.log'],
        ];

        $source = (string)($_GET['source'] ?? 'app');
        if (!isset($sources[$source])) {
            $source = 'app';
        }
        $level = strtolower(trim((string)($_GET['level'] ?? '')));
        if (!in_array($level, ['', 'error', 'warning', 'info'], true)) {
            $level = '';
        }
        $channel = trim((string)($_GET['channel'] ?? ''));
        $q = trim((string)($_GET['q'] ?? ''));
        $page = max(1, (int)($_GET['page'] ?? 1));

        $entries = self::readLogEntries($source, $sources[$source]['file']);

        $filtered = [];
        foreach ($entries as $entry) {
            if ($level !== '' && $entry['level'] !== $level) {
                continue;
            }
            if ($channel !== '' && stripos((string)$entry['channel'], $channel) === false) {
                continue;
            }
            if ($q !== '') {
                $haystack = $entry['message'] . ' ' . json_encode($entry['context'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                if (stripos($haystack, $q) === false) {
                    continue;
                }
            }
            $filtered[] = $entry;
        }

        // Más recientes primero (el fichero está en orden cronológico).
        $filtered = array_reverse($filtered);

        $counts = ['error' => 0, 'warning' => 0, 'info' => 0];
        foreach ($filtered as $entry) {
            $counts[$entry['level']] = ($counts[$entry['level']] ?? 0) + 1;
        }

        $perPage = 50;
        $total = count($filtered);
        $pages = max(1, (int)ceil($total / $perPage));
        if ($page > $pages) {
            $page = $pages;
        }
        $entriesPage = array_slice($filtered, ($page - 1) * $perPage, $perPage);

        $fileInfo = [];
        foreach ($sources as $key => $meta) {
            $file = $meta['file'];
            $fileInfo[$key] = [
                'label'   => $meta['label'],
                'exists'  => is_file($file),
                'size'    => is_file($file) ? (int)@filesize($file) : 0,
                'mtime'   => is_file($file) ? (int)@filemtime($file) : 0,
            ];
        }

        $diag = [
            'app_version'         => is_file(ROOT_PATH . '/VERSION') ? trim((string)@file_get_contents(ROOT_PATH . '/VERSION')) : '—',
            'php'                 => PHP_VERSION,
            'sapi'                => function_exists('php_sapi_name') ? (string)php_sapi_name() : '—',
            'ext'                 => [
                'curl'       => function_exists('curl_init'),
                'mbstring'   => function_exists('mb_strlen'),
                'openssl'    => function_exists('openssl_encrypt'),
                'sqlite3'    => extension_loaded('sqlite3'),
                'pdo_sqlite' => extension_loaded('pdo_sqlite'),
            ],
            'max_execution_time'  => (string)ini_get('max_execution_time'),
            'memory_limit'        => (string)ini_get('memory_limit'),
            'post_max_size'       => (string)ini_get('post_max_size'),
            'display_errors'      => (string)ini_get('display_errors'),
            'log_errors'          => (string)ini_get('log_errors'),
            'app_debug'           => APP_DEBUG,
            'rewrite'             => HAS_MOD_REWRITE,
            'storage_writable'    => is_writable(STORAGE_PATH),
            'disk_free'           => function_exists('disk_free_space') ? (int)@disk_free_space(STORAGE_PATH) : 0,
            'disk_total'          => function_exists('disk_total_space') ? (int)@disk_total_space(STORAGE_PATH) : 0,
            'db_size'             => is_file(DB_PATH) ? (int)@filesize(DB_PATH) : 0,
            'cve_db_size'         => defined('CVE_DB_PATH') && is_file(CVE_DB_PATH) ? (int)@filesize(CVE_DB_PATH) : 0,
        ];

        $llmProfiles = llm_profile_list();
        $llmTaskProfile = llm_task_profile('cve_report');
        $llmConfigured = class_exists('Module_Llm') && (new Module_Llm())->isConfigured();

        $jobs = [];
        $jobCounts = [];
        try {
            $jobs = CveDatabase::fetchAll(
                "SELECT id, title, status, ai_model, ai_error, ai_duration_ms, no_ai, created_at, finished_at
                 FROM cve_ai_reports
                 ORDER BY id DESC
                 LIMIT 10"
            );
            foreach (CveDatabase::fetchAll("SELECT status, COUNT(*) AS c FROM cve_ai_reports GROUP BY status") as $row) {
                $jobCounts[(string)$row['status']] = (int)$row['c'];
            }
        } catch (Throwable $e) {
            app_log('warning', 'logs', 'No se pudo leer cve_ai_reports', ['error' => $e->getMessage()]);
        }

        $success = flash('success');
        $error = flash('error');

        $title = 'Logs';
        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        require VIEWS_PATH . '/admin/logs.php';
        require VIEWS_PATH . '/layout/footer.php';
    }

    /**
     * Descarga una fuente de log (solo las permitidas).
     */
    public static function logsDownload(): void
    {
        Auth::requireAdmin();

        $files = [
            'app'      => STORAGE_PATH . '/app.log',
            'php'      => STORAGE_PATH . '/php_errors.log',
            'activity' => STORAGE_PATH . '/activity.log',
        ];
        $source = (string)($_GET['source'] ?? '');
        if (!isset($files[$source]) || !is_file($files[$source])) {
            http_response_code(404);
            echo 'Log no disponible.';
            return;
        }

        $file = $files[$source];
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $source . '-' . date('Ymd-His') . '.log"');
        header('Content-Length: ' . (string)filesize($file));
        header('Cache-Control: no-store, no-cache, must-revalidate');
        @readfile($file);
        exit;
    }

    /**
     * Rota (vacía) una fuente de log. Conserva el anterior como .1.
     */
    public static function logsClear(): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $files = [
            'app'      => STORAGE_PATH . '/app.log',
            'php'      => STORAGE_PATH . '/php_errors.log',
            'activity' => STORAGE_PATH . '/activity.log',
        ];
        $source = (string)($_POST['source'] ?? '');
        if (!isset($files[$source])) {
            flash('error', 'Fuente de log no válida.');
            redirect(base_url('admin/logs'));
        }

        $file = $files[$source];
        if (is_file($file)) {
            @rename($file, $file . '.1');
            @file_put_contents($file, '');
        }
        app_log('info', 'admin', 'Log vaciado manualmente', ['source' => $source]);
        flash('success', 'Log vaciado. El anterior se conserva como «' . basename($file) . '.1».');
        redirect(base_url('admin/logs?source=' . rawurlencode($source)));
    }

    /**
     * Lee las últimas entradas de un log (máximo 1 MB) y las normaliza.
     *
     * @return array<int,array{ts:int,level:string,channel:string,message:string,context:mixed,raw:string}>
     */
    private static function readLogEntries(string $source, string $file, int $maxBytes = 1048576): array
    {
        if (!is_file($file) || !is_readable($file)) {
            return [];
        }

        $size = (int)@filesize($file);
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            return [];
        }
        if ($size > $maxBytes) {
            @fseek($fh, $size - $maxBytes);
        }
        $data = (string)@stream_get_contents($fh);
        @fclose($fh);

        if ($size > $maxBytes) {
            $pos = strpos($data, "\n");
            if ($pos !== false) {
                $data = substr($data, $pos + 1);
            }
        }

        $lines = preg_split('/\r\n|\n|\r/', $data) ?: [];
        $entries = [];

        if ($source === 'php') {
            $current = null;
            foreach ($lines as $line) {
                if ($line === '') {
                    continue;
                }
                if (preg_match('/^\[([^\]]+)\]\s*(.*)$/', $line, $m)) {
                    if ($current !== null) {
                        $entries[] = $current;
                    }
                    $ts = strtotime($m[1]);
                    $message = $m[2];
                    $level = 'info';
                    if (preg_match('/fatal|error|exception|uncaught/i', $message)) {
                        $level = 'error';
                    } elseif (preg_match('/warning/i', $message)) {
                        $level = 'warning';
                    }
                    $current = [
                        'ts'      => $ts !== false ? $ts : 0,
                        'level'   => $level,
                        'channel' => 'php',
                        'message' => $message,
                        'context' => '',
                        'raw'     => $line,
                    ];
                } elseif ($current !== null) {
                    $current['message'] .= "\n" . $line;
                    $current['raw'] .= "\n" . $line;
                }
            }
            if ($current !== null) {
                $entries[] = $current;
            }
            return $entries;
        }

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $row = json_decode($line, true);
            if (!is_array($row)) {
                $entries[] = [
                    'ts' => 0, 'level' => 'info', 'channel' => $source,
                    'message' => $line, 'context' => '', 'raw' => $line,
                ];
                continue;
            }

            $ts = strtotime((string)($row['timestamp'] ?? ''));
            if ($source === 'activity') {
                $context = is_array($row['context'] ?? null) ? $row['context'] : [];
                $context['user_id'] = $row['user_id'] ?? null;
                $context['ip'] = $row['ip'] ?? null;
                $entries[] = [
                    'ts'      => $ts !== false ? $ts : 0,
                    'level'   => 'info',
                    'channel' => 'activity',
                    'message' => (string)($row['action'] ?? ''),
                    'context' => $context,
                    'raw'     => $line,
                ];
                continue;
            }

            $level = strtolower((string)($row['level'] ?? 'info'));
            if (!in_array($level, ['error', 'warning', 'info'], true)) {
                $level = 'info';
            }
            $entries[] = [
                'ts'      => $ts !== false ? $ts : 0,
                'level'   => $level,
                'channel' => (string)($row['channel'] ?? 'app'),
                'message' => (string)($row['message'] ?? ''),
                'context' => $row['context'] ?? [],
                'raw'     => $line,
            ];
        }

        return $entries;
    }

    /**
     * Tamaño de un directorio (con tope de ficheros para no castigar el hosting).
     */
    private static function dirSize(string $path, int $maxFiles = 20000): int
    {
        if (!is_dir($path)) { return 0; }
        $total = 0;
        $count = 0;
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            foreach ($it as $f) {
                if ($f->isFile()) {
                    $total += $f->getSize();
                    if (++$count >= $maxFiles) { break; }
                }
            }
        } catch (Throwable $e) {}
        return $total;
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
        'storage'          => 'storage',
        'security'         => 'security',
        'apis'             => 'apis',
        'apis/cve-status'  => 'cveStatus',
        'logs'             => 'logs',
        'logs/download'    => 'logsDownload',
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
        'apis/verify'      => 'apisVerify',
        'apis/default'     => 'apisDefault',
        'apis/delete'      => 'apisDelete',
        'apis/tasks'       => 'apisTasks',
        'apis/cve-save'    => 'cveSave',
        'apis/cve-test'    => 'cveTest',
        'apis/cve-defender-report-save' => 'cveDefenderReportSave',
        'logs/clear'       => 'logsClear',
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
