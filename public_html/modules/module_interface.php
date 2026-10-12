<?php
/**
 * ModuleInterface — Contrato que todo módulo debe implementar.
 * Cada herramienta de la plataforma es un módulo independiente.
 */

declare(strict_types=1);

interface ModuleInterface
{
    /**
     * Clave única del módulo (snake_case).
     */
    public function key(): string;

    /**
     * Nombre visible del módulo.
     */
    public function name(): string;

    /**
     * Descripción corta del módulo.
     */
    public function description(): string;

    /**
     * Versión del módulo (semver).
     */
    public function version(): string;

    /**
     * Permisos de Microsoft Graph que requiere este módulo.
     * @return string[]
     */
    public function requiredPermissions(): array;

    /**
     * Se ejecuta al cargar el módulo.
     */
    public function boot(): void;

    /**
     * Se ejecuta al desactivar el módulo.
     */
    public function shutdown(): void;

    /**
     * Indica si el módulo tiene funcionalidad de sincronización.
     */
    public function isSyncable(): bool;

    /**
     * Sincroniza datos desde Microsoft Graph para un tenant.
     * @return array{success: bool, records?: int, error?: string}
     */
    public function sync(int $tenantId): array;

    /**
     * Devuelve el ítem de navegación para el sidebar.
     * @return array{label: string, url: string, icon: string, group?: string}|null
     */
    public function getNavItem(): ?array;

    /**
     * Devuelve las rutas del módulo para el router.
     * @return array<int, array{method: string, pattern: string, handler: callable|string}>
     */
    public function routes(): array;

    /**
     * Renderiza una vista del módulo.
     */
    public function render(string $view, array $data = []): string;
}

/**
 * Clase base abstracta para módulos con funcionalidad común.
 */
abstract class BaseModule implements ModuleInterface
{
    protected array $config = [];

    public function __construct()
    {
        $this->loadConfig();
    }

    /**
     * Carga la configuración del módulo desde la BD.
     */
    protected function loadConfig(): void
    {
        $row = Database::fetchOne(
            "SELECT config FROM modules WHERE module_key = ?",
            [$this->key()]
        );
        $this->config = safe_json_decode($row['config'] ?? null, []);
    }

    /**
     * Guarda la configuración del módulo.
     */
    protected function saveConfig(array $config): void
    {
        $this->config = $config;
        Database::update(
            "UPDATE modules SET config = ?, updated_at = datetime('now') WHERE module_key = ?",
            [json_encode($config, JSON_UNESCAPED_SLASHES), $this->key()]
        );
    }

    public function boot(): void
    {
        // Por defecto, registrar rutas
        $this->registerRoutes();
    }

    public function shutdown(): void
    {
        // Limpieza por defecto
    }

    /**
     * Registra las rutas del módulo en el router global.
     * Se invoca tras crear el Router en el front controller.
     */
    public function loadRoutes(): void
    {
        $this->registerRoutes();
    }

    /**
     * Registra las rutas del módulo en el router global.
     */
    protected function registerRoutes(): void
    {
        $router = $GLOBALS['router'] ?? null;
        if (!$router) return;

        foreach ($this->routes() as $route) {
            $method = strtolower($route['method']);
            $pattern = '/modules/' . $this->key() . '/' . ltrim($route['pattern'], '/');
            $router->$method($pattern, $route['handler'], [function () {
                Auth::require();
            }]);
        }
    }

    public function render(string $view, array $data = []): string
    {
        $viewFile = MODULES_PATH . '/' . $this->key() . '/views/' . $view . '.php';
        if (!file_exists($viewFile)) {
            $viewFile = MODULES_PATH . '/' . $this->key() . '/' . $view . '.php';
        }
        if (!file_exists($viewFile)) {
            return "<p class=\"text-red-500\">Vista no encontrada: $view</p>";
        }

        extract($data);
        ob_start();
        require $viewFile;
        return ob_get_clean();
    }

    /**
     * Renderiza una vista de módulo envuelta en el layout completo del panel
     * (header + sidebar + footer). A diferencia de render(), esta salida es una
     * página HTML completa lista para responder a una navegación del usuario.
     */
    public function page(string $view, array $data = []): string
    {
        $content = $this->render($view, $data);

        $title = $this->name();
        $pageTitle = $this->name();

        ob_start();
        require VIEWS_PATH . '/layout/header.php';
        require VIEWS_PATH . '/layout/sidebar.php';
        echo $content;
        require VIEWS_PATH . '/layout/footer.php';
        return ob_get_clean();
    }

    /**
     * Obtiene un cliente Graph para un tenant (descifrando el secret).
     */
    protected function getGraphClient(int $tenantId): GraphClient
    {
        $tenant = TenantManager::getById($tenantId);
        if (!$tenant) {
            throw new RuntimeException("Tenant $tenantId no encontrado");
        }

        $secret = Encryption::decrypt($tenant['client_secret_encrypted'], $tenant['client_secret_iv']);

        return new GraphClient(
            $tenant['tenant_id'],
            $tenant['client_id'],
            $secret
        );
    }

    /**
     * Registra el resultado de una sincronización en el log.
     */
    protected function logSync(int $tenantId, string $syncType, string $status, int $records = 0, ?string $error = null): void
    {
        Database::insert(
            "INSERT INTO sync_log (tenant_id, module_key, sync_type, status, records_processed, error_message, completed_at)
             VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
            [$tenantId, $this->key(), $syncType, $status, $records, $error]
        );

        // Actualizar estado del tenant
        Database::update(
            "UPDATE tenants SET last_sync_at = datetime('now'), last_sync_status = ?, last_error = ? WHERE id = ?",
            [$status, $error, $tenantId]
        );
    }

    public function isSyncable(): bool
    {
        return true;
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => $this->name(),
            'url'   => base_url('modules/' . $this->key()),
            'icon'  => 'shield',
            'group' => 'Módulos',
        ];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET', 'pattern' => '', 'handler' => [$this, 'index']],
        ];
    }

    /**
     * Vista por defecto del módulo.
     */
    public function index(array $params = []): void
    {
        $data = [
            'module'  => $this,
            'tenants' => TenantManager::getActive(),
        ];
        echo $this->render('index', $data);
    }
}
