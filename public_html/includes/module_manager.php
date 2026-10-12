<?php
/**
 * ModuleManager — Gestor de módulos de la aplicación.
 * Cada módulo es autocontenido en su directorio bajo /modules/.
 */

declare(strict_types=1);

require_once MODULES_PATH . '/module_interface.php';

class ModuleManager
{
    private static array $modules = [];
    private static array $instances = [];
    private static bool $initialized = false;

    /**
     * Inicializa el gestor: descubre y carga módulos activos.
     */
    public static function init(): void
    {
        if (self::$initialized) {
            return;
        }
        self::$initialized = true;

        // Obtener módulos activos de la BD
        $activeModules = Database::fetchAll(
            "SELECT * FROM modules WHERE is_active = 1 ORDER BY module_key"
        );

        foreach ($activeModules as $mod) {
            self::$modules[$mod['module_key']] = $mod;
            self::loadModule($mod['module_key']);
        }
    }

    /**
     * Carga un módulo desde su directorio.
     */
    private static function loadModule(string $moduleKey): void
    {
        $moduleDir = MODULES_PATH . '/' . $moduleKey;
        $moduleFile = $moduleDir . '/module.php';

        if (!file_exists($moduleFile)) {
            return;
        }

        require_once $moduleFile;

        // El módulo debe registrar una clase que implemente ModuleInterface
        // Buscamos la clase por convención: Module_{ModuleKey}
        $className = 'Module_' . str_replace(' ', '', ucwords(str_replace('_', ' ', $moduleKey)));

        if (class_exists($className)) {
            self::$instances[$moduleKey] = new $className();
            self::$instances[$moduleKey]->boot();
        }
    }

    /**
     * Obtiene una instancia de módulo.
     */
    public static function get(string $moduleKey): ?ModuleInterface
    {
        return self::$instances[$moduleKey] ?? null;
    }

    /**
     * Comprueba si un módulo está activo.
     */
    public static function isActive(string $moduleKey): bool
    {
        return isset(self::$modules[$moduleKey]);
    }

    /**
     * Obtiene todos los módulos activos.
     */
    public static function getActiveModules(): array
    {
        return self::$modules;
    }

    /**
     * Obtiene todas las instancias de módulos cargados.
     */
    public static function getInstances(): array
    {
        return self::$instances;
    }

    /**
     * Activa un módulo.
     */
    public static function activate(string $moduleKey): bool
    {
        Database::update(
            "UPDATE modules SET is_active = 1, updated_at = datetime('now') WHERE module_key = ?",
            [$moduleKey]
        );
        $row = Database::fetchOne("SELECT * FROM modules WHERE module_key = ?", [$moduleKey]);
        if ($row) {
            self::$modules[$moduleKey] = $row;
            self::loadModule($moduleKey);
        }
        log_activity('module.activated', ['module' => $moduleKey]);
        return true;
    }

    /**
     * Desactiva un módulo.
     */
    public static function deactivate(string $moduleKey): bool
    {
        Database::update(
            "UPDATE modules SET is_active = 0, updated_at = datetime('now') WHERE module_key = ?",
            [$moduleKey]
        );
        unset(self::$modules[$moduleKey]);
        if (isset(self::$instances[$moduleKey])) {
            self::$instances[$moduleKey]->shutdown();
            unset(self::$instances[$moduleKey]);
        }
        log_activity('module.deactivated', ['module' => $moduleKey]);
        return true;
    }

    /**
     * Registra las rutas de todos los módulos cargados en el router dado.
     * Debe llamarse después de crear el Router en el front controller.
     */
    public static function registerAllRoutes(Router $router): void
    {
        $GLOBALS['router'] = $router;
        foreach (self::$instances as $instance) {
            if ($instance instanceof BaseModule) {
                $instance->loadRoutes();
            }
        }
    }

    /**
     * Obtiene la navegación de todos los módulos activos.
     */
    public static function getNavigation(): array
    {
        $nav = [];
        foreach (self::$instances as $key => $instance) {
            $navItem = $instance->getNavItem();
            if ($navItem !== null) {
                $nav[] = $navItem;
            }
        }
        return $nav;
    }

    /**
     * Ejecuta la sincronización de un módulo específico para un tenant.
     */
    public static function syncModule(string $moduleKey, int $tenantId): array
    {
        $module = self::get($moduleKey);
        if (!$module) {
            return ['success' => false, 'error' => "Módulo $moduleKey no disponible"];
        }
        return $module->sync($tenantId);
    }

    /**
     * Ejecuta la sincronización de todos los módulos activos para un tenant.
     */
    public static function syncAll(int $tenantId): array
    {
        $results = [];
        foreach (self::$instances as $key => $instance) {
            if ($instance->isSyncable()) {
                $results[$key] = $instance->sync($tenantId);
            }
        }
        return $results;
    }
}
