<?php
/**
 * Layout: sidebar + header + apertura del contenido.
 * Sistema visual: md/ESPECIFICACION-UI.md §4 (shell) y §5 (navegación)
 */

$navModules  = ModuleManager::getNavigation();
$currentUser = Auth::user();
$currentPath = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?? '';

// Agrupar navegación por sección
$groups = [];
foreach ($navModules as $item) {
    $group = $item['group'] ?? 'Módulos';
    $groups[$group][] = $item;
}

$isDashboard = str_contains($currentPath, '/admin')
    && !str_contains($currentPath, '/admin/tenant')
    && !str_contains($currentPath, '/admin/user')
    && !str_contains($currentPath, '/admin/module')
    && !str_contains($currentPath, '/admin/settings')
    && !str_contains($currentPath, '/admin/logs')
    && !str_contains($currentPath, '/admin/apis')
    && !str_contains($currentPath, '/admin/storage')
    && !str_contains($currentPath, '/admin/security')
    && !str_contains($currentPath, '/admin/updates')
    && !str_contains($currentPath, '/admin/change-password');

$adminItems = [
    ['key' => 'tenants',     'url' => base_url('admin/tenants'),          'icon' => 'business',      'label' => 'Tenants'],
    ['key' => 'graph',       'url' => base_url('modules/graph_connector'),'icon' => 'link',          'label' => 'Conexión Graph'],
    ['key' => 'users',       'url' => base_url('admin/users'),            'icon' => 'group',         'label' => 'Usuarios'],
    ['key' => 'modules',     'url' => base_url('admin/modules'),          'icon' => 'widgets',       'label' => 'Módulos'],
    ['key' => 'apis',        'url' => base_url('admin/apis'),             'icon' => 'api',           'label' => 'APIs'],
    ['key' => 'logs',        'url' => base_url('admin/logs'),             'icon' => 'article',       'label' => 'Logs'],
    ['key' => 'settings',    'url' => base_url('admin/settings'),         'icon' => 'settings',      'label' => 'Configuración'],
    ['key' => 'updates',     'url' => base_url('admin/updates'),          'icon' => 'system_update', 'label' => 'Actualizaciones'],
    ['key' => 'storage',     'url' => base_url('admin/storage'),          'icon' => 'storage',       'label' => 'Almacenamiento'],
    ['key' => 'security',    'url' => base_url('admin/security'),         'icon' => 'security',      'label' => 'Seguridad'],
];

$adminOpen = false;
foreach ($adminItems as $ai) {
    if (str_contains($currentPath, '/' . $ai['key'])) {
        $adminOpen = true;
        break;
    }
}
$adminOpen = $adminOpen || str_contains($currentPath, '/admin/tenant') || str_contains($currentPath, '/admin/user');
?>

<!-- Overlay del drawer lateral (solo < lg) -->
<div class="shell-overlay" data-shell-overlay hidden></div>

<aside id="app-sidebar" class="app-sidebar" aria-label="Main navigation">
    <!-- Marca -->
    <a href="<?= base_url('admin') ?>" class="sidebar-brand">
        <span class="sidebar-logo">
            <?= icon('security', 20) ?>
        </span>
        <span><?= e(APP_NAME) ?></span>
    </a>

    <!-- Navegación -->
    <nav class="sidebar-nav">
        <a href="<?= base_url('admin') ?>"
           class="sidebar-link<?= $isDashboard ? ' is-active' : '' ?>"
           <?= $isDashboard ? 'aria-current="page"' : '' ?>>
            <?= icon('dashboard', 18) ?>
            <span>Dashboard</span>
        </a>

        <?php foreach ($groups as $groupName => $items): ?>
            <div class="sidebar-group-label"><?= e($groupName) ?></div>

            <?php foreach ($items as $item):
                $itemPath = basename(parse_url($item['url'], PHP_URL_PATH) ?? '');
                $isActive = $itemPath !== '' && str_contains($currentPath, '/modules/' . $itemPath);
                $isTi = str_contains((string)$item['url'], 'threat_intelligence');
                $isCve = str_contains((string)$item['url'], '/modules/cve');
            ?>
                <a href="<?= e($item['url']) ?>"
                   class="sidebar-link<?= $isActive ? ' is-active' : '' ?>"
                   <?= $isActive ? 'aria-current="page"' : '' ?>>
                    <?= getModuleIcon($item['icon']) ?>
                    <span><?= e($item['label']) ?></span>

                    <?php if ($isTi): ?>
                        <span id="ti-sync-badge" class="ml-auto items-center gap-1 text-[10px] font-medium text-brand-600 dark:text-brand-300" style="display:none" title="Sincronización en curso">
                            <i class="material-icons icon-14 animate-spin" aria-hidden="true">progress_activity</i>
                            <span id="ti-sync-badge-pct">0%</span>
                            <button type="button" id="ti-sync-badge-stop" title="Detener la sincronización" class="ml-0.5 p-0.5 rounded hover:bg-brand-100 dark:hover:bg-brand-900 text-red-500">
                                <i class="material-icons icon-14" aria-hidden="true">close</i>
                            </button>
                        </span>
                    <?php elseif ($isCve): ?>
                        <span id="cve-sync-badge" class="ml-auto items-center gap-1 text-[10px] font-medium text-brand-600 dark:text-brand-300" style="display:none" title="Sincronización CVE en curso">
                            <i class="material-icons icon-14 animate-spin" aria-hidden="true">progress_activity</i>
                            <span id="cve-sync-badge-pct">0%</span>
                            <?php if (Auth::isAdmin()): ?>
                                <button type="button" id="cve-sync-badge-stop" title="Detener la sincronización CVE" class="ml-0.5 p-0.5 rounded hover:bg-brand-100 dark:hover:bg-brand-900 text-red-500">
                                    <i class="material-icons icon-14" aria-hidden="true">close</i>
                                </button>
                            <?php endif; ?>
                        </span>
                    <?php endif; ?>
                </a>
            <?php endforeach; ?>
        <?php endforeach; ?>

        <?php if (Auth::isAdmin()): ?>
            <div class="sidebar-subgroup<?= $adminOpen ? ' is-open' : '' ?>">
                <button type="button" class="sidebar-link sidebar-parent"
                        data-submenu-toggle="sidebar-admin"
                        aria-expanded="<?= $adminOpen ? 'true' : 'false' ?>"
                        aria-controls="sidebar-admin">
                    <?= icon('admin_panel_settings', 18) ?>
                    <span>Administración</span>
                    <i class="material-icons sidebar-caret icon-18" aria-hidden="true">expand_more</i>
                </button>

                <div id="sidebar-admin" class="sidebar-submenu">
                    <?php foreach ($adminItems as $ai):
                        $active = str_contains($currentPath, '/' . $ai['key']);
                    ?>
                        <a href="<?= e($ai['url']) ?>"
                           class="sidebar-sublink<?= $active ? ' is-active' : '' ?>"
                           <?= $active ? 'aria-current="page"' : '' ?>>
                            <?= e($ai['label']) ?>
                        </a>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>
    </nav>

    <!-- Usuario -->
    <div class="sidebar-footer">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-full bg-brand-100 dark:bg-brand-900 flex items-center justify-center shrink-0">
                <span class="text-xs font-semibold text-brand-700 dark:text-brand-300">
                    <?= e(strtoupper(substr($currentUser['display_name'] ?? $currentUser['username'] ?? 'U', 0, 2))) ?>
                </span>
            </div>
            <div class="min-w-0 flex-1">
                <p class="text-sm font-medium truncate m-0"><?= e($currentUser['display_name'] ?? $currentUser['username'] ?? '') ?></p>
                <span class="role-chip"><?= e($currentUser['role'] ?? 'user') ?></span>
            </div>
        </div>
        <p class="mt-2 mb-0 text-center text-[10px] text-ink-soft" title="Versión instalada">v<?= e(APP_VERSION) ?></p>
    </div>
</aside>

<div class="app-body">
    <!-- Header -->
    <header class="app-header">
        <div class="flex min-w-0 items-center gap-3">
            <button type="button" class="shell-menu" data-shell-menu
                    aria-label="Abrir menú de navegación" aria-expanded="false" aria-controls="app-sidebar">
                <?= icon('menu', 20) ?>
            </button>
            <span class="app-header-brand text-base font-bold lg:hidden"><?= e(APP_NAME) ?></span>
            <h1 class="app-header-title"><?= e($pageTitle ?? 'Dashboard') ?></h1>
        </div>

        <div class="app-header-actions">
            <!-- Tema -->
            <button type="button" class="icon-btn theme-toggle" data-theme-toggle
                    aria-label="Cambiar tema" title="Cambiar tema">
                <i class="material-icons icon-20" aria-hidden="true">dark_mode</i>
            </button>

            <!-- Menú de usuario -->
            <div class="relative" data-user-menu>
                <button type="button" id="account-menu-button" class="user-menu"
                        data-user-menu-toggle aria-expanded="false" aria-controls="account-dropdown">
                    <?= icon('person', 18, 'text-ink-muted') ?>
                    <span class="hide-on-small-only"><?= e($currentUser['display_name'] ?? $currentUser['username'] ?? '') ?></span>
                    <span class="role-chip"><?= e($currentUser['role'] ?? 'user') ?></span>
                    <?= icon('arrow_drop_down', 18, 'text-ink-muted') ?>
                </button>

                <ul id="account-dropdown" class="user-menu-panel" hidden>
                    <li class="px-4 py-2 border-b border-line">
                        <p class="text-sm font-medium m-0"><?= e($currentUser['display_name'] ?? $currentUser['username'] ?? '') ?></p>
                        <p class="text-xs text-ink-muted m-0"><?= e($currentUser['email'] ?? '') ?></p>
                    </li>
                    <li>
                        <a href="<?= base_url('admin/change-password') ?>">
                            <?= icon('key', 18) ?>
                            Cambiar contraseña
                        </a>
                    </li>
                    <li class="menu-sep" role="separator"></li>
                    <li>
                        <a href="<?= base_url('admin/logout') ?>" class="text-danger">
                            <?= icon('logout', 18) ?>
                            Cerrar sesión
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </header>

    <!-- Contenido de la página -->
    <main class="app-main">
        <div class="page-container">
