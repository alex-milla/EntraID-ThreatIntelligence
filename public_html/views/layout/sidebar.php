<?php
/**
 * Sidebar — Navegación lateral fija.
 * Muestra navegación de módulos activos + administración.
 */

$navModules = ModuleManager::getNavigation();
$currentUser = Auth::user();
$currentPath = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?? '';

// Agrupar navegación
$groups = [];
foreach ($navModules as $item) {
    $group = $item['group'] ?? 'Módulos';
    $groups[$group][] = $item;
}
?>

<!-- Overlay móvil -->
<div id="sidebar-overlay" class="fixed inset-0 bg-black/50 z-20 lg:hidden hidden" onclick="toggleSidebar()"></div>

<!-- Sidebar -->
<aside id="sidebar" class="fixed lg:static inset-y-0 left-0 z-30 w-64 bg-surface dark:bg-surface-dark border-r border-gray-200 dark:border-gray-700 transform -translate-x-full lg:translate-x-0 transition-transform duration-200 flex flex-col">
    <!-- Logo -->
    <div class="h-16 px-6 border-b border-gray-200 dark:border-gray-700 flex items-center gap-3 shrink-0">
        <div class="w-8 h-8 rounded-lg bg-brand-500 flex items-center justify-center">
            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
        </div>
        <span class="font-bold text-lg truncate"><?= e(APP_NAME) ?></span>
    </div>

    <!-- Navegación -->
    <nav class="flex-1 p-4 space-y-1 overflow-y-auto">
        <!-- Dashboard -->
        <a href="<?= base_url('admin') ?>"
           class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= str_contains($currentPath, '/admin') && !str_contains($currentPath, '/admin/tenant') && !str_contains($currentPath, '/admin/users') && !str_contains($currentPath, '/admin/modules') && !str_contains($currentPath, '/admin/settings') && !str_contains($currentPath, '/admin/updates') ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
            <svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>
            Dashboard
        </a>

        <?php foreach ($groups as $groupName => $items): ?>
            <div class="mt-4 mb-1 px-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                <?= e($groupName) ?>
            </div>
            <?php foreach ($items as $item): ?>
                <?php $isActive = str_contains($currentPath, '/modules/' . basename(parse_url($item['url'], PHP_URL_PATH))); ?>
                <a href="<?= e($item['url']) ?>"
                   class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= $isActive ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
                    <?= getModuleIcon($item['icon']) ?>
                    <?= e($item['label']) ?>
                    <?php if (str_contains((string)$item['url'], 'threat_intelligence')): ?>
                        <span id="ti-sync-badge" class="ml-auto items-center gap-1 text-[10px] font-medium text-brand-600 dark:text-brand-300" style="display:none" title="Sincronización en curso">
                            <svg class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path></svg>
                            <span id="ti-sync-badge-pct">0%</span>
                        </span>
                    <?php endif; ?>
                </a>
            <?php endforeach; ?>
        <?php endforeach; ?>

        <?php if (Auth::isAdmin()): ?>
            <div class="mt-4 mb-1 px-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Administración
            </div>
            <a href="<?= base_url('admin/tenants') ?>"
               class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= str_contains($currentPath, '/admin/tenants') || str_contains($currentPath, '/admin/tenant') ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
                <svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>
                Tenants
            </a>
            <a href="<?= base_url('modules/graph_connector') ?>"
               class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= str_contains($currentPath, '/modules/graph_connector') ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
                <svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                Conexión Graph
            </a>
            <a href="<?= base_url('admin/users') ?>"
               class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= str_contains($currentPath, '/admin/users') ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
                <svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"/></svg>
                Usuarios
            </a>
            <a href="<?= base_url('admin/modules') ?>"
               class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= str_contains($currentPath, '/admin/modules') ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
                <svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>
                Módulos
            </a>
            <a href="<?= base_url('admin/apis') ?>"
               class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= str_contains($currentPath, '/admin/apis') ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
                <svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                APIs
            </a>
            <a href="<?= base_url('admin/settings') ?>"
               class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= str_contains($currentPath, '/admin/settings') ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
                <svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                Configuración
            </a>
            <a href="<?= base_url('admin/updates') ?>"
               class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= str_contains($currentPath, '/admin/updates') ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
                <svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                Actualizaciones
            </a>
            <a href="<?= base_url('admin/storage') ?>"
               class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors <?= str_contains($currentPath, '/admin/storage') ? 'bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300' : 'text-gray-600 dark:text-gray-400 hover:bg-muted-light dark:hover:bg-muted-dark' ?>">
                <svg class="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/></svg>
                Almacenamiento
            </a>
        <?php endif; ?>
    </nav>

    <!-- Footer sidebar: usuario -->
    <div class="p-4 border-t border-gray-200 dark:border-gray-700 shrink-0">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-full bg-brand-100 dark:bg-brand-900 flex items-center justify-center shrink-0">
                <span class="text-xs font-semibold text-brand-700 dark:text-brand-300">
                    <?= e(strtoupper(substr($currentUser['display_name'] ?? $currentUser['username'] ?? 'U', 0, 2))) ?>
                </span>
            </div>
            <div class="min-w-0 flex-1">
                <p class="text-sm font-medium truncate"><?= e($currentUser['display_name'] ?? $currentUser['username'] ?? '') ?></p>
                <span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-brand-100 dark:bg-brand-900 text-brand-700 dark:text-brand-300">
                    <?= e($currentUser['role'] ?? 'user') ?>
                </span>
            </div>
        </div>
    </div>
</aside>

<!-- Contenido principal (el header cierra en footer.php) -->
<div class="flex-1 flex flex-col min-w-0">
    <!-- Header -->
    <header class="h-16 bg-surface dark:bg-surface-dark border-b border-gray-200 dark:border-gray-700 px-6 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-4">
            <!-- Botón hamburguesa (móvil) -->
            <button onclick="toggleSidebar()" class="lg:hidden p-2 rounded-lg hover:bg-muted-light dark:hover:bg-muted-dark transition-colors">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
            </button>
            <h1 class="text-lg font-semibold"><?= e($pageTitle ?? 'Dashboard') ?></h1>
        </div>
        <div class="flex items-center gap-2">
            <!-- Theme toggle -->
            <button onclick="toggleTheme()" class="p-2 rounded-lg hover:bg-muted-light dark:hover:bg-muted-dark transition-colors" title="Cambiar tema">
                <svg id="theme-icon-sun" class="w-[18px] h-[18px] hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
                <svg id="theme-icon-moon" class="w-[18px] h-[18px] block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
            </button>
            <!-- Usuario -->
            <div class="relative">
                <button onclick="toggleUserMenu()" class="flex items-center gap-2 text-sm p-1.5 rounded-lg hover:bg-muted-light dark:hover:bg-muted-dark transition-colors">
                    <div class="w-7 h-7 rounded-full bg-brand-500 flex items-center justify-center">
                        <span class="text-xs font-semibold text-white"><?= e(strtoupper(substr($currentUser['username'] ?? 'U', 0, 1))) ?></span>
                    </div>
                </button>
                <!-- Dropdown usuario -->
                <div id="user-menu" class="hidden absolute right-0 top-full mt-2 w-48 bg-white dark:bg-surface-dark rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-20">
                    <div class="px-4 py-2 border-b border-gray-100 dark:border-gray-700">
                        <p class="text-sm font-medium"><?= e($currentUser['display_name'] ?? $currentUser['username']) ?></p>
                        <p class="text-xs text-gray-500"><?= e($currentUser['email'] ?? '') ?></p>
                    </div>
                    <a href="<?= base_url('admin/change-password') ?>" class="w-full flex items-center gap-2 px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                        Cambiar contraseña
                    </a>
                    <div class="border-t border-gray-100 dark:border-gray-700 my-1"></div>
                    <a href="<?= base_url('admin/logout') ?>" class="w-full flex items-center gap-2 px-4 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-950 transition-colors">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
                        Cerrar sesión
                    </a>
                </div>
            </div>
        </div>
    </header>

    <!-- Main content -->
    <main class="flex-1 p-6 overflow-auto">

