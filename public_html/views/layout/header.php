<?php
/**
 * Layout: cabecera del documento + apertura del shell.
 * Sistema visual: md/ESPECIFICACION-UI.md §1.3, §3, §4
 */

// Tema resuelto en servidor desde cookie (el script inline lo ajusta con localStorage)
$__theme = (($_COOKIE['eiti_theme'] ?? '') === 'dark') ? 'dark' : 'light';
$__assetVersion = defined('APP_VERSION') ? APP_VERSION : '1';
?>
<!DOCTYPE html>
<html lang="es" data-theme="<?= $__theme ?>" class="<?= $__theme === 'dark' ? 'dark ' : '' ?>h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#f97316">
    <meta name="description" content="EntraID Threat Intelligence Platform — Multi-tenant Microsoft Graph data extraction">
    <meta name="csrf-token" content="<?= e(Csrf::token()) ?>">
    <title><?= e($title ?? APP_NAME) ?> — <?= e(APP_NAME) ?></title>

    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='45' fill='%23f97316'/><polygon points='50,25 75,70 25,70' fill='white'/><circle cx='50' cy='62' r='5' fill='%23f97316'/></svg>">

    <!-- Fuentes autoalojadas (Inter, JetBrains Mono, Material Icons) -->
    <link rel="preload" href="<?= asset_url('fonts/inter-var-wght-latin.woff2') ?>" as="font" type="font/woff2" crossorigin>

    <!-- Orden normativo: fonts -> tokens/base -> layout+componentes -> utilities -->
    <link rel="stylesheet" href="<?= asset_url('css/fonts.css') ?>?v=<?= $__assetVersion ?>">
    <link rel="stylesheet" href="<?= asset_url('css/app.css') ?>?v=<?= $__assetVersion ?>">
    <link rel="stylesheet" href="<?= asset_url('css/ui.css') ?>?v=<?= $__assetVersion ?>">
    <link rel="stylesheet" href="<?= asset_url('css/tw.css') ?>?v=<?= $__assetVersion ?>">
    <link rel="stylesheet" href="<?= asset_url('css/print.css') ?>?v=<?= $__assetVersion ?>" media="print">

    <!-- Tema inicial, antes del primer pintado -->
    <script>
        (function () {
            try {
                var stored = localStorage.getItem('theme') || 'auto';
                var dark = stored === 'dark'
                    || (stored === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
                var root = document.documentElement;
                root.classList.toggle('dark', dark);
                root.setAttribute('data-theme', dark ? 'dark' : 'light');
            } catch (e) { /* preferencia no disponible */ }
        })();
    </script>
</head>
<body class="ui-v2 h-full overflow-hidden antialiased transition-theme">
<!-- Token CSRF global: lo usan las llamadas AJAX (api() en app.js) de los módulos -->
<input type="hidden" name="csrf_token" value="<?= e(Csrf::token()) ?>">
<div class="app-shell">
