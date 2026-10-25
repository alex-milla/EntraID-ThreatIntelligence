<?php
$__theme = (($_COOKIE['eiti_theme'] ?? '') === 'dark') ? 'dark' : 'light';
$__assetVersion = defined('APP_VERSION') ? APP_VERSION : '1';
?>
<!DOCTYPE html>
<html lang="es" data-theme="<?= $__theme ?>" class="<?= $__theme === 'dark' ? 'dark ' : '' ?>h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 — No encontrado</title>
    <link rel="stylesheet" href="<?= asset_url('css/fonts.css') ?>?v=<?= $__assetVersion ?>">
    <link rel="stylesheet" href="<?= asset_url('css/app.css') ?>?v=<?= $__assetVersion ?>">
    <link rel="stylesheet" href="<?= asset_url('css/ui.css') ?>?v=<?= $__assetVersion ?>">
    <link rel="stylesheet" href="<?= asset_url('css/tw.css') ?>?v=<?= $__assetVersion ?>">
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
<body class="ui-v2 min-h-screen flex items-center justify-center antialiased">
    <div class="text-center px-4">
        <p class="text-6xl font-bold text-brand-500 m-0">404</p>
        <h1 class="text-xl font-semibold text-ink mt-4 mb-0">Página no encontrada</h1>
        <p class="text-sm text-ink-muted mt-2">La página que buscas no existe.</p>
        <a href="<?= base_url('admin') ?>" class="btn mt-6">
            <i class="material-icons icon-16" aria-hidden="true">dashboard</i>
            Volver al dashboard
        </a>
    </div>
</body>
</html>
