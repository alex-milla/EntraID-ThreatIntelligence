<?php
/**
 * Vista: Login.
 * Sistema visual: md/ESPECIFICACION-UI.md (shell mínimo, sin navegación)
 */
$__theme = (($_COOKIE['eiti_theme'] ?? '') === 'dark') ? 'dark' : 'light';
$__assetVersion = defined('APP_VERSION') ? APP_VERSION : '1';
?>
<!DOCTYPE html>
<html lang="es" data-theme="<?= $__theme ?>" class="<?= $__theme === 'dark' ? 'dark ' : '' ?>h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#f97316">
    <meta name="csrf-token" content="<?= e(Csrf::token()) ?>">
    <title>Iniciar sesión — <?= e(APP_NAME) ?></title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='45' fill='%23f97316'/><polygon points='50,25 75,70 25,70' fill='white'/><circle cx='50' cy='62' r='5' fill='%23f97316'/></svg>">
    <link rel="preload" href="<?= asset_url('fonts/inter-var-wght-latin.woff2') ?>" as="font" type="font/woff2" crossorigin>
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
<body class="ui-v2 min-h-screen antialiased">
<div class="min-h-screen flex items-center justify-center px-4 py-10">
    <div class="w-full max-w-sm">
        <!-- Marca -->
        <div class="text-center mb-8">
            <div class="inline-flex items-center justify-center w-16 h-16 rounded-card bg-brand-500 mb-4 text-white">
                <i class="material-icons icon-32" aria-hidden="true">security</i>
            </div>
            <h1 class="text-2xl font-bold text-ink m-0"><?= e(APP_NAME) ?></h1>
            <p class="text-sm text-ink-muted mt-1 mb-0">Threat Intelligence Platform</p>
        </div>

        <!-- Formulario -->
        <form method="POST" action="<?= base_url('admin/login') ?>" class="card p-6">
            <?= Csrf::field() ?>

            <?php if (!empty($error)): ?>
                <div class="alert alert-error"><?= e($error) ?></div>
            <?php endif; ?>

            <?php
            $flashData = flash();
            foreach ($flashData as $type => $msg):
                $alertClass = match ($type) {
                    'success' => 'alert-success',
                    'warning' => 'alert-warning',
                    'error'   => 'alert-error',
                    default   => 'alert-info',
                };
            ?>
                <div class="alert <?= $alertClass ?>"><?= e($msg) ?></div>
            <?php endforeach; ?>

            <div class="input-field">
                <label for="username">Usuario o email</label>
                <input type="text" id="username" name="username" value="<?= e($old['username'] ?? '') ?>"
                       required autofocus autocomplete="username" placeholder="usuario@dominio.com">
            </div>

            <div class="input-field">
                <label for="password">Contraseña</label>
                <input type="password" id="password" name="password" required autocomplete="current-password" placeholder="••••••••">
            </div>

            <button type="submit" class="btn w-full">
                <i class="material-icons icon-16" aria-hidden="true">login</i>
                Entrar
            </button>
        </form>

        <p class="text-center text-xs text-ink-soft mt-6 mb-0">
            Usuario por defecto: <code class="font-mono">admin</code> / <code class="font-mono">admin</code>
            <br><span class="text-warning">Cámbiala tras el primer acceso</span>
        </p>
        <p class="text-center text-[10px] text-ink-soft mt-2 mb-0">v<?= e(APP_VERSION) ?></p>
    </div>
</div>
</body>
</html>
