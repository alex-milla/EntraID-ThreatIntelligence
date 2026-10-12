<!DOCTYPE html>
<html lang="es" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#f97316">
    <title>Iniciar sesión — <?= e(APP_NAME) ?></title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='45' fill='%23f97316'/><polygon points='50,25 75,70 25,70' fill='white'/><circle cx='50' cy='62' r='5' fill='%23f97316'/></svg>">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { colors: { brand: { 50:'#fff7ed',100:'#ffedd5',200:'#fed7aa',300:'#fdba74',400:'#fb923c',500:'#f97316',600:'#ea580c',700:'#c2410c',900:'#7c2d12',950:'#431407' }, surface: { DEFAULT:'#ffffff', dark:'#0f172a' } }, fontFamily: { sans: ['Inter','sans-serif'] } } }
        };
    </script>
    <script>
        (function() {
            var theme = localStorage.getItem('theme') || 'auto';
            if (theme === 'dark' || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                document.documentElement.classList.add('dark');
            }
        })();
    </script>
</head>
<body class="h-full bg-gray-50 dark:bg-gray-900 antialiased">
<div class="min-h-screen flex items-center justify-center px-4">
    <div class="w-full max-w-sm">
        <!-- Marca -->
        <div class="text-center mb-8">
            <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-500 mb-4">
                <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                </svg>
            </div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white"><?= e(APP_NAME) ?></h1>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Threat Intelligence Platform</p>
        </div>

        <!-- Formulario -->
        <form method="POST" action="<?= base_url('admin/login') ?>" class="bg-white dark:bg-surface-dark rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6 space-y-4">
            <?= Csrf::field() ?>

            <?php if (!empty($error)): ?>
                <div class="text-sm text-red-500 bg-red-50 dark:bg-red-900/20 px-3 py-2 rounded-lg">
                    <?= e($error) ?>
                </div>
            <?php endif; ?>

            <?php
            $flashData = flash();
            foreach ($flashData as $type => $msg):
                $colors = match($type) {
                    'success' => 'text-green-600 bg-green-50 dark:bg-green-900/20',
                    'warning' => 'text-amber-600 bg-amber-50 dark:bg-amber-900/20',
                    'error'   => 'text-red-500 bg-red-50 dark:bg-red-900/20',
                    default   => 'text-blue-600 bg-blue-50 dark:bg-blue-900/20',
                };
            ?>
                <div class="text-sm <?= $colors ?> px-3 py-2 rounded-lg"><?= e($msg) ?></div>
            <?php endforeach; ?>

            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Usuario o email</label>
                <input type="text" name="username" value="<?= e($old['username'] ?? '') ?>" required autofocus
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Contraseña</label>
                <input type="password" name="password" required
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
            </div>

            <button type="submit"
                    class="w-full py-2.5 px-4 bg-brand-500 hover:bg-brand-600 text-white font-medium rounded-lg transition-colors">
                Entrar
            </button>
        </form>

        <p class="text-center text-xs text-gray-400 mt-6">
            Usuario por defecto: <code class="font-mono">admin</code> / <code class="font-mono">admin</code>
            <br><span class="text-amber-500">Cámbiala tras el primer acceso</span>
        </p>
    </div>
</div>
</body>
</html>
