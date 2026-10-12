<!DOCTYPE html>
<html lang="es" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#f97316">
    <meta name="description" content="EntraID Threat Intelligence Platform — Multi-tenant Microsoft Graph data extraction">
    <title><?= e($title ?? APP_NAME) ?> — <?= e(APP_NAME) ?></title>

    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='45' fill='%23f97316'/><polygon points='50,25 75,70 25,70' fill='white'/><circle cx='50' cy='62' r='5' fill='%23f97316'/></svg>">

    <!-- Google Fonts: Inter + JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

    <!-- Tailwind CSS via CDN (para hosting compartido sin build step) -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: {
                            50:  '#fff7ed', 100: '#ffedd5', 200: '#fed7aa', 300: '#fdba74',
                            400: '#fb923c', 500: '#f97316', 600: '#ea580c', 700: '#c2410c',
                            900: '#7c2d12', 950: '#431407',
                        },
                        surface: { DEFAULT: '#ffffff', dark: '#0f172a' },
                        muted:   { light: '#f1f5f9', dark: '#1e293b' },
                    },
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                },
            },
        };
    </script>

    <!-- Estilos personalizados -->
    <link rel="stylesheet" href="<?= asset_url('css/style.css') ?>?v=<?= filemtime(ASSETS_PATH . '/css/style.css') ?: '1' ?>">

    <!-- Tema inicial (antes del render para evitar flash) -->
    <script>
        (function() {
            var theme = localStorage.getItem('theme') || 'auto';
            if (theme === 'dark' || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                document.documentElement.classList.add('dark');
            }
        })();
    </script>
</head>
<body class="h-full flex overflow-hidden bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white antialiased transition-theme">
<!-- Token CSRF global: lo usan las llamadas AJAX (api() en app.js) de los módulos -->
<input type="hidden" name="csrf_token" value="<?= e(Csrf::token()) ?>">
