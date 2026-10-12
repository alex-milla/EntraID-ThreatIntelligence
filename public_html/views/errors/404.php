<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 — No encontrado</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 dark:bg-gray-900 min-h-screen flex items-center justify-center">
    <div class="text-center">
        <p class="text-6xl font-bold text-brand-500">404</p>
        <h1 class="text-xl font-semibold text-gray-900 dark:text-white mt-4">Página no encontrada</h1>
        <p class="text-sm text-gray-500 mt-2">La página que buscas no existe.</p>
        <a href="<?= base_url('admin') ?>" class="inline-block mt-6 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
            Volver al dashboard
        </a>
    </div>
</body>
</html>
