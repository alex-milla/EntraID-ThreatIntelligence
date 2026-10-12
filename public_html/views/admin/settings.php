<?php
/**
 * Vista: Configuración global.
 */
$pageTitle = 'Configuración';
?>

<?php
$flashData = flash();
foreach ($flashData as $type => $msg):
    $colors = match($type) {
        'success' => 'text-green-600 bg-green-50 dark:bg-green-900/20',
        'error'   => 'text-red-600 bg-red-50 dark:bg-red-900/20',
        default   => 'text-blue-600 bg-blue-50 dark:bg-blue-900/20',
    };
?>
    <div class="mb-4 px-4 py-3 rounded-lg text-sm <?= $colors ?>"><?= e($msg) ?></div>
<?php endforeach; ?>

<div class="max-w-2xl space-y-6">
    <!-- Información del sistema -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6">
        <h2 class="text-lg font-semibold mb-4">Sistema</h2>
        <dl class="space-y-3">
            <div class="flex justify-between text-sm">
                <dt class="text-gray-500">Aplicación</dt>
                <dd class="font-medium"><?= e(APP_NAME) ?></dd>
            </div>
            <div class="flex justify-between text-sm">
                <dt class="text-gray-500">Entorno</dt>
                <dd class="font-medium"><?= e(APP_ENV) ?></dd>
            </div>
            <div class="flex justify-between text-sm">
                <dt class="text-gray-500">Zona horaria</dt>
                <dd class="font-medium"><?= e(APP_TIMEZONE) ?></dd>
            </div>
            <div class="flex justify-between text-sm">
                <dt class="text-gray-500">Base de datos</dt>
                <dd class="font-mono text-xs"><?= e(basename(DB_PATH)) ?></dd>
            </div>
            <div class="flex justify-between text-sm">
                <dt class="text-gray-500">Clave de cifrado</dt>
                <dd class="font-medium <?= empty(ENCRYPTION_KEY) ? 'text-red-500' : 'text-green-600' ?>">
                    <?= empty(ENCRYPTION_KEY) ? 'NO CONFIGURADA' : 'Configurada' ?>
                </dd>
            </div>
        </dl>
    </div>

    <!-- LLM -->
    <?php $llm = llm_config(); $llmKeySet = $llm['api_key'] !== ''; ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6">
        <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold">Integración LLM</h2>
            <a href="<?= base_url('admin/apis') ?>" class="text-sm text-brand-600 dark:text-brand-400 hover:underline">Configurar</a>
        </div>
        <div class="space-y-3 text-sm">
            <div class="flex justify-between">
                <span class="text-gray-500">Proveedor</span>
                <span class="font-medium"><?= e($llm['provider'] ?: 'No configurado') ?></span>
            </div>
            <div class="flex justify-between">
                <span class="text-gray-500">Modelo</span>
                <span class="font-medium"><?= e($llm['model'] ?: '—') ?></span>
            </div>
            <div class="flex justify-between">
                <span class="text-gray-500">API Key</span>
                <span class="font-medium <?= $llmKeySet ? 'text-green-600' : 'text-gray-400' ?>">
                    <?= $llmKeySet ? '••••••••' : 'No configurada' ?>
                </span>
            </div>
        </div>
        <p class="text-xs text-gray-400 mt-4">
            Se configura en <a href="<?= base_url('admin/apis') ?>" class="text-brand-600 dark:text-brand-400 hover:underline">Admin → APIs</a> (guardado cifrado) o, como fallback, en el archivo <code class="font-mono">.env</code>.
        </p>
    </div>

    <!-- Instrucciones .env -->
    <div class="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-xl p-6">
        <h2 class="text-sm font-semibold text-amber-800 dark:text-amber-200 mb-2">Configuración de seguridad</h2>
        <ol class="text-sm text-amber-700 dark:text-amber-300 space-y-1 list-decimal list-inside">
            <li>Copia <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">.env.example</code> a <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">.env</code></li>
            <li>Genera la clave de cifrado: <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">php -r "echo base64_encode(random_bytes(32));"</code></li>
            <li>Configura <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">ENCRYPTION_KEY</code> y <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">SESSION_SECRET</code></li>
            <li>Nunca subas el archivo <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">.env</code> a repositorios</li>
            <li>El archivo <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">.env</code> está protegido por <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">.htaccess</code></li>
        </ol>
    </div>
</div>
