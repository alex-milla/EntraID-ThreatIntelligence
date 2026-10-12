<?php
/**
 * Vista: Panel de configuración de APIs (LLM).
 * Variables: $cfg (array), $keySet (bool), $success, $error
 */
$pageTitle = 'APIs';
$providers = [
    ''          => '— Sin configurar —',
    'openai'    => 'OpenAI',
    'anthropic' => 'Anthropic',
    'azure'     => 'Azure OpenAI',
    'ollama'    => 'Ollama (local)',
    'gemini'    => 'Google Gemini',
    'mistral'   => 'Mistral',
    'custom'    => 'Personalizado (compatible OpenAI)',
];
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
    <div>
        <h1 class="text-xl font-semibold">Configuración de APIs</h1>
        <p class="text-sm text-gray-500 mt-1">Credenciales de los servicios externos que usa la plataforma. Se guardan <strong>cifradas</strong> en la base de datos.</p>
    </div>

    <!-- LLM -->
    <form method="POST" action="<?= base_url('admin/apis/save') ?>" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 space-y-4">
        <?= Csrf::field() ?>
        <div class="flex items-center justify-between">
            <h2 class="text-lg font-semibold">Inteligencia Artificial (LLM)</h2>
            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $cfg['provider'] !== '' && ($keySet || $cfg['provider'] === 'ollama') ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400' ?>">
                <?= $cfg['provider'] !== '' && ($keySet || $cfg['provider'] === 'ollama') ? 'Configurado' : 'No configurado' ?>
            </span>
        </div>

        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Proveedor</label>
            <select name="llm_provider" id="llm_provider"
                    class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 outline-none">
                <?php foreach ($providers as $val => $label): ?>
                    <option value="<?= e($val) ?>" <?= $cfg['provider'] === $val ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
        </div>

        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Base URL <span class="text-gray-400 font-normal">(opcional)</span></label>
            <input type="text" name="llm_api_url" id="llm_api_url" value="<?= e($cfg['api_url']) ?>" placeholder="https://api.openai.com/v1/chat/completions"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 outline-none font-mono text-sm">
            <p class="text-xs text-gray-400 mt-1">Vacío = endpoint por defecto del proveedor. Para Ollama: <code class="font-mono">http://localhost:11434</code>. Para Azure: endpoint del recurso.</p>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Modelo</label>
                <input type="text" name="llm_model" id="llm_model" value="<?= e($cfg['model']) ?>" placeholder="gpt-4o-mini"
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 outline-none font-mono text-sm">
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Max tokens</label>
                <input type="number" name="llm_max_tokens" id="llm_max_tokens" value="<?= (int)$cfg['max_tokens'] ?>" min="1" max="128000"
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 outline-none">
            </div>
        </div>

        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">API Key</label>
            <input type="password" name="llm_api_key" id="llm_api_key" autocomplete="new-password"
                   placeholder="<?= $keySet ? '•••••••• (ya configurada — deja vacío para mantenerla)' : 'Pega aquí tu API key' ?>"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-brand-500 outline-none font-mono text-sm">
            <?php if ($keySet): ?>
                <label class="inline-flex items-center gap-2 mt-2 text-xs text-gray-500">
                    <input type="checkbox" name="llm_api_key_clear" value="1" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                    Borrar la clave guardada
                </label>
            <?php endif; ?>
            <p class="text-xs text-gray-400 mt-1">Ollama no necesita clave.</p>
        </div>

        <div class="flex items-center gap-3 pt-2 border-t border-gray-100 dark:border-gray-700">
            <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                Guardar
            </button>
            <button type="button" onclick="testApi()" id="btn-test"
                    class="px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">
                Probar conexión
            </button>
            <span id="test-result" class="text-sm"></span>
        </div>
    </form>

    <div class="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-xl p-4">
        <p class="text-xs text-amber-700 dark:text-amber-300">
            La API key se guarda <strong>cifrada (AES-256)</strong> y nunca se muestra ni se envía al navegador.
            Si no configuras nada aquí, se seguirán usando los valores del archivo <code class="font-mono">.env</code>.
        </p>
    </div>
</div>

<script>
function testApi() {
    var btn = document.getElementById('btn-test');
    var out = document.getElementById('test-result');
    btn.disabled = true;
    out.className = 'text-sm text-gray-500';
    out.textContent = 'Probando...';
    api('POST', '<?= base_url('admin/apis/test') ?>', {
        llm_provider: document.getElementById('llm_provider').value,
        llm_api_url: document.getElementById('llm_api_url').value,
        llm_model: document.getElementById('llm_model').value,
        llm_api_key: document.getElementById('llm_api_key').value
    }).then(function(res) {
        out.className = 'text-sm ' + (res.success ? 'text-green-600' : 'text-red-600');
        out.textContent = res.success ? (res.message || 'OK') : ('Error: ' + (res.error || 'desconocido'));
    }).catch(function() {
        out.className = 'text-sm text-red-600';
        out.textContent = 'Error de conexión';
    }).finally(function() {
        btn.disabled = false;
    });
}
</script>
