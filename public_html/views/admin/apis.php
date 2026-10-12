<?php
/**
 * Vista: Panel de APIs / perfiles de IA.
 * Variables: $profiles, $editProfile, $tasks, $taskProfiles, $success, $error
 */
$pageTitle = 'APIs';
$providers = [
    ''          => '— Selecciona proveedor —',
    'openai'    => 'OpenAI',
    'anthropic' => 'Anthropic',
    'azure'     => 'Azure OpenAI',
    'ollama'    => 'Ollama (local)',
    'ollama_cloud' => 'Ollama Cloud (API)',
    'gemini'    => 'Google Gemini',
    'mistral'   => 'Mistral',
    'custom'    => 'Personalizado (compatible OpenAI)',
];
$editId = (int)($editProfile['id'] ?? 0);
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

<div class="mb-6">
    <h1 class="text-xl font-semibold">Configuración de APIs</h1>
    <p class="text-sm text-gray-500 mt-1">Guarda varios proveedores de IA a la vez. Marca uno como <strong>predeterminado</strong> y, si quieres, asigna un modelo distinto a cada tarea.</p>
</div>

<!-- Perfiles -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden mb-6">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-sm font-semibold">Perfiles de IA (<?= count($profiles) ?>)</h2>
    </div>
    <?php if (empty($profiles)): ?>
        <p class="px-5 py-6 text-sm text-gray-500">No hay perfiles todavía. Crea el primero abajo.</p>
    <?php else: ?>
        <table class="w-full text-sm">
            <thead>
                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                    <th class="text-left px-4 py-2">Nombre</th>
                    <th class="text-left px-4 py-2">Proveedor</th>
                    <th class="text-left px-4 py-2">Modelo</th>
                    <th class="text-left px-4 py-2">Estado</th>
                    <th class="text-right px-4 py-2">Acciones</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                <?php foreach ($profiles as $p): ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <td class="px-4 py-2 font-medium"><?= e($p['name']) ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($p['provider'] ?: '—') ?></td>
                        <td class="px-4 py-2 text-xs font-mono text-gray-500"><?= e($p['model'] ?: '—') ?></td>
                        <td class="px-4 py-2">
                            <?php if (!empty($p['is_default'])): ?>
                                <span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-brand-100 dark:bg-brand-900 text-brand-700 dark:text-brand-300">Predeterminado</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-4 py-2 text-right whitespace-nowrap">
                            <button type="button" onclick="testProfile(<?= (int)$p['id'] ?>)" class="text-xs text-gray-400 hover:text-brand-500 mr-2">Probar</button>
                            <a href="<?= base_url('admin/apis?edit=' . (int)$p['id']) ?>" class="text-xs text-gray-400 hover:text-brand-500 mr-2">Editar</a>
                            <?php if (empty($p['is_default'])): ?>
                                <form method="POST" action="<?= base_url('admin/apis/default') ?>" class="inline">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="id" value="<?= (int)$p['id'] ?>">
                                    <button type="submit" class="text-xs text-gray-400 hover:text-brand-500 mr-2">Usar por defecto</button>
                                </form>
                            <?php endif; ?>
                            <form method="POST" action="<?= base_url('admin/apis/delete') ?>" class="inline" data-confirm="¿Eliminar el perfil «<?= e($p['name']) ?>»?" data-confirm-danger>
                                <?= Csrf::field() ?>
                                <input type="hidden" name="id" value="<?= (int)$p['id'] ?>">
                                <button type="submit" class="text-xs text-gray-400 hover:text-red-500">Eliminar</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<!-- Formulario perfil -->
<form method="POST" action="<?= base_url('admin/apis/save') ?>" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 space-y-4 mb-6">
    <?= Csrf::field() ?>
    <input type="hidden" name="id" value="<?= $editId ?>">
    <h2 class="text-lg font-semibold"><?= $editId ? 'Editar perfil' : 'Nuevo perfil' ?></h2>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Nombre</label>
            <input type="text" name="name" value="<?= e($editProfile['name'] ?? '') ?>" placeholder="Mistral prod / OpenAI…"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Proveedor</label>
            <select name="provider" id="provider"
                    class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <?php foreach ($providers as $val => $label): ?>
                    <option value="<?= e($val) ?>" <?= ($editProfile['provider'] ?? '') === $val ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
    </div>

    <div>
        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Base URL <span class="text-gray-400 font-normal">(opcional)</span></label>
        <input type="text" name="api_url" value="<?= e($editProfile['api_url'] ?? '') ?>" placeholder="Vacío = endpoint por defecto del proveedor"
               class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Modelo</label>
            <input type="text" name="model" id="model-input" value="<?= e($editProfile['model'] ?? '') ?>" placeholder="mistral-large-latest / gpt-4o-mini" list="model-suggestions" autocomplete="off"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <datalist id="model-suggestions"></datalist>
            <p class="text-xs text-gray-400 mt-1">El modelo debe ser válido para el proveedor elegido (se sugieren los típicos de cada uno).</p>
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Max tokens</label>
            <input type="number" name="max_tokens" value="<?= (int)($editProfile['max_tokens'] ?? 2048) ?>" min="1" max="128000"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
    </div>

    <div>
        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">API Key</label>
        <input type="password" name="api_key" autocomplete="new-password"
               placeholder="<?= !empty($editProfile['api_key']) ? '•••••••• (ya configurada — deja vacío para mantenerla)' : 'Pega aquí tu API key (no necesaria para Ollama local)' ?>"
               class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
    </div>

    <label class="inline-flex items-center gap-2 text-sm">
        <input type="checkbox" name="is_default" value="1" <?= !empty($editProfile['is_default']) || $editId === 0 ? 'checked' : '' ?> class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
        Usar como perfil predeterminado
    </label>

    <div class="flex items-center gap-3 pt-2 border-t border-gray-100 dark:border-gray-700">
        <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Guardar perfil</button>
        <button type="button" onclick="testForm()" class="px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">Probar conexión</button>
        <?php if ($editId): ?>
            <a href="<?= base_url('admin/apis') ?>" class="text-sm text-gray-500 hover:underline">Cancelar edición</a>
        <?php endif; ?>
    </div>
</form>

<!-- Modelo por tarea -->
<form method="POST" action="<?= base_url('admin/apis/tasks') ?>" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-6">
    <?= Csrf::field() ?>
    <h2 class="text-lg font-semibold mb-1">Modelo por tarea</h2>
    <p class="text-xs text-gray-500 mb-4">Elige qué perfil usar en cada tarea (o deja «Predeterminado»).</p>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <?php foreach ($tasks as $key => $label): ?>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"><?= e($label) ?></label>
                <select name="tasks[<?= e($key) ?>]" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="0" <?= empty($taskProfiles[$key]) ? 'selected' : '' ?>>Predeterminado</option>
                    <?php foreach ($profiles as $p): ?>
                        <option value="<?= (int)$p['id'] ?>" <?= (int)($taskProfiles[$key] ?? 0) === (int)$p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
        <?php endforeach; ?>
    </div>
    <div class="pt-4">
        <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Guardar tareas</button>
    </div>
</form>

<div class="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-xl p-4">
    <p class="text-xs text-amber-700 dark:text-amber-300">
        La API key se guarda <strong>cifrada (AES-256-GCM)</strong> y nunca se muestra ni se envía al navegador.
        Consejo: el <strong>nombre del modelo debe ser válido para el proveedor</strong> elegido; si no, la prueba de conexión indicará «Invalid model».
        Mistral no entrena con tus prompts (zero-retention).
    </p>
</div>

<script>
// Sugerencias de modelos por proveedor (se vuelcan en el <datalist>).
var MODEL_SUGGESTIONS = {
    openai:    ['gpt-4o-mini', 'gpt-4o', 'gpt-4.1-mini', 'gpt-4.1'],
    mistral:   ['mistral-large-latest', 'mistral-small-latest', 'open-mistral-nemo', 'codestral-latest'],
    anthropic: ['claude-3-5-sonnet-20241022', 'claude-3-5-haiku-20241022', 'claude-3-opus-20240229'],
    gemini:    ['gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-2.0-flash'],
    azure:     ['gpt-4o-mini', 'gpt-4o'],
    ollama:    ['llama3.1', 'qwen2.5', 'mistral', 'phi3'],
    ollama_cloud: ['gpt-oss:120b', 'gpt-oss:20b', 'gemma4:31b'],
    custom:    []
};
function updateModelSuggestions() {
    var list = document.getElementById('model-suggestions');
    var prov = document.getElementById('provider');
    if (!list || !prov) return;
    list.innerHTML = '';
    (MODEL_SUGGESTIONS[prov.value] || []).forEach(function(m) {
        var o = document.createElement('option');
        o.value = m;
        list.appendChild(o);
    });
}
function testProfile(id) {
    api('POST', '<?= base_url('admin/apis/test') ?>', { profile_id: id })
        .then(function(res) { toast(res.success ? (res.message || 'OK') : ('Error: ' + (res.error || 'desconocido')), res.success ? 'success' : 'error'); })
        .catch(function() { toast('Error de conexión', 'error'); });
}
function testForm() {
    api('POST', '<?= base_url('admin/apis/test') ?>', {
        provider: document.getElementById('provider').value,
        api_url: document.querySelector('input[name="api_url"]').value,
        model: document.querySelector('input[name="model"]').value,
        api_key: document.querySelector('input[name="api_key"]').value
    }).then(function(res) { toast(res.success ? (res.message || 'OK') : ('Error: ' + (res.error || 'desconocido')), res.success ? 'success' : 'error'); })
      .catch(function() { toast('Error de conexión', 'error'); });
}

(function() {
    var prov = document.getElementById('provider');
    if (prov) { prov.addEventListener('change', updateModelSuggestions); }
    updateModelSuggestions();
})();
</script>
