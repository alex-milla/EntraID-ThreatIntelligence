<?php
/**
 * Vista índice del módulo LLM.
 */
?>
<?php if (!$configured): ?>
<div class="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-xl p-6 mb-6">
    <div class="flex items-start gap-3">
        <svg class="w-5 h-5 text-amber-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        <div>
            <p class="text-sm font-medium text-amber-800 dark:text-amber-200">LLM no configurado</p>
            <p class="text-sm text-amber-700 dark:text-amber-300 mt-1">
                Configura <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">LLM_PROVIDER</code>,
                <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">LLM_API_KEY</code> y
                <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">LLM_MODEL</code> en el archivo <code class="font-mono bg-amber-100 dark:bg-amber-900 px-1 rounded">.env</code>
            </p>
            <p class="text-xs text-amber-600 dark:text-amber-400 mt-2">Proveedores soportados: openai, anthropic, azure, ollama, gemini, mistral, opencode</p>
            <a href="<?= base_url('admin/apis') ?>" class="mt-3 inline-flex items-center gap-2 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">
                Configurar APIs
            </a>
        </div>
    </div>
</div>
<?php else: ?>
<div class="mb-4 flex items-center gap-3">
    <span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">Configurado</span>
    <span class="text-sm text-gray-500">Proveedor: <strong><?= e($provider) ?></strong> · Modelo: <strong><?= e($model) ?></strong></span>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Chat libre -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h2 class="text-sm font-semibold mb-4">Consulta al modelo</h2>
        <div class="space-y-3">
            <div>
                <label class="block text-xs text-gray-500 mb-1">Prompt del sistema</label>
                <textarea id="system-prompt" rows="2" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">Eres un analista de ciberseguridad senior.</textarea>
            </div>
            <div>
                <label class="block text-xs text-gray-500 mb-1">Mensaje</label>
                <textarea id="user-prompt" rows="4" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none" placeholder="Pregunta sobre seguridad, IOCs, incidentes..."></textarea>
            </div>
            <button onclick="sendChat()" class="w-full px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Enviar</button>
        </div>
    </div>

    <!-- Respuesta -->
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h2 class="text-sm font-semibold mb-4">Respuesta</h2>
        <div id="llm-response" class="md-body min-h-[200px]">
            <p class="text-gray-400">La respuesta aparecerá aquí...</p>
        </div>
    </div>
</div>

<!-- Análisis de datos -->
<div class="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-4">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4">
        <h3 class="text-sm font-semibold mb-2">Clasificar IOCs</h3>
        <p class="text-xs text-gray-500 mb-3">Clasifica los últimos IOCs del tenant seleccionado con IA.</p>
        <select id="ioc-tenant" class="w-full px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm mb-2">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>"><?= e($t['name']) ?></option>
            <?php endforeach; ?>
        </select>
        <button onclick="classifyIocs()" class="w-full px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">Clasificar</button>
    </div>
</div>

<script>
function sendChat() {
    var sys = document.getElementById('system-prompt').value;
    var usr = document.getElementById('user-prompt').value;
    if (!usr.trim()) { toast('Escribe un mensaje', 'warning'); return; }
    document.getElementById('llm-response').innerHTML = '<div class="spinner mx-auto"></div>';
    api('POST', '<?= base_url('modules/llm/chat') ?>', { system: sys, prompt: usr })
        .then(function(res) {
            if (res.success) {
                document.getElementById('llm-response').innerHTML = res.content_html || esc(res.content);
            } else {
                document.getElementById('llm-response').innerHTML = '<p class="text-red-500">' + esc(res.error || 'Error') + '</p>';
            }
        })
        .catch(function() { document.getElementById('llm-response').innerHTML = '<p class="text-red-500">Error de conexión</p>'; });
}

function classifyIocs() {
    var tid = document.getElementById('ioc-tenant').value;
    toast('Clasificando IOCs...', 'info');
    api('POST', '<?= base_url('modules/llm/classify-iocs') ?>', { tenant_id: parseInt(tid), limit: 30 })
        .then(function(res) {
            if (res.success) {
                document.getElementById('llm-response').innerHTML = res.content_html || esc(res.content);
                toast('Clasificación completada', 'success');
            } else {
                toast('Error: ' + (res.error || ''), 'error');
            }
        });
}

function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
</script>
<?php endif; ?>
