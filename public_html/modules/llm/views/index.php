<?php
/**
 * Vista índice del módulo LLM — Análisis IA centrado en los datos del tenant.
 */
$anTasks = [
    'summary'         => 'Resumen ejecutivo',
    'incidents'       => 'Incidentes y alertas',
    'vulnerabilities' => 'Vulnerabilidades',
    'secure_score'    => 'Secure Score',
    'iocs'            => 'IOCs',
    'risks'           => 'Riesgos',
];
?>
<?php if (!$configured): ?>
<div class="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-xl p-6 mb-6">
    <div class="flex items-start gap-3">
        <svg class="w-5 h-5 text-amber-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        <div>
            <p class="text-sm font-medium text-amber-800 dark:text-amber-200">LLM no configurado</p>
            <p class="text-sm text-amber-700 dark:text-amber-300 mt-1">
                Configura un proveedor en <strong>Admin → APIs</strong> (perfiles de IA).
            </p>
            <p class="text-xs text-amber-600 dark:text-amber-400 mt-2">Proveedores soportados: openai, anthropic, azure, ollama, ollama_cloud, gemini, mistral</p>
            <a href="<?= base_url('admin/apis') ?>" class="mt-3 inline-flex items-center gap-2 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">
                Configurar APIs
            </a>
        </div>
    </div>
</div>
<?php else: ?>
<div class="mb-4 flex items-center gap-3 flex-wrap">
    <span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">Configurado</span>
    <?php if (count($profiles ?? []) > 1): ?>
        <label class="text-sm text-gray-500">Modelo:</label>
        <select id="llm-profile" class="px-2 py-1 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <?php foreach ($profiles as $p): ?>
                <option value="<?= (int)$p['id'] ?>" <?= (int)($defaultProfileId ?? 0) === (int)$p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?><?= !empty($p['model']) ? ' · ' . e($p['model']) : '' ?></option>
            <?php endforeach; ?>
        </select>
    <?php else: ?>
        <span class="text-sm text-gray-500">Proveedor: <strong><?= e($provider) ?></strong> · Modelo: <strong><?= e($model) ?></strong></span>
    <?php endif; ?>
</div>

<?php if (empty($tenants)): ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
    <p class="text-sm text-gray-500">No hay tenants configurados.</p>
    <a href="<?= base_url('admin/tenant/edit') ?>" class="inline-block mt-3 text-sm text-brand-500 hover:underline">Añadir tenant</a>
</div>
<?php else: ?>

<!-- Configuración del análisis -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-6">
    <h2 class="text-sm font-semibold mb-3">Análisis del tenant</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
            <label class="block text-xs text-gray-500 mb-1">Tenant</label>
            <select id="an-tenant" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <?php foreach ($tenants as $t): ?>
                    <option value="<?= (int)$t['id'] ?>"><?= e($t['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Pregunta libre <span class="text-gray-400">(opcional)</span></label>
            <input type="text" id="an-question" placeholder="p. ej. ¿cuáles son los riesgos más urgentes?" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
    </div>
    <p class="text-xs text-gray-400 mt-3">
        El análisis usa los <strong>datos locales</strong> del tenant seleccionado (incidentes, alertas, IOCs, vulnerabilidades, Secure Score…).
        Esos datos se envían al proveedor de IA configurado.
    </p>
    <div class="flex flex-wrap gap-2 mt-4">
        <?php foreach ($anTasks as $key => $label): ?>
            <button type="button" onclick="analyzeTenant('<?= e($key) ?>')" class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">
                <?= e($label) ?>
            </button>
        <?php endforeach; ?>
        <button type="button" onclick="analyzeTenant('question')" class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-xs font-medium rounded-lg transition-colors">
            Responder a la pregunta
        </button>
    </div>
</div>

<!-- Respuesta -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
    <h2 class="text-sm font-semibold mb-4">Análisis</h2>
    <div id="llm-response" class="md-body min-h-[200px]">
        <p class="text-gray-400">Elige un tenant y pulsa una acción de análisis (o formula una pregunta).</p>
    </div>
</div>

<script>
function getProfile() { var s = document.getElementById('llm-profile'); return s ? parseInt(s.value, 10) : 0; }

function analyzeTenant(task) {
    var sel = document.getElementById('an-tenant');
    var tid = sel ? sel.value : '';
    if (!tid) { toast('Selecciona un tenant', 'warning'); return; }

    var q = document.getElementById('an-question');
    var question = q ? q.value : '';
    if (task === 'question' && !question.trim()) { toast('Escribe una pregunta', 'warning'); return; }

    var out = document.getElementById('llm-response');
    out.innerHTML = '<div class="spinner mx-auto"></div>';

    api('POST', '<?= base_url('modules/llm/analyze-tenant') ?>', {
        tenant_id: parseInt(tid, 10),
        task: task,
        question: question,
        profile_id: getProfile()
    })
        .then(function(res) {
            if (res.success) {
                out.innerHTML = res.content_html || esc(res.content);
            } else {
                out.innerHTML = '<p class="text-red-500">' + esc(res.error || 'Error') + '</p>';
                toast('Error: ' + (res.error || ''), 'error');
            }
        })
        .catch(function() { out.innerHTML = '<p class="text-red-500">Error de conexión</p>'; });
}

function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }
</script>

<?php endif; ?>
<?php endif; ?>
