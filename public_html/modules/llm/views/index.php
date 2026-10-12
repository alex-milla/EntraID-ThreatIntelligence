<?php
/**
 * Vista índice del módulo LLM — Análisis IA sobre los datos del tenant.
 */
$anTasks = [
    'summary'         => 'Resumen ejecutivo',
    'incidents'       => 'Incidentes y alertas',
    'vulnerabilities' => 'Vulnerabilidades',
    'secure_score'    => 'Secure Score',
    'iocs'            => 'IOCs',
    'articles'        => 'Artículos TI',
    'risks'           => 'Riesgos',
];
?>
<?php if (!$configured): ?>
<div class="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-xl p-6 mb-6">
    <div class="flex items-start gap-3">
        <svg class="w-5 h-5 text-amber-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        <div>
            <p class="text-sm font-medium text-amber-800 dark:text-amber-200">LLM no configurado</p>
            <p class="text-sm text-amber-700 dark:text-amber-300 mt-1">Configura un proveedor en <strong>Admin → APIs</strong> (perfiles de IA).</p>
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

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Consulta -->
    <div class="lg:col-span-1 bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 self-start">
        <h2 class="text-sm font-semibold mb-4">Consultar datos del tenant</h2>

        <label class="block text-xs text-gray-500 mb-1">Tenant</label>
        <select id="an-tenant" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= (int)$t['id'] ?>"><?= e($t['name']) ?></option>
            <?php endforeach; ?>
        </select>

        <label class="block text-xs text-gray-500 mb-1 mt-4">Pregunta</label>
        <textarea id="an-question" rows="4" placeholder="p. ej. títulos y enlaces de las últimas noticias y sus IOCs asociados" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none"></textarea>

        <button type="button" onclick="analyzeTenant('question')" class="w-full mt-3 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Preguntar</button>

        <label class="inline-flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-3 cursor-pointer">
            <input type="checkbox" id="an-detailed" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
            Más detalle (envía más datos del tenant)
        </label>

        <p class="text-xs text-gray-400 mt-4">
            Usa los <strong>datos locales</strong> del tenant: incidentes, alertas, IOCs, artículos de Threat Intel (con enlace y sus IOCs), vulnerabilidades, Secure Score… Esos datos se envían al proveedor de IA configurado.
        </p>
    </div>

    <!-- Resultado -->
    <div class="lg:col-span-2 bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-semibold">Acciones rápidas</h2>
            <span id="an-status" class="text-xs text-gray-400"></span>
        </div>
        <div class="flex flex-wrap gap-2 mb-4">
            <?php foreach ($anTasks as $key => $label): ?>
                <button type="button" onclick="analyzeTenant('<?= e($key) ?>')" class="inline-flex items-center px-3 py-1.5 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-xs font-medium rounded-lg transition-colors">
                    <?= e($label) ?>
                </button>
            <?php endforeach; ?>
        </div>
        <div id="llm-response" class="md-body min-h-[240px] border-t border-gray-100 dark:border-gray-700 pt-4">
            <p class="text-gray-400">Elige un tenant, escribe una pregunta o pulsa una acción rápida.</p>
        </div>
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
    if (task === 'question' && !question.trim()) {
        toast('Escribe una pregunta', 'warning');
        if (q) q.focus();
        return;
    }

    var detailed = document.getElementById('an-detailed').checked ? 1 : 0;
    var out = document.getElementById('llm-response');
    var st = document.getElementById('an-status');
    st.textContent = 'Analizando…';
    out.innerHTML = '<div class="spinner mx-auto"></div>';

    api('POST', '<?= base_url('modules/llm/analyze-tenant') ?>', {
        tenant_id: parseInt(tid, 10),
        task: task,
        question: question,
        detailed: detailed,
        profile_id: getProfile()
    })
        .then(function(res) {
            st.textContent = '';
            if (res.success) {
                out.innerHTML = res.content_html || esc(res.content);
            } else {
                out.innerHTML = '<p class="text-red-500">' + esc(res.error || 'Error') + '</p>';
                toast('Error: ' + (res.error || ''), 'error');
            }
        })
        .catch(function() { st.textContent = ''; out.innerHTML = '<p class="text-red-500">Error de conexión</p>'; });
}

function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }
</script>

<?php endif; ?>
<?php endif; ?>
