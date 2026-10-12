<?php
/**
 * Vista índice del módulo LLM — Análisis IA sobre los datos del tenant.
 * Las acciones rápidas se leen de la tabla llm_actions (editables en Admin → APIs).
 */
?>
<?php if (!$configured): ?>
<div class="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-xl p-6 mb-6">
    <div class="flex items-start gap-3">
        <svg class="w-5 h-5 text-amber-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        <div>
            <p class="text-sm font-medium text-amber-800 dark:text-amber-200">LLM no configurado</p>
            <p class="text-sm text-amber-700 dark:text-amber-300 mt-1">Configura un proveedor en <strong>Admin → APIs</strong> (perfiles de IA).</p>
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

        <button type="button" onclick="analyzeTenantQuestion()" class="w-full mt-3 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Preguntar</button>

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
            <div class="flex items-center gap-2">
                <span id="an-status" class="text-xs text-gray-400"></span>
                <?php if (Auth::isAdmin()): ?>
                    <div class="relative">
                        <button type="button" onclick="toggleActionsMenu()" class="w-7 h-7 inline-flex items-center justify-center rounded-lg text-gray-400 hover:text-brand-500 hover:bg-gray-100 dark:hover:bg-gray-800 text-lg leading-none" title="Opciones de acciones">&#8942;</button>
                        <div id="actions-menu" class="hidden absolute right-0 mt-1 z-20 w-48 bg-white dark:bg-surface-dark border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg py-1 text-sm">
                            <button type="button" onclick="openActionsEditor()" class="w-full text-left px-4 py-2 hover:bg-gray-50 dark:hover:bg-gray-800/60">Editar acciones…</button>
                            <button type="button" onclick="restoreActions()" class="w-full text-left px-4 py-2 hover:bg-gray-50 dark:hover:bg-gray-800/60 text-gray-500">Restaurar por defecto</button>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        <div class="flex flex-wrap gap-2 mb-4">
            <?php if (empty($actions ?? [])): ?>
                <p class="text-xs text-gray-400">No hay acciones rápidas configuradas. Añádelas en <a href="<?= base_url('admin/apis') ?>" class="text-brand-500 hover:underline">Admin → APIs</a>.</p>
            <?php else: ?>
                <?php foreach ($actions as $ac): ?>
                    <button type="button" onclick="analyzeTenantAction(<?= (int)$ac['id'] ?>)" class="inline-flex items-center px-3 py-1.5 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-xs font-medium rounded-lg transition-colors">
                        <?= e($ac['label']) ?>
                    </button>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
        <div id="an-result-actions" class="hidden items-center justify-end gap-2 mb-2">
            <button type="button" onclick="copyAnalysis()" class="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Copiar</button>
            <button type="button" onclick="downloadAnalysis()" class="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Descargar .md</button>
        </div>
        <div id="llm-response" class="md-body min-h-[240px] border-t border-gray-100 dark:border-gray-700 pt-4">
            <p class="text-gray-400">Elige un tenant, escribe una pregunta o pulsa una acción rápida.</p>
        </div>
    </div>
</div>

<?php if (Auth::isAdmin()): ?>
<!-- Modal: editar acciones rápidas -->
<div id="actions-modal" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/50 p-4">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 w-full max-w-2xl shadow-xl max-h-[90vh] flex flex-col">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h3 class="text-base font-semibold">Editar acciones rápidas</h3>
            <button type="button" onclick="closeActionsEditor()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">✕</button>
        </div>
        <div class="p-5 overflow-y-auto">
            <div id="actions-list" class="space-y-2 mb-5"></div>

            <div class="border-t border-gray-100 dark:border-gray-700 pt-4">
                <h4 id="action-form-title" class="text-sm font-semibold mb-3">Nueva acción</h4>
                <input type="hidden" id="action-id" value="0">
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div class="sm:col-span-2">
                        <label class="block text-xs text-gray-500 mb-1">Etiqueta (texto del botón)</label>
                        <input type="text" id="action-label" placeholder="Resumen ejecutivo" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <div>
                        <label class="block text-xs text-gray-500 mb-1">Orden</label>
                        <input type="number" id="action-position" value="0" min="0" max="9999" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                </div>
                <div class="mt-3">
                    <label class="block text-xs text-gray-500 mb-1">Prompt (instrucción para la IA)</label>
                    <textarea id="action-prompt" rows="3" placeholder="Elabora un RESUMEN EJECUTIVO…" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
                </div>
                <label class="inline-flex items-center gap-2 text-sm mt-3">
                    <input type="checkbox" id="action-active" checked class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                    Activa
                </label>
                <div class="flex items-center gap-3 mt-4">
                    <button type="button" onclick="saveAction()" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Guardar acción</button>
                    <button type="button" onclick="newAction()" class="text-sm text-gray-500 hover:underline">Nueva acción</button>
                </div>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<script>
var LLM_ACTIONS = <?= json_encode(array_map(function ($a) {
    return ['id' => (int)$a['id'], 'label' => (string)$a['label'], 'prompt' => (string)$a['prompt'], 'position' => (int)$a['position'], 'is_active' => (int)$a['is_active']];
}, $actions ?? []), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

function toggleActionsMenu() {
    var m = document.getElementById('actions-menu');
    if (m) { m.classList.toggle('hidden'); }
}
document.addEventListener('click', function (ev) {
    var m = document.getElementById('actions-menu');
    if (m && !m.classList.contains('hidden') && !ev.target.closest('#actions-menu') && !ev.target.closest('button[title="Opciones de acciones"]')) {
        m.classList.add('hidden');
    }
});

function renderActionsList() {
    var list = document.getElementById('actions-list');
    if (!list) return;
    if (!LLM_ACTIONS.length) { list.innerHTML = '<p class="text-xs text-gray-400">No hay acciones.</p>'; return; }
    list.innerHTML = LLM_ACTIONS.map(function (a) {
        return '<div class="flex items-start justify-between gap-3 border border-gray-100 dark:border-gray-700 rounded-lg p-3">'
            + '<div class="min-w-0"><p class="text-sm font-medium">' + esc(a.label) + (a.is_active ? '' : ' <span class="text-xs text-gray-400">(inactiva)</span>') + '</p>'
            + '<p class="text-xs text-gray-400 truncate">' + esc(a.prompt) + '</p></div>'
            + '<div class="flex items-center gap-2 shrink-0">'
            + '<button type="button" onclick="editAction(' + a.id + ')" class="text-xs text-brand-500 hover:underline">Editar</button>'
            + '<button type="button" onclick="deleteAction(' + a.id + ')" class="text-xs text-red-500 hover:underline">Eliminar</button>'
            + '</div></div>';
    }).join('');
}
function openActionsEditor() {
    var menu = document.getElementById('actions-menu');
    if (menu) menu.classList.add('hidden');
    renderActionsList();
    newAction();
    var m = document.getElementById('actions-modal');
    if (m) { m.classList.remove('hidden'); m.classList.add('flex'); }
}
function closeActionsEditor() {
    var m = document.getElementById('actions-modal');
    if (m) { m.classList.add('hidden'); m.classList.remove('flex'); }
}
function newAction() {
    document.getElementById('action-id').value = '0';
    document.getElementById('action-label').value = '';
    document.getElementById('action-prompt').value = '';
    document.getElementById('action-position').value = '0';
    document.getElementById('action-active').checked = true;
    document.getElementById('action-form-title').textContent = 'Nueva acción';
}
function editAction(id) {
    var a = LLM_ACTIONS.filter(function (x) { return x.id === id; })[0];
    if (!a) return;
    document.getElementById('action-id').value = a.id;
    document.getElementById('action-label').value = a.label;
    document.getElementById('action-prompt').value = a.prompt;
    document.getElementById('action-position').value = a.position;
    document.getElementById('action-active').checked = !!a.is_active;
    document.getElementById('action-form-title').textContent = 'Editar acción';
}
function saveAction() {
    var prompt = document.getElementById('action-prompt').value;
    if (!prompt.trim()) { toast('El prompt no puede estar vacío', 'warning'); return; }
    api('POST', '<?= base_url('modules/llm/actions/save') ?>', {
        id: parseInt(document.getElementById('action-id').value, 10) || 0,
        label: document.getElementById('action-label').value,
        prompt: prompt,
        position: parseInt(document.getElementById('action-position').value, 10) || 0,
        is_active: document.getElementById('action-active').checked ? 1 : 0
    }).then(function (res) {
        if (res.success) { toast('Acción guardada', 'success'); setTimeout(function () { location.reload(); }, 700); }
        else { toast('Error: ' + (res.error || ''), 'error'); }
    }).catch(function () { toast('Error de conexión', 'error'); });
}
function deleteAction(id) {
    appConfirm('¿Eliminar esta acción?').then(function (ok) {
        if (!ok) return;
        api('POST', '<?= base_url('modules/llm/actions/delete') ?>', { id: id }).then(function (res) {
            if (res.success) { toast('Acción eliminada', 'success'); setTimeout(function () { location.reload(); }, 700); }
        });
    });
}
function restoreActions() {
    appConfirm('¿Restaurar las acciones por defecto? Se perderán las actuales.', { danger: true }).then(function (ok) {
        if (!ok) return;
        api('POST', '<?= base_url('modules/llm/actions/restore') ?>', {}).then(function (res) {
            if (res.success) { toast('Acciones restauradas', 'success'); setTimeout(function () { location.reload(); }, 700); }
        });
    });
}

function getProfile() { var s = document.getElementById('llm-profile'); return s ? parseInt(s.value, 10) : 0; }

function runAnalyze(payload) {
    var sel = document.getElementById('an-tenant');
    var tid = sel ? sel.value : '';
    if (!tid) { toast('Selecciona un tenant', 'warning'); return; }

    payload.tenant_id = parseInt(tid, 10);
    payload.detailed = document.getElementById('an-detailed').checked ? 1 : 0;
    payload.profile_id = getProfile();

    var out = document.getElementById('llm-response');
    var st = document.getElementById('an-status');
    st.textContent = 'Analizando…';
    setAnActions(false);
    out.innerHTML = '<div class="spinner mx-auto"></div>';

    api('POST', '<?= base_url('modules/llm/analyze-tenant') ?>', payload)
        .then(function(res) {
            st.textContent = '';
            if (res.success) {
                AN_RAW = res.content || '';
                out.innerHTML = res.content_html || esc(res.content);
                setAnActions(AN_RAW.trim() !== '');
            } else {
                out.innerHTML = '<p class="text-red-500">' + esc(res.error || 'Error') + '</p>';
                toast('Error: ' + (res.error || ''), 'error');
            }
        })
        .catch(function() { st.textContent = ''; out.innerHTML = '<p class="text-red-500">Error de conexión</p>'; });
}

var AN_RAW = '';
function setAnActions(show) {
    var el = document.getElementById('an-result-actions');
    if (!el) return;
    if (show) { el.classList.remove('hidden'); el.classList.add('flex'); }
    else { el.classList.add('hidden'); el.classList.remove('flex'); }
}
function copyAnalysis() {
    if (!AN_RAW) return;
    navigator.clipboard.writeText(AN_RAW).then(function () { toast('Copiado al portapapeles', 'success'); })
        .catch(function () { toast('No se pudo copiar', 'error'); });
}
function downloadAnalysis() {
    if (!AN_RAW) return;
    var d = new Date();
    var stamp = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
    downloadFile(AN_RAW, 'analisis-' + stamp + '.md', 'text/markdown');
}

function analyzeTenantAction(id) {
    runAnalyze({ action_id: id, question: '' });
}

function analyzeTenantQuestion() {
    var q = document.getElementById('an-question');
    var val = q ? q.value : '';
    if (!val.trim()) { toast('Escribe una pregunta', 'warning'); if (q) q.focus(); return; }
    runAnalyze({ action_id: 0, question: val });
}

function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }
</script>

<?php endif; ?>
<?php endif; ?>
