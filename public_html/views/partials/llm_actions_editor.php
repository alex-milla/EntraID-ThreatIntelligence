<?php
/**
 * Partial: editor (modal ⋮) de acciones rápidas de un ámbito.
 * Requiere: $actionScope (string) y $actionsEditorList (array de acciones).
 */
$__scope = $actionScope ?? 'tenant';
$__json = json_encode(array_map(function ($a) {
    return [
        'id'        => (int)$a['id'],
        'label'     => (string)$a['label'],
        'prompt'    => (string)$a['prompt'],
        'position'  => (int)$a['position'],
        'is_active' => (int)$a['is_active'],
    ];
}, $actionsEditorList ?? []), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>
<div id="scope-actions-modal" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/50 p-4">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 w-full max-w-2xl shadow-xl max-h-[90vh] flex flex-col">
        <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h3 class="text-base font-semibold">Editar acciones rápidas</h3>
            <button type="button" onclick="scopeCloseEditor()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">✕</button>
        </div>
        <div class="p-5 overflow-y-auto">
            <div id="scope-actions-list" class="space-y-2 mb-5"></div>
            <div class="border-t border-gray-100 dark:border-gray-700 pt-4">
                <h4 id="scope-form-title" class="text-sm font-semibold mb-3">Nueva acción</h4>
                <input type="hidden" id="scope-action-id" value="0">
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div class="sm:col-span-2">
                        <label class="block text-xs text-gray-500 mb-1">Etiqueta (texto del botón)</label>
                        <input type="text" id="scope-action-label" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <div>
                        <label class="block text-xs text-gray-500 mb-1">Orden</label>
                        <input type="number" id="scope-action-position" value="0" min="0" max="9999" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                </div>
                <div class="mt-3">
                    <label class="block text-xs text-gray-500 mb-1">Prompt (instrucción para la IA)</label>
                    <textarea id="scope-action-prompt" rows="3" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
                </div>
                <label class="inline-flex items-center gap-2 text-sm mt-3">
                    <input type="checkbox" id="scope-action-active" checked class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                    Activa
                </label>
                <div class="flex items-center gap-3 mt-4">
                    <button type="button" onclick="scopeSave()" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Guardar acción</button>
                    <button type="button" onclick="scopeNew()" class="text-sm text-gray-500 hover:underline">Nueva acción</button>
                    <button type="button" onclick="scopeRestore()" class="text-sm text-gray-400 hover:text-brand-500 ml-auto">Restaurar por defecto</button>
                </div>
            </div>
        </div>
    </div>
</div>
<script>
var SCOPE_ACTIONS = <?= $__json ?>;
var SCOPE_SCOPE = '<?= e($__scope) ?>';
function scopeEsc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function scopeRenderList() {
    var list = document.getElementById('scope-actions-list');
    if (!list) return;
    if (!SCOPE_ACTIONS.length) { list.innerHTML = '<p class="text-xs text-gray-400">No hay acciones.</p>'; return; }
    list.innerHTML = SCOPE_ACTIONS.map(function (a) {
        return '<div class="flex items-start justify-between gap-3 border border-gray-100 dark:border-gray-700 rounded-lg p-3">'
            + '<div class="min-w-0"><p class="text-sm font-medium">' + scopeEsc(a.label) + (a.is_active ? '' : ' <span class="text-xs text-gray-400">(inactiva)</span>') + '</p>'
            + '<p class="text-xs text-gray-400 truncate">' + scopeEsc(a.prompt) + '</p></div>'
            + '<div class="flex items-center gap-2 shrink-0">'
            + '<button type="button" onclick="scopeEdit(' + a.id + ')" class="text-xs text-brand-500 hover:underline">Editar</button>'
            + '<button type="button" onclick="scopeDelete(' + a.id + ')" class="text-xs text-red-500 hover:underline">Eliminar</button>'
            + '</div></div>';
    }).join('');
}
function scopeOpenEditor() { scopeRenderList(); scopeNew(); var m = document.getElementById('scope-actions-modal'); if (m) { m.classList.remove('hidden'); m.classList.add('flex'); } }
function scopeCloseEditor() { var m = document.getElementById('scope-actions-modal'); if (m) { m.classList.add('hidden'); m.classList.remove('flex'); } }
function scopeNew() {
    document.getElementById('scope-action-id').value = '0';
    document.getElementById('scope-action-label').value = '';
    document.getElementById('scope-action-prompt').value = '';
    document.getElementById('scope-action-position').value = '0';
    document.getElementById('scope-action-active').checked = true;
    document.getElementById('scope-form-title').textContent = 'Nueva acción';
}
function scopeEdit(id) {
    var a = SCOPE_ACTIONS.filter(function (x) { return x.id === id; })[0];
    if (!a) return;
    document.getElementById('scope-action-id').value = a.id;
    document.getElementById('scope-action-label').value = a.label;
    document.getElementById('scope-action-prompt').value = a.prompt;
    document.getElementById('scope-action-position').value = a.position;
    document.getElementById('scope-action-active').checked = !!a.is_active;
    document.getElementById('scope-form-title').textContent = 'Editar acción';
}
function scopeSave() {
    var prompt = document.getElementById('scope-action-prompt').value;
    if (!prompt.trim()) { toast('El prompt no puede estar vacío', 'warning'); return; }
    api('POST', '<?= base_url('modules/llm/actions/save') ?>', {
        id: parseInt(document.getElementById('scope-action-id').value, 10) || 0,
        label: document.getElementById('scope-action-label').value,
        prompt: prompt,
        position: parseInt(document.getElementById('scope-action-position').value, 10) || 0,
        is_active: document.getElementById('scope-action-active').checked ? 1 : 0,
        scope: SCOPE_SCOPE
    }).then(function (res) {
        if (res.success) { toast('Acción guardada', 'success'); setTimeout(function () { location.reload(); }, 700); }
        else { toast('Error: ' + (res.error || ''), 'error'); }
    }).catch(function () { toast('Error de conexión', 'error'); });
}
function scopeDelete(id) {
    appConfirm('¿Eliminar esta acción?').then(function (ok) {
        if (!ok) return;
        api('POST', '<?= base_url('modules/llm/actions/delete') ?>', { id: id }).then(function (res) {
            if (res.success) { toast('Acción eliminada', 'success'); setTimeout(function () { location.reload(); }, 700); }
        });
    });
}
function scopeRestore() {
    appConfirm('¿Restaurar las acciones por defecto de esta sección?', { danger: true }).then(function (ok) {
        if (!ok) return;
        api('POST', '<?= base_url('modules/llm/actions/restore') ?>', { scope: SCOPE_SCOPE }).then(function (res) {
            if (res.success) { toast('Acciones restauradas', 'success'); setTimeout(function () { location.reload(); }, 700); }
        });
    });
}
(function () {
    var m = document.getElementById('scope-actions-modal');
    if (m) { m.addEventListener('click', function (ev) { if (ev.target === m) scopeCloseEditor(); }); }
})();
</script>
