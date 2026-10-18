<?php
/**
 * Vista principal del módulo Remediación.
 * Variables: $isAdmin, $tab, $orgs, $org, $selectedOrgId, $tenants, $tasks,
 *            $filters, $selectedTask, $cveData, $chats, $chat, $messages,
 *            $stats, $sla, $llmConfigured, $profiles.
 */

$statusLabels = [
    'open'           => 'Abierta',
    'in_progress'    => 'En curso',
    'patched'        => 'Parcheada',
    'mitigated'      => 'Mitigada',
    'accepted'       => 'Aceptada',
    'false_positive' => 'Falso positivo',
];
$statusClasses = [
    'open'           => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'in_progress'    => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    'patched'        => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'mitigated'      => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    'accepted'       => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
    'false_positive' => 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
];
$severityLabels = [
    'Critical' => 'Crítica',
    'High'     => 'Alta',
    'Medium'   => 'Media',
    'Low'      => 'Baja',
    'None'     => 'Ninguna',
];
$severityClasses = [
    'Critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'High'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'Medium'   => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    'Low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'None'     => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
];

$modUrl = base_url('modules/remediation');
$link = static function (array $over = []) use ($modUrl, $tab, $selectedOrgId): string {
    $params = array_merge(['tab' => $tab, 'org' => $selectedOrgId], $over);
    $params = array_filter($params, static fn($v) => $v !== '' && $v !== null && $v !== 0);
    return $modUrl . '?' . http_build_query($params);
};

$flashData = flash();
?>
<?php foreach ($flashData as $type => $msg): ?>
    <?php
    $colors = match ($type) {
        'success' => 'bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-300',
        'error'   => 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300',
        default   => 'bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300',
    };
    ?>
    <div class="mb-4 px-4 py-3 rounded-lg text-sm <?= $colors ?>"><?= e((string)$msg) ?></div>
<?php endforeach; ?>

<div class="no-print mb-6 flex items-start justify-between gap-4 flex-wrap">
    <div>
        <h1 class="text-xl font-semibold">Remediación</h1>
        <p class="text-sm text-gray-500 mt-1">
            Tareas de remediación por organización, con SLA, parcheo, evidencia y asistente IA.
        </p>
    </div>
    <div class="flex items-end gap-2 flex-wrap">
        <form method="GET" action="<?= e($modUrl) ?>" class="flex items-end gap-2">
            <input type="hidden" name="tab" value="<?= e($tab) ?>">
            <label class="block">
                <span class="block text-[10px] font-semibold uppercase tracking-wide text-gray-400 mb-1">Organización</span>
                <select name="org" onchange="this.form.submit()"
                        class="min-w-[220px] px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    <?php foreach ($orgs as $o): ?>
                        <option value="<?= (int)$o['id'] ?>" <?= (int)$o['id'] === $selectedOrgId ? 'selected' : '' ?>>
                            <?= e((string)$o['name']) ?><?= $o['kind'] === 'tenant' ? ' · tenant' : '' ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </label>
        </form>
        <button type="button" onclick="openOrgModal()"
                class="px-3 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">
            + Organización
        </button>
        <?php if ($org !== null): ?>
            <button type="button" onclick='openOrgModal(<?= json_encode([
                'id' => (int)$org['id'],
                'name' => (string)$org['name'],
                'kind' => (string)$org['kind'],
                'tenant_id' => (int)($org['tenant_id'] ?? 0),
                'notes' => (string)($org['notes'] ?? ''),
            ], JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_UNESCAPED_UNICODE) ?>)'
                    class="px-3 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">
                Editar
            </button>
        <?php endif; ?>
    </div>
</div>

<div class="no-print flex items-center gap-2 mb-5 border-b border-gray-200 dark:border-gray-700">
    <?php
    $tabs = [
        'tasks'     => 'Bandeja',
        'assistant' => 'Asistente IA',
        'metrics'   => 'Métricas',
    ];
    if ($isAdmin) {
        $tabs['settings'] = 'Ajustes';
    }
    ?>
    <?php foreach ($tabs as $key => $label): ?>
        <a href="<?= e($modUrl . '?tab=' . $key . '&org=' . $selectedOrgId) ?>"
           class="px-3 py-2 -mb-px text-sm font-medium border-b-2 <?= $tab === $key
               ? 'border-brand-500 text-brand-600 dark:text-brand-300'
               : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300' ?>">
            <?= e($label) ?>
        </a>
    <?php endforeach; ?>
</div>

<?php if ($org === null): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
        <p class="text-sm font-semibold">No hay organización seleccionada</p>
        <p class="text-xs text-gray-500 mt-1">Crea una organización manual o vincula un tenant para empezar.</p>
    </div>
<?php else: ?>
    <?php if ($tab === 'assistant'): ?>
        <?php require __DIR__ . '/assistant.php'; ?>
    <?php elseif ($tab === 'metrics'): ?>
        <?php require __DIR__ . '/metrics.php'; ?>
    <?php elseif ($tab === 'settings' && $isAdmin): ?>
        <?php require __DIR__ . '/settings.php'; ?>
    <?php else: ?>
        <?php require __DIR__ . '/tasks.php'; ?>
    <?php endif; ?>
<?php endif; ?>

<!-- Modal organización -->
<div id="org-modal" class="hidden fixed inset-0 z-50 no-print">
    <div class="absolute inset-0 bg-black/40" onclick="closeOrgModal()"></div>
    <div class="relative mx-auto mt-20 w-[calc(100%-2rem)] max-w-lg bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 shadow-xl p-5">
        <div class="flex items-start justify-between gap-3">
            <div>
                <h3 class="text-sm font-semibold" id="org-modal-title">Nueva organización</h3>
                <p class="text-xs text-gray-500 mt-1">Manual (sin Graph) o vinculada a un tenant de Defender.</p>
            </div>
            <button type="button" onclick="closeOrgModal()" class="text-xs text-gray-400 hover:text-gray-600">Cerrar</button>
        </div>

        <form method="POST" action="<?= base_url('modules/remediation/orgs/save') ?>" class="mt-4 space-y-3">
            <?= Csrf::field() ?>
            <input type="hidden" name="id" id="org-id" value="0">
            <label class="block">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Nombre</span>
                <input type="text" name="name" id="org-name" maxlength="120" required
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            </label>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <label class="block">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Tipo</span>
                    <select name="kind" id="org-kind" onchange="syncOrgKind()"
                            class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                        <option value="manual">Manual (sin Graph)</option>
                        <option value="tenant">Vinculada a un tenant</option>
                    </select>
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Tenant</span>
                    <select name="tenant_id" id="org-tenant" disabled
                            class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none disabled:opacity-50">
                        <option value="0">—</option>
                        <?php foreach (($tenants ?? []) as $tenant): ?>
                            <option value="<?= (int)$tenant['id'] ?>"><?= e((string)$tenant['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
            </div>
            <label class="block">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Notas</span>
                <textarea name="notes" id="org-notes" rows="3"
                          class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
            </label>
            <div class="flex items-center justify-end gap-2 pt-2">
                <button type="button" onclick="closeOrgModal()"
                        class="px-3 py-2 border border-gray-300 dark:border-gray-600 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">
                    Cancelar
                </button>
                <button type="submit"
                        class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">
                    Guardar
                </button>
            </div>
        </form>

        <?php if ($isAdmin && $org !== null): ?>
            <form method="POST" action="<?= base_url('modules/remediation/orgs/delete') ?>" class="mt-3 pt-3 border-t border-gray-100 dark:border-gray-700"
                  data-confirm="¿Eliminar la organización «<?= e((string)$org['name']) ?>»? Se borrarán sus tareas y conversaciones." data-confirm-danger>
                <?= Csrf::field() ?>
                <input type="hidden" name="id" value="<?= (int)$org['id'] ?>">
                <button type="submit" class="text-xs text-red-600 dark:text-red-400 hover:underline">Eliminar organización actual</button>
            </form>
        <?php endif; ?>
    </div>
</div>

<script>
function openOrgModal(org) {
    org = org || null;
    var modal = document.getElementById('org-modal');
    if (!modal) return;
    document.getElementById('org-modal-title').textContent = org ? 'Editar organización' : 'Nueva organización';
    document.getElementById('org-id').value = org ? org.id : 0;
    document.getElementById('org-name').value = org ? org.name : '';
    document.getElementById('org-kind').value = org ? org.kind : 'manual';
    document.getElementById('org-tenant').value = org ? String(org.tenant_id || 0) : '0';
    document.getElementById('org-notes').value = org ? (org.notes || '') : '';
    syncOrgKind();
    modal.classList.remove('hidden');
    document.getElementById('org-name').focus();
}
function closeOrgModal() {
    var modal = document.getElementById('org-modal');
    if (modal) modal.classList.add('hidden');
}
function syncOrgKind() {
    var kind = document.getElementById('org-kind').value;
    document.getElementById('org-tenant').disabled = kind !== 'tenant';
}
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeOrgModal();
});
</script>
