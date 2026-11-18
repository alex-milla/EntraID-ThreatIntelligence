<?php
/**
 * Vista: ajustes de SLA del módulo Remediación.
 * Variables compartidas: $org, $selectedOrgId, $sla, $taskProfileId, $profiles.
 */

$profileName = 'Predeterminado';
foreach ($profiles as $profile) {
    if ((int)$profile['id'] === (int)$taskProfileId) {
        $profileName = (string)$profile['name'];
        break;
    }
}
$slaCritical = is_array($slaCritical ?? null) ? $slaCritical : ['critical' => 3, 'high' => 7, 'medium' => 15, 'low' => 30];
$users = is_array($users ?? null) ? $users : [];
$roleMap = is_array($roleMap ?? null) ? $roleMap : [];
$roleLabels = is_array($roleLabels ?? null) ? $roleLabels : [];
?>
<div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
    <div class="lg:col-span-2 card p-5">
        <h2 class="text-sm font-semibold">Plazos de remediación (SLA)</h2>
        <p class="text-xs text-ink-muted mt-1">
            Se aplican al crear tareas cuando no se indica una fecha límite manual. Si el CVE está en CISA KEV,
            prevalece la fecha <em>due date</em> de KEV.
        </p>

        <form method="POST" action="<?= base_url('modules/remediation/settings/save') ?>" class="mt-4 space-y-3">
            <?= Csrf::field() ?>
            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <?php
                $fields = [
                    'critical' => ['Crítica', 'Critical'],
                    'high'     => ['Alta', 'High'],
                    'medium'   => ['Media', 'Medium'],
                    'low'      => ['Baja', 'Low'],
                ];
                ?>
                <?php foreach ($fields as $key => [$label, $hint]): ?>
                    <label class="block">
                        <span class="block text-xs font-medium text-ink-muted mb-1">
                            <?= e($label) ?> <span class="text-ink-soft">(<?= e($hint) ?>)</span>
                        </span>
                        <div class="flex items-center gap-2">
                            <input type="number" name="sla_<?= e($key) ?>" min="1" max="365" required
                                   value="<?= (int)($sla[$key] ?? 30) ?>"
                                   class="w-24 px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                            <span class="text-xs text-ink-muted">días</span>
                        </div>
                    </label>
                <?php endforeach; ?>
            </div>

            <div class="mt-5 pt-4 border-t border-line">
                <h3 class="text-xs font-semibold m-0">Activos en producción críticos</h3>
                <p class="text-[11px] text-ink-muted mt-1">
                    Plazo reforzado cuando el ticket afecta a algún activo con entorno
                    <strong>prod</strong> y criticidad <strong>alta</strong>.
                </p>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
                    <?php foreach ($fields as $key => [$label, $hint]): ?>
                        <label class="block">
                            <span class="block text-xs font-medium text-ink-muted mb-1">
                                <?= e($label) ?> <span class="text-ink-soft">(<?= e($hint) ?>)</span>
                            </span>
                            <div class="flex items-center gap-2">
                                <input type="number" name="sla_critical_asset_<?= e($key) ?>" min="1" max="365" required
                                       value="<?= (int)($slaCritical[$key] ?? 7) ?>"
                                       class="w-24 px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                                <span class="text-xs text-ink-muted">días</span>
                            </div>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="pt-2">
                <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">
                    Guardar SLA
                </button>
            </div>
        </form>
    </div>

    <div class="card p-5 mt-5">
        <h2 class="text-sm font-semibold">Roles de remediación</h2>
        <p class="text-xs text-ink-muted mt-1">
            Si no asignas ningún rol, todo el mundo mantiene el acceso actual (analista).
            <strong>Aprobador</strong> puede aceptar riesgos; <strong>Lectura</strong> no puede
            modificar tareas, cola ni informes. Los administradores conservan todos los permisos.
        </p>
        <form method="POST" action="<?= base_url('modules/remediation/settings/roles') ?>" class="mt-4">
            <?= Csrf::field() ?>
            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
            <div class="overflow-x-auto">
                <table class="data-table w-full text-xs">
                    <thead>
                        <tr class="text-[10px] uppercase text-ink-soft border-b border-line">
                            <th class="text-left px-3 py-2">Usuario</th>
                            <th class="text-left px-3 py-2">Rol</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-line-subtle">
                        <?php foreach ($users as $user): ?>
                            <?php $userId = (int)$user['id']; ?>
                            <tr>
                                <td class="px-3 py-2">
                                    <?= e((string)($user['display_name'] ?: $user['username'])) ?>
                                    <span class="text-[10px] text-ink-soft font-mono"><?= e((string)$user['username']) ?></span>
                                </td>
                                <td class="px-3 py-2">
                                    <?php if ((string)($user['role'] ?? '') === 'admin'): ?>
                                        <span class="px-1.5 py-0.5 rounded bg-brand-100 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300 text-[10px] font-semibold">
                                            Administrador (todos)
                                        </span>
                                    <?php else: ?>
                                        <select name="roles[<?= $userId ?>]"
                                                class="px-2 py-1 rounded border border-line-strong bg-input text-ink text-xs">
                                            <?php foreach ($roleLabels as $key => $label): ?>
                                                <option value="<?= e($key) ?>" <?= (string)($roleMap[$userId] ?? 'analista') === $key ? 'selected' : '' ?>>
                                                    <?= e($label) ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <div class="pt-3">
                <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">
                    Guardar roles
                </button>
            </div>
        </form>
    </div>

    <div class="space-y-4">
        <div class="card p-5">
            <h2 class="text-sm font-semibold">Asistente IA</h2>
            <p class="text-xs text-ink-muted mt-1">
                Perfil asignado a la tarea <span class="font-mono">remediation_assistant</span>:
                <strong><?= e($profileName) ?></strong>.
            </p>
            <a href="<?= base_url('admin/apis') ?>" class="inline-block mt-2 text-xs text-primary hover:underline">
                Configurar perfiles y tareas IA →
            </a>
        </div>

        <div class="card p-5">
            <h2 class="text-sm font-semibold">Cómo se calcula el SLA</h2>
            <ol class="mt-2 space-y-1.5 text-xs text-ink-muted list-decimal list-inside">
                <li>Si el CVE está en CISA KEV y tiene <em>due date</em>, se usa esa fecha.</li>
                <li>Si no, se aplica el plazo por severidad de esta página.</li>
                <li>Si algún activo es <strong>prod + criticidad alta</strong>, se aplica el plazo reforzado.</li>
                <li>La fecha límite se puede ajustar manualmente en cada tarea.</li>
            </ol>
        </div>

        <div class="card p-5">
            <h2 class="text-sm font-semibold">Organización</h2>
            <p class="text-xs text-ink-muted mt-1"><?= e((string)$org['name']) ?></p>
            <p class="text-[11px] text-ink-soft mt-0.5">
                <?= $org['kind'] === 'tenant' ? 'Tenant: ' . e((string)($org['tenant_name'] ?? '')) : 'Manual (sin Graph)' ?>
            </p>
            <p class="text-[11px] text-ink-soft mt-2">
                Los ajustes de SLA son globales para todas las organizaciones.
            </p>
        </div>
    </div>
</div>
