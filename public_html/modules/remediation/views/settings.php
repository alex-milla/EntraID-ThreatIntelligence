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
            <div class="pt-2">
                <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">
                    Guardar SLA
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
