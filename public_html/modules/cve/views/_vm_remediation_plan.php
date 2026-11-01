<?php
/**
 * Parcial: planes de remediación del caso (v0.3.6).
 *
 * Variables: $vmRemediationOrgs, $vmRemediationTasks, $vmRemediationFallback,
 *            $vmRemediationError, $vmRemediationCve.
 */

$vmRemediationOrgs = is_array($vmRemediationOrgs ?? null) ? $vmRemediationOrgs : [];
$vmRemediationTasks = is_array($vmRemediationTasks ?? null) ? $vmRemediationTasks : [];
$vmRemediationFallback = !empty($vmRemediationFallback);
$vmRemediationError = trim((string)($vmRemediationError ?? ''));
$vmRemediationCve = strtoupper((string)($vmRemediationCve ?? ''));
$vmRemediationUnsavedCount = max(0, (int)($vmRemediationUnsavedCount ?? 0));
$vmRemediationLastUnsaved = is_array($vmRemediationLastUnsaved ?? null) ? $vmRemediationLastUnsaved : null;
$vmRemediationCaseId = (int)($vmRemediationCaseId ?? 0);

$orgNames = [];
$firstOrgId = 0;
foreach ($vmRemediationOrgs as $orgRow) {
    $orgNames[(int)$orgRow['id']] = (string)($orgRow['name'] ?? '');
    if ($firstOrgId === 0) {
        $firstOrgId = (int)$orgRow['id'];
    }
}
$assistantUrl = base_url('modules/remediation?tab=assistant')
    . ($firstOrgId > 0 ? '&org=' . $firstOrgId : '')
    . ($vmRemediationCve !== '' ? '&cve=' . urlencode($vmRemediationCve) : '');
$statusLabels = [
    'open' => 'Abierta', 'in_progress' => 'En curso', 'blocked' => 'Bloqueada',
    'done' => 'Resuelta', 'patched' => 'Parcheada', 'accepted' => 'Riesgo aceptado',
];
$fmtDate = static function (?string $value): string {
    $value = trim((string)$value);
    if ($value === '') {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('d/m/Y H:i', $ts);
};
?>

<?php if ($vmRemediationError !== ''): ?>
    <div class="rounded-lg px-3 py-2 text-[11px] text-danger bg-danger-bg">
        No se pudo consultar Remediation: <?= e($vmRemediationError) ?>
    </div>
<?php elseif ($vmRemediationOrgs === []): ?>
    <div class="rounded-lg bg-muted px-3 py-2 space-y-1">
        <p class="text-[11px] text-ink-muted">
            No hay una organización de Remediation vinculada a esta empresa. Vincula una en
            <strong>Remediation → Editar organización → Empresa del CVE</strong> y sus planes aparecerán aquí.
        </p>
        <a href="<?= base_url('modules/remediation') ?>"
           class="inline-flex items-center gap-1 text-[11px] text-brand-600 dark:text-brand-300 hover:underline">
            Ir a Remediation <i class="material-icons icon-12" aria-hidden="true">arrow_forward</i>
        </a>
    </div>
<?php elseif ($vmRemediationTasks === []): ?>
    <div class="rounded-lg bg-muted px-3 py-2 space-y-1">
        <?php if ($vmRemediationUnsavedCount > 0): ?>
            <p class="text-[11px] text-ink-muted">
                Hay <?= $vmRemediationUnsavedCount ?> respuesta(s) de IA sobre
                <span class="font-mono"><?= e($vmRemediationCve) ?></span> en Remediation que
                aún no se han guardado como plan<?= $vmRemediationLastUnsaved !== null
                    ? ' (última: ' . e($fmtDate((string)($vmRemediationLastUnsaved['created_at'] ?? ''))) . ')'
                    : '' ?>.
            </p>
            <form data-vm-plan-save method="post"
                  action="<?= base_url('modules/cve/vm/' . $vmRemediationCaseId . '/remediation-save') ?>"
                  class="pt-1">
                <?= Csrf::field() ?>
                <button type="submit"
                        class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-[11px] font-semibold rounded-lg transition-colors">
                    <i class="material-icons icon-12" aria-hidden="true">save</i>
                    Guardar la última respuesta como plan
                </button>
            </form>
            <p class="text-[10px] text-ink-soft">
                Crea o reutiliza la tarea de Remediation de este CVE. El plan se mostrará aquí.
            </p>
        <?php else: ?>
            <p class="text-[11px] text-ink-muted">
                Sin plan guardado para <span class="font-mono"><?= e($vmRemediationCve) ?></span>
                en <?= e(implode(', ', $orgNames)) ?>.
            </p>
            <a href="<?= e($assistantUrl) ?>"
               class="inline-flex items-center gap-1 text-[11px] text-brand-600 dark:text-brand-300 hover:underline">
                Generarlo en el asistente
                <i class="material-icons icon-12" aria-hidden="true">arrow_forward</i>
            </a>
        <?php endif; ?>
    </div>
<?php else: ?>
    <?php if ($vmRemediationFallback): ?>
        <p class="mb-2 text-[10px] text-ink-soft">
            Organización vinculada automáticamente (solo existe una en Remediation).
        </p>
    <?php endif; ?>

    <div class="space-y-3">
        <?php foreach ($vmRemediationTasks as $task): ?>
            <?php
            $taskId = (int)$task['id'];
            $orgId = (int)$task['org_id'];
            $taskStatus = (string)($task['status'] ?? '');
            ?>
            <article class="rounded-lg border border-line overflow-hidden">
                <header class="px-3 py-2 bg-muted flex items-center justify-between gap-2 flex-wrap">
                    <div>
                        <p class="text-[11px] font-semibold">
                            <?= e((string)($task['title'] ?? ('Plan CVE ' . $vmRemediationCve))) ?>
                        </p>
                        <p class="text-[10px] text-ink-soft">
                            <?= e($orgNames[$orgId] ?? 'Organización') ?>
                            · Estado: <?= e($statusLabels[$taskStatus] ?? ($taskStatus !== '' ? $taskStatus : '—')) ?>
                            · Actualizado <?= e($fmtDate((string)($task['updated_at'] ?? ''))) ?>
                        </p>
                    </div>
                    <a href="<?= base_url('modules/remediation?tab=tasks&org=' . $orgId . '&task=' . $taskId) ?>"
                       class="text-[10px] text-brand-600 dark:text-brand-300 hover:underline">Abrir tarea</a>
                </header>
                <div class="px-3 py-2 md-body text-[11px] leading-relaxed">
                    <?= render_ai_markdown((string)($task['plan'] ?? '')) ?>
                </div>
                <footer class="px-3 py-2 border-t border-line">
                    <a href="<?= base_url('modules/remediation?tab=assistant&org=' . $orgId . '&task=' . $taskId) ?>"
                       class="text-[10px] text-brand-600 dark:text-brand-300 hover:underline">
                        Ampliar con el asistente
                    </a>
                </footer>
            </article>
        <?php endforeach; ?>
    </div>
    <?php if ($vmRemediationUnsavedCount > 0): ?>
        <div class="mt-3 rounded-lg border border-amber-200 dark:border-amber-900 bg-amber-50 dark:bg-amber-900/20 px-3 py-2 space-y-1">
            <p class="text-[11px] text-amber-700 dark:text-amber-300">
                Hay <?= $vmRemediationUnsavedCount ?> respuesta(s) más recientes del asistente sin guardar en el plan.
            </p>
            <form data-vm-plan-save method="post"
                  action="<?= base_url('modules/cve/vm/' . $vmRemediationCaseId . '/remediation-save') ?>">
                <?= Csrf::field() ?>
                <button type="submit"
                        class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-amber-300 text-amber-700 dark:text-amber-300 text-[11px] font-medium rounded-lg hover:bg-amber-100 dark:hover:bg-amber-900/30 transition-colors">
                    <i class="material-icons icon-12" aria-hidden="true">save</i>
                    Guardar la última respuesta como plan
                </button>
            </form>
        </div>
    <?php endif; ?>
<?php endif; ?>
