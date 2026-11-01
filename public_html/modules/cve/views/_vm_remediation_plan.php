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
        <p class="text-[11px] text-ink-muted">
            Sin plan guardado para <span class="font-mono"><?= e($vmRemediationCve) ?></span>
            en <?= e(implode(', ', $orgNames)) ?>.
        </p>
        <a href="<?= e($assistantUrl) ?>"
           class="inline-flex items-center gap-1 text-[11px] text-brand-600 dark:text-brand-300 hover:underline">
            Generarlo en el asistente
            <i class="material-icons icon-12" aria-hidden="true">arrow_forward</i>
        </a>
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
<?php endif; ?>
