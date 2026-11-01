<?php
/**
 * Parcial: detalle de un caso de seguimiento (v0.3.2).
 *
 * Se usa de dos formas:
 *   · incluido en views/vm.php cuando se navega con ?case=ID;
 *   · devuelto como fragmento por GET modules/cve/vm/{id}/panel para el
 *     panel inline (fetch), sin recargar la pantalla.
 *
 * Variables: $vmCase, $vmEvents, $vmEvidence.
 */

$case = is_array($vmCase ?? null) ? $vmCase : [];
if ($case === []) {
    echo '<p class="p-4 text-sm text-ink-muted">Caso no disponible.</p>';
    return;
}
$vmEvents = is_array($vmEvents ?? null) ? $vmEvents : [];
$vmEvidence = is_array($vmEvidence ?? null) ? $vmEvidence : [];

$status = (string)($case['status'] ?? 'detected');
$priority = (string)($case['priority'] ?? '');
$caseId = (int)($case['id'] ?? 0);
$today = date('Y-m-d');
$factors = safe_json_decode((string)($case['priority_factors'] ?? ''), []);
$factors = is_array($factors) ? $factors : [];
$reasons = is_array($factors['reasons'] ?? null) ? $factors['reasons'] : [];

$statusLabels = VmCases::STATUSES;
$priorityLabels = VmCases::PRIORITIES;
$priorityClasses = [
    'critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'high'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
];
$statusClasses = [
    'detected'             => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
    'in_review'            => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    'planned'              => 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
    'in_progress'          => 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300',
    'pending_verification' => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    'resolved_verified'    => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'risk_accepted'        => 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
    'false_positive'       => 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
];
$sourceLabels = ['defender-tvm' => 'CSV Defender TVM', 'catalog' => 'Mis CVE (catálogo)'];
$deadline = VmCases::deadlineState(
    (string)($case['due_date'] ?? ''),
    $status,
    (string)($case['accepted_until'] ?? ''),
    $today
);
$deadlineLabels = [
    'closed' => 'Cerrado', 'exception_expired' => 'Excepción caducada',
    'expired' => 'Vencido', 'due_soon' => 'Próximo', 'ok' => 'En plazo', 'none' => 'Sin fecha',
];
$deadlineClasses = [
    'closed' => 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
    'exception_expired' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'expired' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'due_soon' => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    'ok' => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'none' => 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
];
$evidenceKinds = ['plan' => 'Plan de remediación', 'verification' => 'Verificación manual', 'note' => 'Nota'];

$fmtDate = static function (?string $value): string {
    $value = trim((string)$value);
    if ($value === '') {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('d/m/Y', $ts);
};
$fmtDateTime = static function (?string $value): string {
    $value = trim((string)$value);
    if ($value === '') {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('d/m/Y H:i', $ts);
};

$isReobserved = false;
foreach ($vmEvents as $eventRow) {
    if ((string)($eventRow['event_type'] ?? '') === 'reobserved') {
        $isReobserved = true;
        break;
    }
}

$softwareLabels = [];
foreach (preg_split('/[;,]+/', (string)($case['related_software'] ?? '')) ?: [] as $pair) {
    $pair = trim($pair);
    if ($pair !== '') {
        $softwareLabels[] = $pair;
    }
}
?>

<div class="space-y-4">
    <div>
        <div class="flex items-center gap-2 flex-wrap">
            <h3 class="text-base font-bold font-mono"><?= e((string)$case['cve_id']) ?></h3>
            <a href="<?= base_url('modules/cve/detail/' . urlencode((string)$case['cve_id']) . '/panel') ?>"
               data-vm-panel data-vm-title="<?= e((string)$case['cve_id']) ?>"
               class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline">
                Ficha del CVE
            </a>
            <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $priorityClasses[$priority] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300' ?>">
                <?= e(VmCases::priorityLabel($priority)) ?>
            </span>
            <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium <?= $statusClasses[$status] ?? '' ?>">
                <?= e($statusLabels[$status] ?? $status) ?>
            </span>
            <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium <?= $deadlineClasses[$deadline] ?? '' ?>">
                <?= e($deadlineLabels[$deadline] ?? $deadline) ?>
            </span>
        </div>
        <p class="text-[11px] text-ink-soft mt-1">
            Caso #<?= $caseId ?> · <?= e((string)($case['company_name'] ?? 'Empresa')) ?>
            · Origen: <?= e($sourceLabels[(string)($case['source'] ?? 'defender-tvm')] ?? '—') ?>
        </p>
    </div>

    <?php if ($isReobserved && VmCases::isClosed($status)): ?>
        <div class="px-3 py-2 rounded-lg text-[11px] text-amber-700 bg-amber-50 dark:bg-amber-900/20 dark:text-amber-300">
            Este CVE ha vuelto a aparecer en una importación posterior. El caso sigue cerrado hasta que decidas reabrirlo.
        </div>
    <?php endif; ?>

    <div class="grid grid-cols-2 gap-2">
        <div class="rounded-lg bg-muted px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft">Primera observación</p>
            <p class="text-sm font-medium"><?= e($fmtDate((string)($case['first_seen_at'] ?? ''))) ?></p>
            <p class="text-[10px] text-ink-soft">
                <?= (int)($case['first_seen_import_id'] ?? 0) > 0 ? 'Importación #' . (int)$case['first_seen_import_id'] : 'Alta manual desde Mis CVE' ?>
            </p>
        </div>
        <div class="rounded-lg bg-muted px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft">Última observación</p>
            <p class="text-sm font-medium"><?= e($fmtDate((string)($case['last_seen_at'] ?? ''))) ?></p>
            <p class="text-[10px] text-ink-soft">
                <?php if ((string)($case['import_filename'] ?? '') !== ''): ?>
                    <?= e((string)$case['import_filename']) ?>
                <?php elseif ((int)($case['last_seen_import_id'] ?? 0) > 0): ?>
                    Importación #<?= (int)$case['last_seen_import_id'] ?>
                <?php else: ?>
                    Sin observación de TVM
                <?php endif; ?>
            </p>
        </div>
        <div class="rounded-lg bg-muted px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft">Fecha objetivo</p>
            <p class="text-sm font-medium"><?= e($fmtDate((string)($case['due_date'] ?? ''))) ?></p>
            <p class="text-[10px] text-ink-soft">Se guarda; no se recalcula sola</p>
        </div>
        <div class="rounded-lg bg-muted px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft">Responsable</p>
            <p class="text-sm font-medium"><?= e((string)($case['assignee_name'] ?? '—')) ?></p>
            <p class="text-[10px] text-ink-soft"><?= (string)($case['external_ticket'] ?? '') !== '' ? 'Ticket: ' . e((string)$case['external_ticket']) : 'Sin ticket externo' ?></p>
        </div>
    </div>

    <?php if ($reasons !== []): ?>
        <div>
            <p class="text-[10px] uppercase tracking-wide text-ink-soft mb-1">Motivo de la prioridad</p>
            <div class="flex flex-wrap gap-1.5">
                <?php foreach ($reasons as $reason): ?>
                    <span class="inline-flex px-2 py-0.5 rounded bg-muted text-[10px] text-ink-muted"><?= e((string)$reason) ?></span>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($softwareLabels !== []): ?>
        <div class="text-[11px] text-ink-soft">
            Software: <?php foreach (array_slice($softwareLabels, 0, 6) as $label): ?><span class="inline-flex px-1.5 py-0.5 rounded bg-muted text-[10px] mr-1"><?= e($label) ?></span><?php endforeach; ?>
        </div>
    <?php endif; ?>

    <form method="post" action="<?= base_url('modules/cve/vm/update') ?>" class="space-y-3 border-t border-line pt-4">
        <?= Csrf::field() ?>
        <input type="hidden" name="case_id" value="<?= $caseId ?>">

        <div class="grid grid-cols-2 gap-3">
            <div>
                <label class="block text-[11px] font-medium text-ink-muted mb-1">Estado</label>
                <select name="status" data-vm-status
                        class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <?php foreach ($statusLabels as $key => $label): ?>
                        <option value="<?= e($key) ?>" <?= $status === $key ? 'selected' : '' ?>><?= e($label) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label class="block text-[11px] font-medium text-ink-muted mb-1">Prioridad</label>
                <select name="priority"
                        class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="">Mantener (<?= e(VmCases::priorityLabel($priority)) ?>)</option>
                    <?php foreach ($priorityLabels as $key => $label): ?>
                        <option value="<?= e($key) ?>"><?= e($label) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label class="block text-[11px] font-medium text-ink-muted mb-1">Responsable</label>
                <input type="text" name="assignee_name" maxlength="120" value="<?= e((string)($case['assignee_name'] ?? '')) ?>"
                       class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            </div>
            <div>
                <label class="block text-[11px] font-medium text-ink-muted mb-1">Fecha objetivo</label>
                <input type="date" name="due_date" value="<?= e((string)($case['due_date'] ?? '')) ?>"
                       class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            </div>
        </div>

        <div>
            <label class="block text-[11px] font-medium text-ink-muted mb-1">Ticket externo (opcional)</label>
            <input type="text" name="external_ticket" maxlength="200" value="<?= e((string)($case['external_ticket'] ?? '')) ?>"
                   class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
        </div>

        <div class="grid grid-cols-2 gap-3" data-vm-risk>
            <div>
                <label class="block text-[11px] font-medium text-ink-muted mb-1">Motivo del riesgo aceptado</label>
                <input type="text" name="accepted_reason" maxlength="500" value="<?= e((string)($case['accepted_reason'] ?? '')) ?>"
                       class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            </div>
            <div>
                <label class="block text-[11px] font-medium text-ink-muted mb-1">Caducidad del riesgo</label>
                <input type="date" name="accepted_until" value="<?= e((string)($case['accepted_until'] ?? '')) ?>"
                       class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            </div>
        </div>

        <div data-vm-verification class="grid grid-cols-2 gap-3">
            <div>
                <label class="block text-[11px] font-medium text-ink-muted mb-1">Verificación manual (comentario)</label>
                <textarea name="verification_comment" rows="2" maxlength="2000" placeholder="Qué se comprobó y cómo"
                          class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
            </div>
            <div>
                <label class="block text-[11px] font-medium text-ink-muted mb-1">Referencia</label>
                <input type="text" name="verification_reference" maxlength="500" placeholder="Captura, ticket, escaneo…"
                       class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            </div>
        </div>

        <div>
            <label class="block text-[11px] font-medium text-ink-muted mb-1">Comentario (obligatorio para prórrogas)</label>
            <input type="text" name="comment" maxlength="2000"
                   class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
        </div>

        <button type="submit"
                class="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition-colors">
            <i class="material-icons icon-14" aria-hidden="true">save</i>
            Guardar cambios
        </button>
    </form>

    <form method="post" action="<?= base_url('modules/cve/vm/evidence') ?>" class="grid grid-cols-4 gap-2 border-t border-line pt-4">
        <?= Csrf::field() ?>
        <input type="hidden" name="case_id" value="<?= $caseId ?>">
        <select name="kind" class="px-2 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs">
            <?php foreach ($evidenceKinds as $key => $label): ?>
                <option value="<?= e($key) ?>"><?= e($label) ?></option>
            <?php endforeach; ?>
        </select>
        <input type="text" name="comment" maxlength="2000" required placeholder="Comentario de la evidencia"
               class="col-span-2 px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs">
        <input type="text" name="reference" maxlength="500" placeholder="Referencia"
               class="px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs">
        <button type="submit"
                class="col-span-4 px-3 py-2 border border-line-strong text-ink text-xs font-medium rounded-lg hover:bg-muted transition-colors">
            Añadir evidencia
        </button>
    </form>

    <?php if (in_array($status, ['resolved_verified', 'false_positive', 'risk_accepted'], true)): ?>
        <form method="post" action="<?= base_url('modules/cve/vm/reopen') ?>" class="border-t border-line pt-4 space-y-2"
              onsubmit="return confirm('¿Reabrir el caso? Se conservará todo el historial.');">
            <?= Csrf::field() ?>
            <input type="hidden" name="case_id" value="<?= $caseId ?>">
            <input type="text" name="comment" maxlength="500" placeholder="Motivo de la reapertura (opcional)"
                   class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs">
            <button type="submit"
                    class="w-full px-3 py-2 border border-amber-300 text-amber-700 dark:text-amber-300 text-xs font-medium rounded-lg hover:bg-amber-50 dark:hover:bg-amber-900/20 transition-colors">
                Reabrir caso
            </button>
        </form>
    <?php endif; ?>

    <div class="border-t border-line pt-4 grid grid-cols-1 gap-4">
        <div>
            <h4 class="text-xs font-semibold mb-2">Evidencias</h4>
            <?php if ($vmEvidence === []): ?>
                <p class="text-[11px] text-ink-soft">Sin evidencias registradas.</p>
            <?php else: ?>
                <ul class="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                    <?php foreach ($vmEvidence as $evRow): ?>
                        <li class="rounded-lg bg-muted px-3 py-2">
                            <p class="text-[11px] font-medium">
                                <?= e($evidenceKinds[(string)($evRow['kind'] ?? 'note')] ?? (string)($evRow['kind'] ?? '')) ?>
                                <span class="text-[10px] font-normal text-ink-soft">· <?= e((string)($evRow['source'] ?? 'manual')) ?></span>
                            </p>
                            <p class="text-[11px] text-ink-muted"><?= e((string)($evRow['comment'] ?? '')) ?></p>
                            <?php if ((string)($evRow['reference'] ?? '') !== ''): ?>
                                <p class="text-[10px] text-ink-soft">Ref: <?= e((string)$evRow['reference']) ?></p>
                            <?php endif; ?>
                            <p class="text-[10px] text-ink-soft"><?= e($fmtDate((string)($evRow['occurred_at'] ?? ''))) ?> · <?= e((string)($evRow['username'] ?? 'sistema')) ?></p>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
        <div>
            <h4 class="text-xs font-semibold mb-2">Historial</h4>
            <?php if ($vmEvents === []): ?>
                <p class="text-[11px] text-ink-soft">Sin eventos.</p>
            <?php else: ?>
                <ol class="space-y-2 max-h-72 overflow-y-auto pr-1">
                    <?php foreach ($vmEvents as $eventRow): ?>
                        <li class="border-l-2 border-line pl-3">
                            <p class="text-[11px] font-medium">
                                <?= e(VmCases::eventLabel((string)($eventRow['event_type'] ?? ''))) ?>
                                <?php if ((string)($eventRow['old_value'] ?? '') !== '' || (string)($eventRow['new_value'] ?? '') !== ''): ?>
                                    <span class="text-ink-soft font-normal"><?= e((string)($eventRow['old_value'] ?? '')) ?> → <?= e((string)($eventRow['new_value'] ?? '')) ?></span>
                                <?php endif; ?>
                            </p>
                            <?php if ((string)($eventRow['comment'] ?? '') !== ''): ?>
                                <p class="text-[11px] text-ink-muted"><?= e((string)$eventRow['comment']) ?></p>
                            <?php endif; ?>
                            <p class="text-[10px] text-ink-soft"><?= e($fmtDateTime((string)($eventRow['created_at'] ?? ''))) ?> · <?= e((string)($eventRow['username'] ?? 'sistema')) ?></p>
                        </li>
                    <?php endforeach; ?>
                </ol>
            <?php endif; ?>
        </div>
    </div>
</div>
