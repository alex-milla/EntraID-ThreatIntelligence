<?php
/**
 * Parcial: detalle de un caso de seguimiento (v0.3.21).
 *
 * Se usa de dos formas:
 *   · incluido en views/vm.php cuando se navega con ?case=ID;
 *   · devuelto como fragmento por GET modules/cve/vm/{id}/panel para el
 *     panel inline (fetch), sin recargar la pantalla.
 *
 * v0.3.21 — ficha de trabajo en tres pestañas:
 *   1. Resumen y notas: nota rápida + historial unificado + edición plegada.
 *   2. Remediación IA: playbooks contextualizados y plan guardado.
 *   3. Activos: hallazgos por activo/servicio.
 * Los formularios y sus acciones no cambian: solo dejan de estar todos a la vez.
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
$cveId = strtoupper((string)($case['cve_id'] ?? ''));
$companyName = (string)($case['company_name'] ?? '');
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
$evidenceKinds = [
    'plan' => 'Plan de remediación',
    'detection' => 'Detección',
    'mitigation' => 'Mitigación / control compensatorio',
    'verification' => 'Verificación manual',
    'note' => 'Nota',
];
$quickNoteKinds = [
    'note' => 'Nota clave',
    'mitigation' => 'Mitigación aplicada',
    'detection' => 'Detección',
    'verification' => 'Verificación',
];

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

$riskSeverity = (string)($factors['severity'] ?? '');
$riskCvss = $factors['cvss'] ?? ($case['catalog_cvss'] ?? null);
$riskEpss = $factors['epss'] ?? ($case['catalog_epss'] ?? null);
$riskKev = !empty($case['kev_id']);
$riskKevDate = trim((string)($case['kev_date'] ?? ''));
$riskEpssDate = trim((string)($case['catalog_epss_date'] ?? ''));

// --- Historial unificado: evidencias + eventos en una sola línea de tiempo ---
$timeline = [];
foreach ($vmEvidence as $evRow) {
    $evKind = (string)($evRow['kind'] ?? 'note');
    $timeline[] = [
        'at'          => (string)($evRow['occurred_at'] ?? ''),
        'kind'        => 'evidence',
        'icon'        => match ($evKind) {
            'plan'         => 'assignment',
            'mitigation'   => 'shield',
            'detection'    => 'search',
            'verification' => 'verified',
            default        => 'sticky_note_2',
        },
        'title'       => $evidenceKinds[$evKind] ?? 'Evidencia',
        'comment'     => (string)($evRow['comment'] ?? ''),
        'reference'   => (string)($evRow['reference'] ?? ''),
        'user'        => (string)($evRow['username'] ?? 'sistema'),
        'source'      => (string)($evRow['source'] ?? 'manual'),
        'old'         => '',
        'new'         => '',
    ];
}
foreach ($vmEvents as $eventRow) {
    $evType = (string)($eventRow['event_type'] ?? '');
    $timeline[] = [
        'at'          => (string)($eventRow['created_at'] ?? ''),
        'kind'        => 'event',
        'icon'        => match ($evType) {
            'status'     => 'swap_horiz',
            'reobserved' => 'replay',
            'priority'   => 'flag',
            'due_date'   => 'event',
            default      => 'history',
        },
        'title'       => VmCases::eventLabel($evType),
        'comment'     => (string)($eventRow['comment'] ?? ''),
        'reference'   => '',
        'user'        => (string)($eventRow['username'] ?? 'sistema'),
        'source'      => 'auditoría',
        'old'         => (string)($eventRow['old_value'] ?? ''),
        'new'         => (string)($eventRow['new_value'] ?? ''),
    ];
}
usort($timeline, static function (array $a, array $b): int {
    return (int)strtotime($b['at']) <=> (int)strtotime($a['at']);
});
$timelineTotal = count($timeline);
$timelineVisible = array_slice($timeline, 0, 40);

// --- Playbooks IA: abren el asistente con el contexto del CVE y el prompt listo ---
$assistantUrl = base_url('modules/remediation?tab=assistant&cve=' . urlencode($cveId));
$playbooks = [
    [
        'icon'  => 'build',
        'title' => 'Plan de parcheo y rollback',
        'hint'  => 'Versiones/KB corregidas, despliegue, reinicio y vuelta atrás.',
        'text'  => 'Actúa como analista de vulnerabilidades senior. Para el CVE ' . $cveId . ' en esta organización, elabora un plan de remediación paso a paso: versiones o KB corregidas, orden de despliegue, ventana de mantenimiento, impacto de reinicio, comprobaciones previas y posteriores, y procedimiento de rollback. Incluye los comandos o pasos exactos cuando proceda y marca explícitamente lo que no puedas verificar.',
    ],
    [
        'icon'  => 'shield',
        'title' => 'Mitigación sin parche',
        'hint'  => 'Controles compensatorios inmediatos y cómo comprobarlos.',
        'text'  => 'Para el CVE ' . $cveId . ' no es posible aplicar el parche a corto plazo. Propón mitigaciones y controles compensatorios inmediatos (firewall, GPO, registro, configuración del servicio, segmentación) indicando alcance, limitaciones y cómo verificar que están realmente aplicados.',
    ],
    [
        'icon'  => 'search',
        'title' => 'Detección y verificación',
        'hint'  => 'KQL para Defender Hunting y/o script PowerShell de solo lectura.',
        'text'  => 'Genera mecanismos de detección y verificación para el CVE ' . $cveId . ': una consulta KQL para Defender Advanced Hunting y/o un script PowerShell de solo lectura que compruebe versión, archivo o configuración afectada. Indica cómo interpretar el resultado y qué evidencia adjuntar al cierre.',
    ],
    [
        'icon'  => 'mail',
        'title' => 'Nota ejecutiva para el cliente',
        'hint'  => 'Riesgo, acción solicitada y plazo, sin jerga.',
        'text'  => 'Redacta una nota ejecutiva breve (máximo 200 palabras) sobre el CVE ' . $cveId . ': qué riesgo supone, a quién afecta, qué acción se solicita y en qué plazo. Sin jerga innecesaria y sin inventar datos que no consten.',
    ],
];
$findingsCount = (int)($case['findings_count'] ?? 0);
?>

<div class="space-y-4" data-vm-case-root>

    <!-- Cabecera de trabajo -->
    <div class="flex items-start justify-between gap-3 flex-wrap">
        <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
                <h3 class="text-base font-bold font-mono"><?= e($cveId) ?></h3>
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
                Caso #<?= $caseId ?><?= $companyName !== '' ? ' · ' . e($companyName) : '' ?>
                · Origen: <?= e($sourceLabels[(string)($case['source'] ?? 'defender-tvm')] ?? '—') ?>
                · <?= $findingsCount ?> activo(s)
                <?php if ((string)($case['assignee_name'] ?? '') !== ''): ?>
                    · Responsable: <?= e((string)$case['assignee_name']) ?>
                <?php endif; ?>
            </p>
        </div>
        <a href="#vm-cve-info" data-vm-cve-scroll
           class="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-line text-[11px] font-medium hover:bg-muted">
            <i class="material-icons icon-14" aria-hidden="true">description</i>
            Ficha del CVE
        </a>
    </div>

    <?php if ($isReobserved && VmCases::isClosed($status)): ?>
        <div class="px-3 py-2 rounded-lg text-[11px] text-amber-700 bg-amber-50 dark:bg-amber-900/20 dark:text-amber-300">
            Este CVE ha vuelto a aparecer en una importación posterior. El caso sigue cerrado hasta que decidas reabrirlo.
        </div>
    <?php endif; ?>

    <!-- Resumen rápido -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <div class="rounded-lg bg-muted px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft">Primera observación</p>
            <p class="text-sm font-medium"><?= e($fmtDate((string)($case['first_seen_at'] ?? ''))) ?></p>
            <p class="text-[10px] text-ink-soft">
                <?= (int)($case['first_seen_import_id'] ?? 0) > 0 ? 'Importación #' . (int)$case['first_seen_import_id'] : 'Alta manual' ?>
            </p>
        </div>
        <div class="rounded-lg bg-muted px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft">Última observación</p>
            <p class="text-sm font-medium"><?= e($fmtDate((string)($case['last_seen_at'] ?? ''))) ?></p>
            <p class="text-[10px] text-ink-soft truncate" title="<?= e((string)($case['import_filename'] ?? '')) ?>">
                <?= e((string)($case['import_filename'] ?? 'Sin observación de TVM')) ?>
            </p>
        </div>
        <div class="rounded-lg bg-muted px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft">Fecha objetivo</p>
            <p class="text-sm font-medium"><?= e($fmtDate((string)($case['due_date'] ?? ''))) ?></p>
            <?php
            $daysLeft = VmCases::daysUntil((string)($case['due_date'] ?? ''), $today);
            $dueHint = $daysLeft === null
                ? 'Sin fecha objetivo'
                : ($daysLeft < 0
                    ? abs($daysLeft) . ' día(s) de retraso'
                    : ($daysLeft === 0 ? 'Vence hoy' : $daysLeft . ' día(s) restantes'));
            ?>
            <p class="text-[10px] <?= $daysLeft !== null && $daysLeft < 0 ? 'text-danger' : 'text-ink-soft' ?>"><?= e($dueHint) ?></p>
        </div>
        <div class="rounded-lg bg-muted px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft">Ticket externo</p>
            <p class="text-sm font-medium truncate" title="<?= e((string)($case['external_ticket'] ?? '')) ?>">
                <?= (string)($case['external_ticket'] ?? '') !== '' ? e((string)$case['external_ticket']) : '—' ?>
            </p>
            <p class="text-[10px] text-ink-soft"><?= e((string)($case['assignee_name'] ?? 'Sin responsable')) ?></p>
        </div>
    </div>

    <!-- Riesgo del CVE y motivo de la prioridad, plegado -->
    <details class="rounded-lg border border-line">
        <summary class="px-3 py-2 cursor-pointer select-none flex items-center justify-between gap-2 flex-wrap">
            <span class="text-[11px] font-semibold">Riesgo del CVE y prioridad local</span>
            <span class="text-[10px] text-ink-soft">
                <?= e(VmCases::priorityLabel($priority)) ?>
                · CVSS <?= $riskCvss !== null ? number_format((float)$riskCvss, 1) : 'sin datos' ?>
                · EPSS <?= $riskEpss !== null ? number_format((float)$riskEpss * 100, 1) . '%' : 'sin datos' ?>
                <?= $riskKev ? '· KEV' : '' ?>
            </span>
        </summary>
        <div class="px-3 pb-3 pt-1 border-t border-line space-y-2">
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                <div>
                    <span class="block text-[10px] text-ink-soft">Severidad NVD</span>
                    <span class="font-medium"><?= $riskSeverity !== '' ? e(ucfirst($riskSeverity)) : 'sin datos' ?></span>
                </div>
                <div>
                    <span class="block text-[10px] text-ink-soft">CVSS</span>
                    <span class="font-mono"><?= $riskCvss !== null ? number_format((float)$riskCvss, 1) : 'sin datos' ?></span>
                </div>
                <div>
                    <span class="block text-[10px] text-ink-soft">EPSS</span>
                    <span class="font-mono">
                        <?= $riskEpss !== null ? number_format((float)$riskEpss, 4) : 'sin datos' ?>
                        <?php if ($riskEpss !== null): ?>
                            <span class="block text-[9px] font-sans text-ink-soft"><?= e($fmtDate($riskEpssDate) !== '—' ? $fmtDate($riskEpssDate) : 'fecha sin datos') ?></span>
                        <?php endif; ?>
                    </span>
                </div>
                <div>
                    <span class="block text-[10px] text-ink-soft">CISA KEV</span>
                    <span class="font-medium"><?= $riskKev ? 'Sí' : 'No' ?></span>
                    <?php if ($riskKev): ?>
                        <span class="block text-[9px] text-ink-soft"><?= $riskKevDate !== '' ? 'Añadido ' . e($fmtDate($riskKevDate)) : 'fecha sin datos' ?></span>
                    <?php endif; ?>
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
                    Software:
                    <?php foreach (array_slice($softwareLabels, 0, 8) as $label): ?>
                        <span class="inline-flex px-1.5 py-0.5 rounded bg-muted text-[10px] mr-1"><?= e($label) ?></span>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <p class="text-[10px] text-ink-soft">
                La prioridad local combina estos factores con el dato importado; no es el riesgo total del parque.
            </p>
        </div>
    </details>

    <!-- Pestañas internas de la ficha -->
    <div class="flex items-center gap-1 border-b border-line" role="tablist" aria-label="Detalle del caso">
        <button type="button" data-vm-tab="summary" role="tab" aria-selected="true"
                class="px-3 py-2 text-xs font-semibold border-b-2 border-brand-500 text-brand-600 dark:text-brand-300">
            Resumen y notas
        </button>
        <button type="button" data-vm-tab="remediation" role="tab" aria-selected="false"
                class="px-3 py-2 text-xs font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
            Remediación IA
        </button>
        <button type="button" data-vm-tab="assets" role="tab" aria-selected="false"
                class="px-3 py-2 text-xs font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
            Activos<?= $findingsCount > 0 ? ' (' . $findingsCount . ')' : '' ?>
        </button>
    </div>

    <!-- ================= RESUMEN Y NOTAS ================= -->
    <section data-vm-pane="summary" class="space-y-3">
        <form method="post" action="<?= base_url('modules/cve/vm/evidence') ?>"
              class="rounded-lg border border-line p-3 space-y-2">
            <?= Csrf::field() ?>
            <input type="hidden" name="case_id" value="<?= $caseId ?>">
            <p class="text-[11px] font-semibold">Añadir nota o evidencia</p>
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <label class="block">
                    <span class="text-[10px] font-medium text-ink-muted">Tipo</span>
                    <select name="kind" class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                        <?php foreach ($quickNoteKinds as $key => $label): ?>
                            <option value="<?= e($key) ?>"><?= e($label) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <label class="block sm:col-span-2">
                    <span class="text-[10px] font-medium text-ink-muted">Comentario</span>
                    <input type="text" name="comment" maxlength="2000" required
                           placeholder="Qué has comprobado, decidido o aplicado"
                           class="mt-0.5 w-full px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                </label>
            </div>
            <div class="flex items-end gap-2 flex-wrap">
                <label class="block flex-1 min-w-[180px]">
                    <span class="text-[10px] font-medium text-ink-muted">Referencia (opcional)</span>
                    <input type="text" name="reference" maxlength="500" placeholder="Ticket, captura, escaneo…"
                           class="mt-0.5 w-full px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                </label>
                <button type="submit"
                        class="inline-flex items-center gap-1.5 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-[11px] font-semibold rounded-lg transition-colors">
                    <i class="material-icons icon-12" aria-hidden="true">add_comment</i>
                    Añadir
                </button>
            </div>
        </form>

        <details class="rounded-lg border border-line">
            <summary class="px-3 py-2 cursor-pointer select-none text-[11px] font-semibold">
                Editar caso, excepción y verificación
            </summary>
            <form method="post" action="<?= base_url('modules/cve/vm/update') ?>" class="px-3 pb-3 pt-2 space-y-3 border-t border-line">
                <?= Csrf::field() ?>
                <input type="hidden" name="case_id" value="<?= $caseId ?>">

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
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

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3" data-vm-risk>
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
                    <div>
                        <label class="block text-[11px] font-medium text-ink-muted mb-1">Aprobador de la excepción</label>
                        <input type="text" name="accepted_by" maxlength="120" value="<?= e((string)($case['accepted_by'] ?? '')) ?>"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <div>
                        <label class="block text-[11px] font-medium text-ink-muted mb-1">Fecha de aprobación</label>
                        <input type="date" name="accepted_approved_at" value="<?= e(substr((string)($case['accepted_approved_at'] ?? ''), 0, 10)) ?>"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <div class="sm:col-span-2">
                        <label class="block text-[11px] font-medium text-ink-muted mb-1">Controles compensatorios</label>
                        <textarea name="accepted_controls" rows="2" maxlength="2000"
                                  class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none"><?= e((string)($case['accepted_controls'] ?? '')) ?></textarea>
                    </div>
                </div>

                <div data-vm-verification class="grid grid-cols-1 sm:grid-cols-2 gap-3">
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
        </details>

        <?php if (in_array($status, ['resolved_verified', 'false_positive', 'risk_accepted'], true)): ?>
            <form method="post" action="<?= base_url('modules/cve/vm/reopen') ?>" class="rounded-lg border border-line p-3 space-y-2"
                  onsubmit="return confirm('¿Reabrir el caso? Se conservará todo el historial.');">
                <?= Csrf::field() ?>
                <input type="hidden" name="case_id" value="<?= $caseId ?>">
                <p class="text-[11px] font-semibold">Caso cerrado</p>
                <input type="text" name="comment" maxlength="500" placeholder="Motivo de la reapertura (opcional)"
                       class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs">
                <button type="submit"
                        class="w-full px-3 py-2 border border-amber-300 text-amber-700 dark:text-amber-300 text-xs font-medium rounded-lg hover:bg-amber-50 dark:hover:bg-amber-900/20 transition-colors">
                    Reabrir caso
                </button>
            </form>
        <?php endif; ?>

        <!-- Historial: evidencias y auditoría en una sola línea de tiempo -->
        <div class="rounded-lg border border-line p-3">
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="text-xs font-semibold">Historial</h4>
                <span class="text-[10px] text-ink-soft"><?= $timelineTotal ?> movimiento(s)</span>
            </div>
            <?php if ($timelineVisible === []): ?>
                <p class="text-[11px] text-ink-soft">Sin movimientos registrados.</p>
            <?php else: ?>
                <ol class="space-y-2 max-h-80 overflow-y-auto pr-1">
                    <?php foreach ($timelineVisible as $item): ?>
                        <li class="border-l-2 <?= $item['kind'] === 'evidence' ? 'border-brand-300' : 'border-line' ?> pl-3">
                            <p class="text-[11px] font-medium flex items-center gap-1">
                                <i class="material-icons icon-12 text-ink-soft" aria-hidden="true"><?= e($item['icon']) ?></i>
                                <?= e($item['title']) ?>
                                <?php if ($item['old'] !== '' || $item['new'] !== ''): ?>
                                    <span class="text-ink-soft font-normal"><?= e($item['old']) ?> → <?= e($item['new']) ?></span>
                                <?php endif; ?>
                            </p>
                            <?php if ($item['comment'] !== ''): ?>
                                <p class="text-[11px] text-ink-muted"><?= e($item['comment']) ?></p>
                            <?php endif; ?>
                            <?php if ($item['reference'] !== ''): ?>
                                <p class="text-[10px] text-ink-soft">Ref: <?= e($item['reference']) ?></p>
                            <?php endif; ?>
                            <p class="text-[10px] text-ink-soft">
                                <?= e($fmtDateTime($item['at'])) ?> · <?= e($item['user']) ?>
                                <?php if ($item['kind'] === 'evidence'): ?>
                                    · <?= e($item['source']) ?>
                                <?php endif; ?>
                            </p>
                        </li>
                    <?php endforeach; ?>
                </ol>
                <?php if ($timelineTotal > count($timelineVisible)): ?>
                    <p class="mt-2 text-[10px] text-ink-soft">
                        Se muestran los <?= count($timelineVisible) ?> movimientos más recientes de <?= $timelineTotal ?>.
                    </p>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <!-- Información del CVE: se carga aquí sin salir del caso -->
        <div class="rounded-lg border border-line p-3" id="vm-cve-info" data-vm-cve-section>
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="text-xs font-semibold">Información del CVE</h4>
                <span class="text-[10px] text-ink-soft">Catálogo local · KEV · EPSS · exploits</span>
            </div>
            <div data-vm-cve-panel
                 data-vm-cve-url="<?= base_url('modules/cve/vm/' . $caseId . '/cve-info') ?>">
                <p class="text-[11px] text-ink-soft">Cargando información del CVE…</p>
            </div>
        </div>
    </section>

    <!-- ================= REMEDIACIÓN IA ================= -->
    <section data-vm-pane="remediation" class="space-y-3" hidden>
        <div class="rounded-lg border border-line p-3">
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="text-xs font-semibold">Playbooks de remediación</h4>
                <span class="text-[10px] text-ink-soft">Abren el asistente con el CVE y el prompt listos</span>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <?php foreach ($playbooks as $playbook): ?>
                    <a href="<?= e($assistantUrl . '&prompt=' . urlencode($playbook['text'])) ?>"
                       class="group flex items-start gap-2 rounded-lg border border-line px-3 py-2 hover:border-brand-400 hover:bg-muted transition-colors">
                        <i class="material-icons icon-16 text-brand-600 dark:text-brand-300 mt-0.5" aria-hidden="true"><?= e($playbook['icon']) ?></i>
                        <span class="min-w-0">
                            <span class="block text-[11px] font-semibold"><?= e($playbook['title']) ?></span>
                            <span class="block text-[10px] text-ink-soft"><?= e($playbook['hint']) ?></span>
                        </span>
                    </a>
                <?php endforeach; ?>
            </div>
            <p class="mt-2 text-[10px] text-ink-soft">
                El asistente guarda el resultado como plan si lo pides; desde aquí puedes ampliarlo y fijarlo en el caso.
            </p>
        </div>

        <div class="rounded-lg border border-line p-3" data-vm-plan-section>
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="text-xs font-semibold">Plan de remediación</h4>
                <span class="text-[10px] text-ink-soft">Guardado en Remediation · Markdown</span>
            </div>
            <div data-vm-plan-panel
                 data-vm-plan-url="<?= base_url('modules/cve/vm/' . $caseId . '/remediation-plan') ?>">
                <p class="text-[11px] text-ink-soft">Cargando plan de remediación…</p>
            </div>
        </div>
    </section>

    <!-- ================= ACTIVOS ================= -->
    <section data-vm-pane="assets" class="space-y-3" hidden>
        <div class="rounded-lg border border-line p-3" data-vm-findings-section>
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="text-xs font-semibold">Hallazgos (activos o servicios)</h4>
                <span class="text-[10px] text-ink-soft">Un estado por activo</span>
            </div>
            <div data-vm-findings-panel
                 data-vm-findings-url="<?= base_url('modules/cve/vm/' . $caseId . '/findings') ?>">
                <p class="text-[11px] text-ink-soft">Cargando hallazgos…</p>
            </div>
        </div>
    </section>
</div>
