<?php
/**
 * Vista: bandeja de remediación.
 * Variables compartidas: $org, $selectedOrgId, $tasks, $filters, $selectedTask,
 * $cveData, $statusLabels, $statusClasses, $severityLabels, $severityClasses.
 */

$modUrl = base_url('modules/remediation');
$taskState = (string)($taskState ?? '');
$taskLog = is_array($taskLog ?? null) ? $taskLog : [];
$taskSla = is_array($taskSla ?? null) ? $taskSla : null;
$taskAssets = is_array($taskAssets ?? null) ? $taskAssets : [];
$taskCritical = !empty($taskCritical);
$users = is_array($users ?? null) ? $users : [];
$workflowLabels = is_array($workflowLabels ?? null) ? $workflowLabels : [];
$workflowClasses = is_array($workflowClasses ?? null) ? $workflowClasses : [];
$logTypeLabels = is_array($logTypeLabels ?? null) ? $logTypeLabels : [];
if ($taskState === '' && $selectedTask !== null && class_exists('RemediationWorkflow')) {
    $taskState = RemediationWorkflow::stateForStatus((string)($selectedTask['status'] ?? 'open'));
}
$isOverdue = static function (array $task): bool {
    if (empty($task['due_at'])) {
        return false;
    }
    if (in_array((string)$task['status'], ['patched', 'mitigated', 'accepted', 'false_positive'], true)) {
        return false;
    }
    return $task['due_at'] < date('Y-m-d');
};
$taskMachines = [];
if ($selectedTask !== null) {
    $decodedMachines = safe_json_decode((string)($selectedTask['machines_json'] ?? ''), []);
    $taskMachines = is_array($decodedMachines) ? $decodedMachines : [];
}
?>
<div class="no-print flex items-start justify-between gap-3 flex-wrap mb-4">
    <form method="GET" action="<?= e($modUrl) ?>" class="flex items-end gap-2 flex-wrap">
        <input type="hidden" name="tab" value="tasks">
        <input type="hidden" name="org" value="<?= (int)$selectedOrgId ?>">
        <label class="block">
            <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Estado</span>
            <select name="status" class="px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                <option value="">Todos</option>
                <?php foreach ($statusLabels as $key => $label): ?>
                    <option value="<?= e($key) ?>" <?= ($filters['status'] ?? '') === $key ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <label class="block">
            <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Severidad</span>
            <select name="severity" class="px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                <option value="">Todas</option>
                <?php foreach (['Critical', 'High', 'Medium', 'Low'] as $sev): ?>
                    <option value="<?= e($sev) ?>" <?= ($filters['severity'] ?? '') === $sev ? 'selected' : '' ?>><?= e($severityLabels[$sev]) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <label class="block">
            <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Buscar</span>
            <input type="search" name="q" value="<?= e((string)($filters['q'] ?? '')) ?>" placeholder="CVE, título, responsable"
                   class="w-48 px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-ink text-xs">
        </label>
        <label class="flex items-center gap-1.5 text-xs text-ink-muted mt-5">
            <input type="checkbox" name="overdue" value="1" <?= !empty($filters['overdue']) ? 'checked' : '' ?> class="rounded border-line-strong text-brand-500">
            Solo vencidas
        </label>
        <button type="submit" class="px-3 py-1.5 bg-gray-900 hover:bg-black text-white text-xs font-medium rounded-lg mt-5">Filtrar</button>
    </form>

    <div class="flex items-center gap-2 mt-5">
        <button type="button" onclick="openTaskModal()"
                class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">
            + Nueva tarea
        </button>
        <?php if (($org['kind'] ?? '') === 'tenant'): ?>
            <button type="button" onclick="openImportModal()"
                    class="px-4 py-2 border border-line-strong text-ink text-sm font-medium rounded-lg hover:bg-muted">
                Importar desde Defender
            </button>
        <?php endif; ?>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
    <div class="card overflow-hidden">
        <div class="px-4 py-3 border-b border-line flex items-center justify-between">
            <h2 class="text-sm font-semibold">Tareas</h2>
            <span class="text-[10px] text-ink-soft"><?= count($tasks) ?></span>
        </div>
        <?php if ($tasks === []): ?>
            <p class="p-6 text-xs text-ink-muted text-center">No hay tareas con esos filtros.</p>
        <?php else: ?>
            <div class="max-h-[65vh] overflow-y-auto divide-y divide-line-subtle">
                <?php foreach ($tasks as $task): ?>
                    <?php $overdue = $isOverdue($task); ?>
                    <a href="<?= e($modUrl . '?tab=tasks&org=' . $selectedOrgId . '&task=' . (int)$task['id']) ?>"
                       class="block px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/40 <?= $selectedTask !== null && (int)$selectedTask['id'] === (int)$task['id'] ? 'bg-brand-50 dark:bg-brand-950/40' : '' ?>">
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="font-mono text-xs font-semibold"><?= e((string)$task['cve_id']) ?></span>
                            <?php if (!empty($task['severity'])): ?>
                                <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $severityClasses[$task['severity']] ?? 'bg-gray-100 text-gray-600' ?>">
                                    <?= e($severityLabels[$task['severity']] ?? $task['severity']) ?>
                                </span>
                            <?php endif; ?>
                            <?php if (!empty($task['kev'])): ?>
                                <span class="px-1.5 py-0.5 rounded bg-danger-bg text-danger text-[10px] font-semibold">KEV</span>
                            <?php endif; ?>
                            <span class="ml-auto px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $statusClasses[$task['status']] ?? 'bg-gray-100 text-gray-600' ?>">
                                <?= e($statusLabels[$task['status']] ?? $task['status']) ?>
                            </span>
                        </div>
                        <p class="text-xs text-ink-muted truncate mt-1"><?= e((string)($task['title'] ?? '')) ?></p>
                        <div class="flex items-center gap-2 text-[10px] text-ink-soft mt-1 flex-wrap">
                            <?php if (!empty($task['due_at'])): ?>
                                <span class="<?= $overdue ? 'text-red-500 font-semibold' : '' ?>">Vence <?= e(format_date((string)$task['due_at'], 'd/m/Y')) ?></span>
                            <?php endif; ?>
                            <?php if (!empty($task['owner'])): ?><span>· <?= e((string)$task['owner']) ?></span><?php endif; ?>
                            <span>· <?= (int)$task['machine_count'] ?> equipos</span>
                        </div>
                        <?php $taskSlaRow = is_array($task['_sla'] ?? null) ? $task['_sla'] : null; ?>
                        <?php if ($taskSlaRow !== null): ?>
                            <?php
                            $slaState = (string)($taskSlaRow['state'] ?? 'sin_datos');
                            $slaTextMap = RemediationSla::textClasses();
                            $slaBarMap = RemediationSla::barClasses();
                            ?>
                            <div class="mt-1.5 flex items-center gap-2 text-[10px]">
                                <span class="<?= $slaTextMap[$slaState] ?? 'text-ink-muted' ?>"><?= e((string)($taskSlaRow['label'] ?? '')) ?></span>
                                <?php if (!empty($taskSlaRow['critical'])): ?>
                                    <span class="px-1 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300 text-[9px] font-semibold">activo crítico</span>
                                <?php endif; ?>
                            </div>
                            <div class="mt-1 h-1 w-full rounded-full bg-muted overflow-hidden">
                                <div class="h-full <?= $slaBarMap[$slaState] ?? 'bg-gray-300' ?>" style="width: <?= (int)($taskSlaRow['pct'] ?? 0) ?>%"></div>
                            </div>
                        <?php endif; ?>
                    </a>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="lg:col-span-2">
        <?php if ($selectedTask === null): ?>
            <div class="card p-10 text-center">
                <p class="text-sm font-semibold">Ninguna tarea seleccionada</p>
                <p class="text-xs text-ink-muted mt-1">Elige una tarea de la lista o crea una nueva.</p>
            </div>
        <?php else: ?>
            <?php
            $task = $selectedTask;
            $overdue = $isOverdue($task);
            $catalog = is_array($cveData['catalog'] ?? null) ? $cveData['catalog'] : null;
            $kev = is_array($cveData['kev'] ?? null) ? $cveData['kev'] : null;
            $epss = is_array($cveData['epss'] ?? null) ? $cveData['epss'] : null;
            $references = $catalog !== null ? safe_json_decode((string)($catalog['references_json'] ?? ''), []) : [];
            ?>
            <div class="card p-5 mb-4">
                <div class="flex items-start justify-between gap-3 flex-wrap">
                    <div class="min-w-0">
                        <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft">Tarea de remediación</p>
                        <h2 class="text-xl font-bold font-mono mt-0.5"><?= e((string)$task['cve_id']) ?></h2>
                        <p class="text-xs text-ink-muted mt-1"><?= e((string)($task['title'] ?? '')) ?></p>
                    </div>
                    <div class="flex items-center gap-2 flex-wrap">
                        <span class="px-2 py-0.5 rounded text-[11px] font-semibold <?= $workflowClasses[$taskState] ?? 'bg-gray-100 text-gray-600' ?>">
                            <?= e($workflowLabels[$taskState] ?? $taskState) ?>
                        </span>
                        <span class="px-2 py-0.5 rounded text-[11px] font-semibold <?= $statusClasses[$task['status']] ?? 'bg-gray-100 text-gray-600' ?>">
                            <?= e($statusLabels[$task['status']] ?? $task['status']) ?>
                        </span>
                        <?php if (!empty($task['severity'])): ?>
                            <span class="px-2 py-0.5 rounded text-[11px] font-semibold <?= $severityClasses[$task['severity']] ?? 'bg-gray-100 text-gray-600' ?>">
                                <?= e($severityLabels[$task['severity']] ?? $task['severity']) ?>
                            </span>
                        <?php endif; ?>
                        <a href="<?= e($modUrl . '?tab=assistant&org=' . $selectedOrgId . '&task=' . (int)$task['id']) ?>"
                           class="px-3 py-1.5 bg-gray-900 hover:bg-black text-white text-xs font-medium rounded-lg">
                            Preguntar a la IA
                        </a>
                    </div>
                </div>

                <?php
            $logRows = is_array($taskLog ?? null) ? $taskLog : [];
            $impactDays = 0;
            $impactEntries = 0;
            foreach ($logRows as $logEntry) {
                if (in_array((string)($logEntry['tipo'] ?? ''), ['retraso', 'bloqueo'], true)) {
                    $impactDays += (int)($logEntry['impacto_dias'] ?? 0);
                    $impactEntries++;
                }
            }
            $etaActual = (string)($task['eta_actual'] ?? '');
            if ($etaActual === '') {
                $etaActual = (string)($task['due_at'] ?? '');
            }
            ?>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 text-xs">
                <div><p class="text-ink-soft">Responsable</p><p class="font-medium mt-0.5"><?= e((string)($task['owner'] ?? '—')) ?></p></div>
                <div>
                    <p class="text-ink-soft">Fecha límite</p>
                    <p class="font-medium mt-0.5 <?= $overdue ? 'text-red-500' : '' ?>">
                        <?= !empty($task['due_at']) ? e(format_date((string)$task['due_at'], 'd/m/Y')) : '—' ?>
                    </p>
                </div>
                <div>
                    <p class="text-ink-soft">ETA actual</p>
                    <p class="font-medium mt-0.5 <?= $overdue ? 'text-red-500' : '' ?>">
                        <?= $etaActual !== '' ? e(format_date($etaActual, 'd/m/Y')) : '—' ?>
                    </p>
                </div>
                <div>
                    <p class="text-ink-soft">Retrasos</p>
                    <p class="font-medium mt-0.5 <?= $impactDays > 0 ? 'text-amber-600 dark:text-amber-400' : '' ?>">
                        <?= $impactEntries > 0 ? '+' . $impactDays . ' d · ' . $impactEntries . ' entrada(s)' : '—' ?>
                    </p>
                </div>
                <div><p class="text-ink-soft">Equipos</p><p class="font-medium mt-0.5"><?= (int)$task['machine_count'] ?></p></div>
                <div><p class="text-ink-soft">Origen</p><p class="font-medium mt-0.5"><?= $task['source'] === 'defender' ? 'Defender' : 'Manual' ?></p></div>
                <div><p class="text-ink-soft">Parche/KB</p><p class="font-medium mt-0.5"><?= e((string)($task['patch_kb'] ?? '—')) ?></p></div>
                <div><p class="text-ink-soft">Versión corregida</p><p class="font-medium mt-0.5"><?= e((string)($task['fixed_version'] ?? '—')) ?></p></div>
                <div><p class="text-ink-soft">Creada</p><p class="font-medium mt-0.5"><?= e(format_date((string)$task['created_at'], 'd/m/Y')) ?></p></div>
                <div><p class="text-ink-soft">Resuelta</p><p class="font-medium mt-0.5"><?= !empty($task['resolved_at']) ? e(format_date((string)$task['resolved_at'], 'd/m/Y')) : '—' ?></p></div>
                <div><p class="text-ink-soft">Ventana</p><p class="font-medium mt-0.5"><?= e((string)($task['ventana_parcheo'] ?? '—')) ?></p></div>
                <div>
                    <p class="text-ink-soft">Bloqueado desde</p>
                    <p class="font-medium mt-0.5 <?= !empty($task['bloqueado_desde']) ? 'text-amber-600 dark:text-amber-400' : '' ?>">
                        <?= !empty($task['bloqueado_desde']) ? e(format_date((string)$task['bloqueado_desde'], 'd/m/Y')) : '—' ?>
                    </p>
                </div>
            </div>
            </div>

            <?php
            $steps = [
                'ticket_creado' => 'Ticket',
                'planificado'   => 'Planificado',
                'en_curso'      => 'En curso',
                'verificacion'  => 'Verificación',
                'cerrado'       => 'Cierre',
            ];
            $stepKeys = array_keys($steps);
            $stepIndex = array_search($taskState, $stepKeys, true);
            $stepIndex = $stepIndex === false ? 0 : (int)$stepIndex;
            $isBlocked = $taskState === 'bloqueado';
            $isRisk = $taskState === 'riesgo_aceptado';
            $riskDaysLeft = null;
            if ($isRisk && !empty($task['exception_until'])) {
                $riskDaysLeft = (int)floor(
                    (strtotime((string)$task['exception_until']) - strtotime(gmdate('Y-m-d'))) / 86400
                );
            }
            $visualIndex = $isRisk ? -1 : ($isBlocked ? 2 : $stepIndex);
            ?>
            <div class="card p-4 mb-4">
                <div class="flex items-center gap-1 sm:gap-2 flex-wrap">
                    <?php foreach ($stepKeys as $index => $stepKey): ?>
                        <?php $label = $steps[$stepKey]; ?>
                        <div class="flex items-center gap-1.5">
                            <span class="w-6 h-6 rounded-full inline-flex items-center justify-center text-[10px] font-bold
                                <?= $index <= $visualIndex ? 'bg-brand-500 text-white' : 'bg-muted text-ink-soft' ?>">
                                <?= $index + 1 ?>
                            </span>
                            <span class="text-[11px] <?= $index === $visualIndex ? 'font-semibold text-ink' : 'text-ink-soft' ?>">
                                <?= e($label) ?>
                            </span>
                            <?php if ($index < count($steps) - 1): ?>
                                <span class="hidden sm:inline-block w-8 h-px <?= $index < $visualIndex ? 'bg-brand-500' : 'bg-line' ?>"></span>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
                <?php if ($isBlocked): ?>
                    <p class="text-[11px] text-orange-700 dark:text-orange-300 m-0 mt-2">
                        Bloqueado<?= !empty($task['bloqueado_desde']) ? ' desde ' . e(format_date((string)$task['bloqueado_desde'], 'd/m/Y')) : '' ?>.
                        El SLA sigue corriendo; reactiva cuando se resuelva el bloqueo.
                    </p>
                <?php elseif ($isRisk): ?>
                    <p class="text-[11px] text-ink-muted m-0 mt-2">
                        Riesgo aceptado<?= !empty($task['exception_until']) ? ' hasta ' . e(format_date((string)$task['exception_until'], 'd/m/Y')) : '' ?>.
                        Al vencer vuelve sola a la cola.
                        <?php if ($riskDaysLeft !== null && $riskDaysLeft <= 7): ?>
                            <span class="ml-1 text-amber-700 dark:text-amber-300 font-semibold">
                                Caduca en <?= max(0, $riskDaysLeft) ?> día(s): revisa la justificación o renueva.
                            </span>
                        <?php endif; ?>
                    </p>
                <?php endif; ?>
            </div>

            <?php if ($taskSla !== null): ?>
                <?php
                $slaState = (string)($taskSla['state'] ?? 'sin_datos');
                $slaLabel = (string)($taskSla['label'] ?? '');
                $slaPct = (int)($taskSla['pct'] ?? 0);
                $slaDays = (int)($taskSla['days'] ?? 0);
                $slaTextMap = RemediationSla::textClasses();
                $slaBarMap = RemediationSla::barClasses();
                $slaStateLabels = RemediationSla::stateLabels();
                ?>
                <div class="card p-4 mb-4">
                    <div class="flex items-center justify-between gap-2 flex-wrap">
                        <div>
                            <p class="text-xs font-semibold m-0">
                                SLA · <span class="<?= $slaTextMap[$slaState] ?? 'text-ink-muted' ?>"><?= e($slaStateLabels[$slaState] ?? $slaState) ?></span>
                            </p>
                            <p class="text-[11px] text-ink-muted m-0 mt-0.5">
                                <?= e($slaLabel) ?>
                                <?php if ($taskCritical): ?>
                                    · <span class="text-orange-600 dark:text-orange-400 font-semibold">activo en producción crítico</span>
                                <?php endif; ?>
                            </p>
                        </div>
                        <span class="text-[11px] text-ink-soft">
                            <?= $slaDays ?> días de plazo<?= $taskCritical ? ' (reforzado)' : '' ?>
                        </span>
                    </div>
                    <div class="mt-2 h-1.5 w-full rounded-full bg-muted overflow-hidden">
                        <div class="h-full <?= $slaBarMap[$slaState] ?? 'bg-gray-300' ?>" style="width: <?= $slaPct ?>%"></div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($catalog !== null): ?>
                <div class="card p-5 mb-4">
                    <h3 class="text-sm font-semibold mb-3">Datos del CVE</h3>
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                        <div><p class="text-ink-soft">CVSS</p><p class="text-base font-bold"><?= $catalog['cvss_v3_score'] !== null ? e(number_format((float)$catalog['cvss_v3_score'], 1, '.', '')) : '—' ?></p></div>
                        <div><p class="text-ink-soft">EPSS</p><p class="text-base font-bold"><?= $epss !== null && $epss['epss'] !== null ? e(number_format((float)$epss['epss'] * 100, 2, ',', '')) . ' %' : '—' ?></p></div>
                        <div><p class="text-ink-soft">CISA KEV</p><p class="text-base font-bold"><?= $kev !== null ? 'Sí' : 'No' ?></p></div>
                        <div><p class="text-ink-soft">Publicado</p><p class="text-base font-bold"><?= e(format_date((string)($catalog['published_at'] ?? ''), 'd/m/Y')) ?></p></div>
                    </div>
                    <p class="text-[11px] font-mono text-ink-muted mt-3 break-all"><?= e((string)($catalog['cvss_v3_vector'] ?? '')) ?></p>
                    <p class="text-xs text-ink-muted mt-3 leading-relaxed"><?= e(CveReportAi::cleanTranslatedText((string)($catalog['description_es'] ?? '')) ?: (string)($catalog['description'] ?? '')) ?></p>
                    <?php if ($kev !== null && !empty($kev['required_action'])): ?>
                        <div class="mt-3 px-3 py-2 rounded-lg bg-danger-bg text-xs text-danger">
                            <strong>Acción CISA:</strong> <?= e(CveReportAi::cleanTranslatedText((string)($kev['required_action_es'] ?? '')) ?: (string)$kev['required_action']) ?>
                        </div>
                    <?php endif; ?>
                    <?php if (is_array($references) && $references !== []): ?>
                        <div class="mt-3">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft">Referencias</p>
                            <ul class="mt-1 space-y-1">
                                <?php foreach (array_slice($references, 0, 8) as $ref): ?>
                                    <?php $url = is_array($ref) ? (string)($ref['url'] ?? '') : (string)$ref; ?>
                                    <?php if ($url !== ''): ?>
                                        <li><a href="<?= e($url) ?>" target="_blank" rel="noopener noreferrer" class="text-xs text-primary hover:underline break-all"><?= e($url) ?></a></li>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <?php if ($taskAssets !== []): ?>
                <div class="card p-5 mb-4">
                    <div class="flex items-start justify-between gap-2 flex-wrap mb-3">
                        <div>
                            <h3 class="text-sm font-semibold m-0">Activos afectados</h3>
                            <p class="text-[11px] text-ink-muted m-0 mt-0.5">
                                Entorno y criticidad alimentan el SLA reforzado; el dueño es el equipo responsable.
                            </p>
                        </div>
                        <?php if ($taskCritical): ?>
                            <span class="px-2 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300 text-[10px] font-semibold">
                                activo prod crítico
                            </span>
                        <?php endif; ?>
                    </div>
                    <form method="POST" action="<?= e(base_url('modules/remediation/tasks/assets')) ?>">
                        <?= Csrf::field() ?>
                        <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                        <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                        <div class="max-h-[45vh] overflow-y-auto overflow-x-auto">
                            <table class="data-table w-full text-xs">
                                <thead class="sticky top-0 bg-surface">
                                    <tr class="text-[10px] uppercase text-ink-soft border-b border-line">
                                        <th class="text-left py-1.5 pr-3">Equipo</th>
                                        <th class="text-left py-1.5 pr-3">SO / exposición</th>
                                        <th class="text-left py-1.5 pr-3">Entorno</th>
                                        <th class="text-left py-1.5 pr-3">Criticidad</th>
                                        <th class="text-left py-1.5">Dueño</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-line-subtle">
                                    <?php foreach (array_slice($taskAssets, 0, 100) as $asset): ?>
                                        <?php $assetId = (int)($asset['id'] ?? 0); ?>
                                        <tr>
                                            <td class="py-1.5 pr-3 font-medium">
                                                <?= e((string)($asset['asset_name'] ?? '—')) ?>
                                            </td>
                                            <td class="py-1.5 pr-3 text-ink-muted max-w-[220px]">
                                                <?= e((string)($asset['notes'] ?? '—')) ?>
                                            </td>
                                            <td class="py-1.5 pr-3">
                                                <select name="assets[<?= $assetId ?>][environment]"
                                                        class="px-1.5 py-1 rounded border border-line-strong bg-input text-ink text-[11px]">
                                                    <?php foreach (['' => '—', 'prod' => 'Prod', 'pre' => 'Pre', 'test' => 'Test'] as $key => $label): ?>
                                                        <option value="<?= e($key) ?>" <?= (string)($asset['environment'] ?? '') === $key ? 'selected' : '' ?>>
                                                            <?= e($label) ?>
                                                        </option>
                                                    <?php endforeach; ?>
                                                </select>
                                            </td>
                                            <td class="py-1.5 pr-3">
                                                <select name="assets[<?= $assetId ?>][criticality]"
                                                        class="px-1.5 py-1 rounded border border-line-strong bg-input text-ink text-[11px]">
                                                    <?php foreach (['' => '—', 'alta' => 'Alta', 'media' => 'Media', 'baja' => 'Baja'] as $key => $label): ?>
                                                        <option value="<?= e($key) ?>" <?= (string)($asset['criticality'] ?? '') === $key ? 'selected' : '' ?>>
                                                            <?= e($label) ?>
                                                        </option>
                                                    <?php endforeach; ?>
                                                </select>
                                            </td>
                                            <td class="py-1.5">
                                                <input type="text" name="assets[<?= $assetId ?>][owner]"
                                                       value="<?= e((string)($asset['owner'] ?? '')) ?>"
                                                       maxlength="120" placeholder="Equipo responsable"
                                                       class="w-40 px-1.5 py-1 rounded border border-line-strong bg-input text-ink text-[11px]">
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <div class="flex items-center justify-between gap-2 mt-3 flex-wrap">
                            <p class="text-[10px] text-ink-soft m-0">
                                <?= count($taskAssets) ?> activo(s)<?= count($taskAssets) > 100 ? ' · se muestran 100' : '' ?>.
                                <?php if ((int)$task['machine_count'] > count($taskAssets)): ?>
                                    <?= (int)$task['machine_count'] ?> equipos según Defender.
                                <?php endif; ?>
                                Los equipos se sincronizan desde Defender al crear la tarea.
                            </p>
                            <button type="submit" class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                                Guardar activos
                            </button>
                        </div>
                    </form>
                </div>
            <?php elseif ($taskMachines !== []): ?>
                <div class="card p-5 mb-4">
                    <h3 class="text-sm font-semibold mb-3">Equipos afectados</h3>
                    <div class="overflow-x-auto">
                        <table class="data-table w-full text-xs">
                            <thead>
                                <tr class="text-[10px] uppercase text-ink-soft border-b border-line">
                                    <th class="text-left py-1.5 pr-3">Equipo</th>
                                    <th class="text-left py-1.5 pr-3">SO</th>
                                    <th class="text-left py-1.5">Exposición</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-line-subtle">
                                <?php foreach (array_slice($taskMachines, 0, 50) as $machine): ?>
                                    <tr>
                                        <td class="py-1.5 pr-3 font-medium"><?= e((string)($machine['name'] ?? '—')) ?></td>
                                        <td class="py-1.5 pr-3 text-ink-muted"><?= e((string)($machine['os'] ?? '—')) ?></td>
                                        <td class="py-1.5 text-ink-muted"><?= e((string)($machine['exposure'] ?? '—')) ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php if ((int)$task['machine_count'] > count($taskMachines)): ?>
                        <p class="text-[11px] text-ink-soft mt-1">… y <?= (int)$task['machine_count'] - count($taskMachines) ?> equipos más.</p>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <?php if (!empty($task['plan'])): ?>
                <div class="card p-5 mb-4">
                    <h3 class="text-sm font-semibold mb-2">Plan guardado</h3>
                    <pre class="text-xs whitespace-pre-wrap text-ink-muted font-sans"><?= e((string)$task['plan']) ?></pre>
                </div>
            <?php endif; ?>

            <div class="card p-5 mb-4">
                <?php
                $logTypeClasses = [
                    'cambio_estado' => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
                    'retraso'       => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
                    'bloqueo'       => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
                    'nota'          => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
                    'reapertura'    => 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
                    'riesgo'        => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
                ];
                ?>
                <div class="flex items-center justify-between gap-2 flex-wrap mb-3">
                    <h3 class="text-sm font-semibold m-0">Registro del ticket</h3>
                    <span class="text-[11px] text-ink-soft"><?= count($logRows) ?> entrada(s) · no editable</span>
                </div>
                <?php if ($logRows === []): ?>
                    <p class="text-xs text-ink-muted m-0">
                        Sin entradas todavía. Cada cambio de estado queda registrado aquí con autor y fecha.
                    </p>
                <?php else: ?>
                    <ol class="m-0 p-0 list-none space-y-2">
                        <?php foreach (array_slice($logRows, 0, 20) as $entry): ?>
                            <?php
                            $logType = (string)($entry['tipo'] ?? 'nota');
                            $logOrigin = (string)($entry['estado_origen'] ?? '');
                            $logTarget = (string)($entry['estado_destino'] ?? '');
                            $logImpact = (int)($entry['impacto_dias'] ?? 0);
                            ?>
                            <li class="flex items-start gap-2 text-[11px] border-b border-line-subtle pb-2 last:border-0 last:pb-0">
                                <span class="px-1.5 py-0.5 rounded text-[9px] font-semibold whitespace-nowrap <?= $logTypeClasses[$logType] ?? $logTypeClasses['nota'] ?>">
                                    <?= e($logTypeLabels[$logType] ?? $logType) ?>
                                    <?php if ($logImpact > 0): ?> +<?= $logImpact ?> d<?php endif; ?>
                                </span>
                                <div class="min-w-0 flex-1">
                                    <p class="m-0 text-ink">
                                        <?php if ($logOrigin !== '' || $logTarget !== ''): ?>
                                            <span class="text-ink-soft">
                                                <?= e($workflowLabels[$logOrigin] ?? $logOrigin) ?> →
                                                <?= e($workflowLabels[$logTarget] ?? $logTarget) ?> ·
                                            </span>
                                        <?php endif; ?>
                                        <?= e((string)($entry['texto'] ?? '')) ?>
                                    </p>
                                    <p class="m-0 mt-0.5 text-[10px] text-ink-soft">
                                        <?= e(format_date((string)$entry['created_at'], 'd/m/Y H:i')) ?>
                                        · <?= e((string)($entry['autor'] ?? 'Sistema')) ?>
                                    </p>
                                </div>
                            </li>
                        <?php endforeach; ?>
                    </ol>
                    <?php if (count($logRows) > 20): ?>
                        <p class="text-[10px] text-ink-soft mt-2 mb-0">… y <?= count($logRows) - 20 ?> entradas más antiguas.</p>
                    <?php endif; ?>
                <?php endif; ?>
            </div>

            <?php
            $transitions = RemediationWorkflow::transitions($taskState);
            $canIncident = in_array($taskState, ['ticket_creado', 'planificado', 'en_curso', 'bloqueado', 'verificacion'], true);
            $canClose = isset($transitions['cerrar']);
            $canRisk = isset($transitions['aceptar_riesgo']);
            $actionUrl = base_url('modules/remediation/tasks/action');
            ?>
            <div class="card p-5 mb-4" id="task-actions">
                <h3 class="text-sm font-semibold m-0">Acciones</h3>
                <p class="text-[11px] text-ink-muted mt-1 mb-3">
                    Solo se ofrecen las acciones válidas para el estado actual. Cada cambio queda en el registro.
                </p>
                <div class="flex items-center gap-2 flex-wrap">
                    <?php if ($taskState === 'ticket_creado'): ?>
                        <button type="button" onclick="openPlanModal()" class="btn">
                            <?= icon('event_available', 16) ?> Planificar
                        </button>
                    <?php elseif ($taskState === 'planificado'): ?>
                        <form method="POST" action="<?= e($actionUrl) ?>" class="m-0">
                            <?= Csrf::field() ?>
                            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                            <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                            <input type="hidden" name="action" value="iniciar">
                            <button type="submit" class="btn"><?= icon('play_arrow', 16) ?> Iniciar parcheo</button>
                        </form>
                    <?php elseif ($taskState === 'en_curso'): ?>
                        <form method="POST" action="<?= e($actionUrl) ?>" class="m-0">
                            <?= Csrf::field() ?>
                            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                            <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                            <input type="hidden" name="action" value="pasar_verificacion">
                            <button type="submit" class="btn"><?= icon('fact_check', 16) ?> Pasar a verificación</button>
                        </form>
                    <?php elseif ($taskState === 'bloqueado'): ?>
                        <form method="POST" action="<?= e($actionUrl) ?>" class="m-0">
                            <?= Csrf::field() ?>
                            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                            <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                            <input type="hidden" name="action" value="reactivar">
                            <button type="submit" class="btn"><?= icon('play_circle', 16) ?> Reactivar</button>
                        </form>
                    <?php elseif ($taskState === 'verificacion'): ?>
                        <button type="button" onclick="openCloseModal()" class="btn">
                            <?= icon('task_alt', 16) ?> Cerrar CVE
                        </button>
                    <?php elseif ($taskState === 'cerrado'): ?>
                        <form method="POST" action="<?= e($actionUrl) ?>" class="m-0"
                              data-confirm="¿Reabrir este CVE? Volverá a la cola de trabajo.">
                            <?= Csrf::field() ?>
                            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                            <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                            <input type="hidden" name="action" value="reabrir">
                            <button type="submit" class="btn btn-outline"><?= icon('undo', 16) ?> Reabrir</button>
                        </form>
                    <?php elseif ($taskState === 'riesgo_aceptado'): ?>
                        <form method="POST" action="<?= e($actionUrl) ?>" class="m-0"
                              data-confirm="¿Cancelar la aceptación de riesgo? El CVE vuelve a la cola.">
                            <?= Csrf::field() ?>
                            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                            <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                            <input type="hidden" name="action" value="cancelar_riesgo">
                            <button type="submit" class="btn btn-outline"><?= icon('cancel', 16) ?> Cancelar aceptación</button>
                        </form>
                    <?php endif; ?>

                    <?php if ($canIncident): ?>
                        <button type="button" onclick="openIncidentModal('nota')" class="btn btn-outline">
                            <?= icon('note_add', 16) ?> Registrar incidencia
                        </button>
                    <?php endif; ?>

                    <?php if ($canClose && $taskState !== 'verificacion'): ?>
                        <button type="button" onclick="openCloseModal()" class="btn btn-outline">
                            <?= icon('task_alt', 16) ?> Cerrar CVE
                        </button>
                    <?php endif; ?>

                    <?php if ($taskState === 'verificacion'): ?>
                        <button type="button" onclick="openFailureModal()" class="btn btn-outline">
                            <?= icon('report_problem', 16) ?> Verificación fallida
                        </button>
                    <?php endif; ?>

                    <?php if ($canRisk): ?>
                        <button type="button" onclick="openRiskModal()"
                                class="text-xs text-ink-muted hover:text-ink underline ml-auto">
                            Aceptar riesgo
                        </button>
                    <?php endif; ?>
                </div>
            </div>

            <div class="card p-5">
                <h3 class="text-sm font-semibold mb-3">Datos de gestión</h3>
                <form method="POST" action="<?= base_url('modules/remediation/tasks/save') ?>" class="space-y-3">
                    <?= Csrf::field() ?>
                    <input type="hidden" name="id" value="<?= (int)$task['id'] ?>">
                    <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                        <label class="block">
                            <span class="block text-xs font-medium text-ink-muted mb-1">Responsable</span>
                            <input type="text" name="owner" value="<?= e((string)($task['owner'] ?? '')) ?>" maxlength="120"
                                   class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-ink text-xs">
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-ink-muted mb-1">Fecha límite</span>
                            <input type="date" name="due_at" value="<?= e((string)($task['due_at'] ?? '')) ?>"
                                   class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-ink text-xs">
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-ink-muted mb-1">Excepción hasta</span>
                            <input type="date" name="exception_until" value="<?= e((string)($task['exception_until'] ?? '')) ?>"
                                   class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-ink text-xs">
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-ink-muted mb-1">Parche/KB</span>
                            <input type="text" name="patch_kb" value="<?= e((string)($task['patch_kb'] ?? '')) ?>" maxlength="120"
                                   class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-ink text-xs">
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-ink-muted mb-1">Versión corregida</span>
                            <input type="text" name="fixed_version" value="<?= e((string)($task['fixed_version'] ?? '')) ?>" maxlength="120"
                                   class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-ink text-xs">
                        </label>
                        <label class="block sm:col-span-2">
                            <span class="block text-xs font-medium text-ink-muted mb-1">Evidencia</span>
                            <input type="text" name="evidence" value="<?= e((string)($task['evidence'] ?? '')) ?>" maxlength="500"
                                   class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-surface text-ink text-xs">
                        </label>
                    </div>
                    <label class="block">
                        <span class="block text-xs font-medium text-ink-muted mb-1">Notas</span>
                        <textarea name="notes" rows="3"
                                  class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs"><?= e((string)($task['notes'] ?? '')) ?></textarea>
                    </label>
                    <div class="flex items-center justify-between gap-3 flex-wrap">
                        <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">Guardar cambios</button>
                        <button type="button" onclick="document.getElementById('delete-task-form').classList.toggle('hidden')"
                                class="text-xs text-danger hover:underline">Eliminar tarea</button>
                    </div>
                </form>
                <form method="POST" action="<?= base_url('modules/remediation/tasks/delete') ?>" id="delete-task-form"
                      class="hidden mt-3 pt-3 border-t border-line-subtle"
                      data-confirm="¿Eliminar esta tarea de remediación?" data-confirm-danger>
                    <?= Csrf::field() ?>
                    <input type="hidden" name="id" value="<?= (int)$task['id'] ?>">
                    <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                    <button type="submit" class="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs font-medium rounded-lg">Confirmar eliminación</button>
                </form>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Modales de acciones del ticket (F2) -->
<?php if ($selectedTask !== null): ?>
    <?php
    $actionUrl = base_url('modules/remediation/tasks/action');
    $todayIso = gmdate('Y-m-d');
    $maxRiskIso = gmdate('Y-m-d', strtotime('+90 days'));
    ?>
    <div id="plan-modal" class="hidden fixed inset-0 z-50 no-print">
        <div class="absolute inset-0 bg-black/40" onclick="closeActionModal('plan-modal')"></div>
        <div class="relative mx-auto mt-24 w-[calc(100%-2rem)] max-w-lg card shadow-xl p-5">
            <h3 class="text-sm font-semibold">Planificar el ticket</h3>
            <p class="text-xs text-ink-muted mt-1">Fija la ventana acordada. Después podrás iniciar el parcheo.</p>
            <form method="POST" action="<?= e($actionUrl) ?>" class="mt-4 space-y-3">
                <?= Csrf::field() ?>
                <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                <input type="hidden" name="action" value="planificar">
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Ventana de parcheo</span>
                    <input type="text" name="ventana_parcheo" maxlength="160" required placeholder="dom 22:00"
                           class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm">
                </label>
                <div class="flex justify-end gap-2">
                    <button type="button" onclick="closeActionModal('plan-modal')" class="btn btn-outline">Cancelar</button>
                    <button type="submit" class="btn">Planificar</button>
                </div>
            </form>
        </div>
    </div>

    <div id="incident-modal" class="hidden fixed inset-0 z-50 no-print">
        <div class="absolute inset-0 bg-black/40" onclick="closeActionModal('incident-modal')"></div>
        <div class="relative mx-auto mt-20 w-[calc(100%-2rem)] max-w-lg card shadow-xl p-5">
            <h3 class="text-sm font-semibold">Registrar incidencia</h3>
            <p class="text-xs text-ink-muted mt-1">Retraso y bloqueo desplazan la ETA; el bloqueo congela el ticket.</p>
            <form method="POST" action="<?= e($actionUrl) ?>" class="mt-4 space-y-3">
                <?= Csrf::field() ?>
                <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                <input type="hidden" name="action" value="incidencia">
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Tipo</span>
                    <select name="tipo" id="incident-type" onchange="toggleIncidentImpact()"
                            class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm">
                        <option value="nota">Nota</option>
                        <option value="retraso">Retraso</option>
                        <?php if ($taskState === 'en_curso'): ?>
                            <option value="bloqueo">Bloqueo</option>
                        <?php endif; ?>
                    </select>
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Motivo</span>
                    <textarea name="texto" rows="3" required placeholder="Ventana denegada por cambio en FW"
                              class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm"></textarea>
                </label>
                <label class="block" id="incident-impact-row">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Días de impacto</span>
                    <input type="number" name="impacto_dias" min="1" max="365" value="1"
                           class="w-28 px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm">
                </label>
                <div class="flex justify-end gap-2">
                    <button type="button" onclick="closeActionModal('incident-modal')" class="btn btn-outline">Cancelar</button>
                    <button type="submit" class="btn">Registrar</button>
                </div>
            </form>
        </div>
    </div>

    <div id="close-modal" class="hidden fixed inset-0 z-50 no-print">
        <div class="absolute inset-0 bg-black/40" onclick="closeActionModal('close-modal')"></div>
        <div class="relative mx-auto mt-20 w-[calc(100%-2rem)] max-w-lg card shadow-xl p-5">
            <h3 class="text-sm font-semibold">Cerrar CVE</h3>
            <p class="text-xs text-ink-muted mt-1">Sin evidencia no hay cierre: ID de cambio, KB aplicada o comprobante.</p>
            <form method="POST" action="<?= e($actionUrl) ?>" class="mt-4 space-y-3">
                <?= Csrf::field() ?>
                <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                <input type="hidden" name="action" value="cerrar">
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Evidencia de cierre</span>
                    <input type="text" name="evidencia" maxlength="500" required
                           value="<?= e((string)($task['evidence'] ?? '')) ?>"
                           placeholder="CHG-2026-0123 · KB5040442 aplicada"
                           class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm">
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Resolución</span>
                    <select name="resolucion" class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm">
                        <option value="patched">Parcheada</option>
                        <option value="mitigated">Mitigada</option>
                        <option value="false_positive">Falso positivo</option>
                    </select>
                </label>
                <div class="flex justify-end gap-2">
                    <button type="button" onclick="closeActionModal('close-modal')" class="btn btn-outline">Cancelar</button>
                    <button type="submit" class="btn">Cerrar CVE</button>
                </div>
            </form>
        </div>
    </div>

    <div id="risk-modal" class="hidden fixed inset-0 z-50 no-print">
        <div class="absolute inset-0 bg-black/40" onclick="closeActionModal('risk-modal')"></div>
        <div class="relative mx-auto mt-16 w-[calc(100%-2rem)] max-w-xl card shadow-xl p-5">
            <h3 class="text-sm font-semibold">Aceptar riesgo</h3>
            <p class="text-xs text-ink-muted mt-1">
                Justificación y caducidad (máximo 90 días). Si el CVSS es 9 o superior, hace falta un segundo aprobador.
            </p>
            <form method="POST" action="<?= e($actionUrl) ?>" class="mt-4 space-y-3">
                <?= Csrf::field() ?>
                <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                <input type="hidden" name="action" value="aceptar_riesgo">
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Justificación</span>
                    <textarea name="justificacion" rows="3" required
                              placeholder="Compensado con regla WAF; sin exposición directa"
                              class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm"></textarea>
                </label>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <label class="block">
                        <span class="block text-xs font-medium text-ink-muted mb-1">Caducidad</span>
                        <input type="date" name="caducidad" required
                               min="<?= e($todayIso) ?>" max="<?= e($maxRiskIso) ?>"
                               value="<?= e(gmdate('Y-m-d', strtotime('+30 days'))) ?>"
                               class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm">
                    </label>
                    <label class="block">
                        <span class="block text-xs font-medium text-ink-muted mb-1">Segundo aprobador (CVSS ≥ 9)</span>
                        <select name="segundo_aprobador"
                                class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm">
                            <option value="0">— No necesario —</option>
                            <?php foreach ($users as $user): ?>
                                <?php if ((int)$user['id'] === (int)Auth::id()) { continue; } ?>
                                <option value="<?= (int)$user['id'] ?>">
                                    <?= e((string)($user['display_name'] ?: $user['username'])) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                </div>
                <div class="flex justify-end gap-2">
                    <button type="button" onclick="closeActionModal('risk-modal')" class="btn btn-outline">Cancelar</button>
                    <button type="submit" class="btn">Aceptar riesgo</button>
                </div>
            </form>
        </div>
    </div>

    <div id="failure-modal" class="hidden fixed inset-0 z-50 no-print">
        <div class="absolute inset-0 bg-black/40" onclick="closeActionModal('failure-modal')"></div>
        <div class="relative mx-auto mt-24 w-[calc(100%-2rem)] max-w-lg card shadow-xl p-5">
            <h3 class="text-sm font-semibold">Verificación fallida</h3>
            <p class="text-xs text-ink-muted mt-1">El ticket vuelve a «En curso» y el motivo queda registrado.</p>
            <form method="POST" action="<?= e($actionUrl) ?>" class="mt-4 space-y-3">
                <?= Csrf::field() ?>
                <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                <input type="hidden" name="task_id" value="<?= (int)$task['id'] ?>">
                <input type="hidden" name="action" value="verificacion_fallida">
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Motivo</span>
                    <textarea name="motivo" rows="3" required
                              class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm"></textarea>
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Días de impacto (opcional)</span>
                    <input type="number" name="impacto_dias" min="0" max="365" value="0"
                           class="w-28 px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm">
                </label>
                <div class="flex justify-end gap-2">
                    <button type="button" onclick="closeActionModal('failure-modal')" class="btn btn-outline">Cancelar</button>
                    <button type="submit" class="btn">Registrar fallo</button>
                </div>
            </form>
        </div>
    </div>
<?php endif; ?>

<!-- Modal nueva tarea -->
<div id="task-modal" class="hidden fixed inset-0 z-50 no-print">
    <div class="absolute inset-0 bg-black/40" onclick="closeTaskModal()"></div>
    <div class="relative mx-auto mt-16 w-[calc(100%-2rem)] max-w-2xl card shadow-xl p-5">
        <div class="flex items-start justify-between gap-3">
            <div>
                <h3 class="text-sm font-semibold">Nueva tarea de remediación</h3>
                <p class="text-xs text-ink-muted mt-1">El CVE se busca en el catálogo; si no está, se descarga de NVD.</p>
            </div>
            <button type="button" onclick="closeTaskModal()" class="text-xs text-ink-soft hover:text-gray-600">Cerrar</button>
        </div>

        <form method="POST" action="<?= base_url('modules/remediation/tasks/save') ?>" class="mt-4 space-y-3">
            <?= Csrf::field() ?>
            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
            <label class="block relative">
                <span class="block text-xs font-medium text-ink-muted mb-1">CVE</span>
                <input type="text" name="cve_id" id="new-cve" required autocomplete="off" placeholder="CVE-2024-38063"
                       oninput="searchCve(this.value)"
                       class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm font-mono">
                <div id="cve-results" class="hidden absolute left-0 right-0 mt-1 z-50 max-h-56 overflow-y-auto bg-surface border border-line dark:border-gray-600 rounded-lg shadow-lg"></div>
            </label>
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Responsable</span>
                    <input type="text" name="owner" maxlength="120" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Fecha límite</span>
                    <input type="date" name="due_at" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Parche/KB</span>
                    <input type="text" name="patch_kb" maxlength="120" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Versión corregida</span>
                    <input type="text" name="fixed_version" maxlength="120" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                </label>
                <label class="block sm:col-span-2">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Equipos afectados (uno por línea)</span>
                    <textarea name="machines" rows="3" placeholder="WEB-01&#10;PC-CONTABILIDAD"
                              class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs"></textarea>
                </label>
            </div>
            <label class="block">
                <span class="block text-xs font-medium text-ink-muted mb-1">Notas</span>
                <textarea name="notes" rows="2" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs"></textarea>
            </label>
            <div class="flex items-center justify-end gap-2 pt-1">
                <button type="button" onclick="closeTaskModal()" class="px-3 py-2 border border-line-strong text-xs font-medium rounded-lg">Cancelar</button>
                <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">Crear tarea</button>
            </div>
        </form>
    </div>
</div>

<?php if (($org['kind'] ?? '') === 'tenant'): ?>
<!-- Modal importar -->
<div id="import-modal" class="hidden fixed inset-0 z-50 no-print">
    <div class="absolute inset-0 bg-black/40" onclick="closeImportModal()"></div>
    <div class="relative mx-auto mt-24 w-[calc(100%-2rem)] max-w-lg card shadow-xl p-5">
        <div class="flex items-start justify-between gap-3">
            <div>
                <h3 class="text-sm font-semibold">Importar desde Defender</h3>
                <p class="text-xs text-ink-muted mt-1">Crea tareas para los CVEs expuestos en el tenant «<?= e((string)($org['tenant_name'] ?? '')) ?>».</p>
            </div>
            <button type="button" onclick="closeImportModal()" class="text-xs text-ink-soft hover:text-gray-600">Cerrar</button>
        </div>
        <form method="POST" action="<?= base_url('modules/remediation/tasks/import') ?>" class="mt-4 space-y-3">
            <?= Csrf::field() ?>
            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
            <div class="grid grid-cols-2 gap-3">
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Severidad</span>
                    <select name="severity" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                        <option value="">Todas</option>
                        <option value="Critical">Crítica</option>
                        <option value="High">Alta</option>
                        <option value="Medium">Media</option>
                        <option value="Low">Baja</option>
                    </select>
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Máximo de tareas</span>
                    <input type="number" name="limit" min="1" max="200" value="50"
                           class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-ink-muted mb-1">Equipos mínimos</span>
                    <input type="number" name="min_machines" min="0" value="1"
                           class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                </label>
                <label class="flex items-center gap-2 text-xs text-ink-muted mt-5">
                    <input type="checkbox" name="exploited" value="1" class="rounded border-line-strong text-brand-500">
                    Solo con exploit
                </label>
            </div>
            <div class="flex items-center justify-end gap-2 pt-1">
                <button type="button" onclick="closeImportModal()" class="px-3 py-2 border border-line-strong text-xs font-medium rounded-lg">Cancelar</button>
                <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">Importar</button>
            </div>
        </form>
    </div>
</div>
<?php endif; ?>

<script>
var REMEDIATION_URL = <?= json_encode($modUrl) ?>;

function openTaskModal() {
    document.getElementById('task-modal').classList.remove('hidden');
    document.getElementById('new-cve').focus();
}
function closeTaskModal() {
    document.getElementById('task-modal').classList.add('hidden');
    document.getElementById('cve-results').classList.add('hidden');
}

function openActionModal(id) {
    var modal = document.getElementById(id);
    if (modal) modal.classList.remove('hidden');
}
function closeActionModal(id) {
    var modal = document.getElementById(id);
    if (modal) modal.classList.add('hidden');
}
function openPlanModal() { openActionModal('plan-modal'); }
function openCloseModal() { openActionModal('close-modal'); }
function openRiskModal() { openActionModal('risk-modal'); }
function openFailureModal() { openActionModal('failure-modal'); }
function openIncidentModal(type) {
    var select = document.getElementById('incident-type');
    if (select && type) { select.value = type; }
    toggleIncidentImpact();
    openActionModal('incident-modal');
}
function toggleIncidentImpact() {
    var select = document.getElementById('incident-type');
    var row = document.getElementById('incident-impact-row');
    if (!select || !row) return;
    row.style.display = select.value === 'nota' ? 'none' : '';
}
<?php if (($org['kind'] ?? '') === 'tenant'): ?>
function openImportModal() { document.getElementById('import-modal').classList.remove('hidden'); }
function closeImportModal() { document.getElementById('import-modal').classList.add('hidden'); }
<?php else: ?>
function openImportModal() {}
function closeImportModal() {}
<?php endif; ?>

var cveTimer = null;
function escapeHtml(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function searchCve(query) {
    var box = document.getElementById('cve-results');
    if (!box) return;
    clearTimeout(cveTimer);
    if (query.trim().length < 3) {
        box.classList.add('hidden');
        box.innerHTML = '';
        return;
    }
    cveTimer = setTimeout(function () {
        fetch(REMEDIATION_URL + '/cve-search?q=' + encodeURIComponent(query.trim()), {
            headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' },
            credentials: 'same-origin'
        }).then(function (r) { return r.json(); }).then(function (res) {
            if (!res || !res.success || !res.results || !res.results.length) {
                box.classList.add('hidden');
                return;
            }
            box.innerHTML = res.results.map(function (c) {
                return '<button type="button" class="block w-full text-left px-3 py-2 hover:bg-gray-50 dark:hover:bg-gray-700 border-b border-line-subtle" data-cve="' + escapeHtml(c.cve_id) + '">'
                    + '<span class="font-mono text-xs font-semibold">' + escapeHtml(c.cve_id) + '</span>'
                    + '<span class="ml-2 text-[10px] uppercase text-ink-muted">' + escapeHtml(c.severity || '') + '</span>'
                    + '<span class="block text-[11px] text-ink-muted truncate">' + escapeHtml(c.summary || '') + '</span>'
                    + '</button>';
            }).join('');
            box.classList.remove('hidden');
            box.querySelectorAll('button[data-cve]').forEach(function (btn) {
                btn.onclick = function () {
                    document.getElementById('new-cve').value = btn.getAttribute('data-cve');
                    box.classList.add('hidden');
                };
            });
        }).catch(function () { box.classList.add('hidden'); });
    }, 250);
}

document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
        closeTaskModal();
        closeImportModal();
        ['plan-modal', 'incident-modal', 'close-modal', 'risk-modal', 'failure-modal'].forEach(closeActionModal);
    }
});
</script>

<?php
$newCve = strtoupper(trim((string)($_GET['new_cve'] ?? '')));
if (preg_match('/^CVE-\d{4}-\d{4,7}$/', $newCve)):
?>
<script>
document.addEventListener('DOMContentLoaded', function () {
    var input = document.getElementById('new-cve');
    if (input) {
        input.value = <?= json_encode($newCve) ?>;
        openTaskModal();
    }
});
</script>
<?php endif; ?>
