<?php
/**
 * Vista: bandeja de remediación.
 * Variables compartidas: $org, $selectedOrgId, $tasks, $filters, $selectedTask,
 * $cveData, $statusLabels, $statusClasses, $severityLabels, $severityClasses.
 */

$modUrl = base_url('modules/remediation');
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
            <span class="block text-[10px] font-semibold uppercase tracking-wide text-gray-400 mb-1">Estado</span>
            <select name="status" class="px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                <option value="">Todos</option>
                <?php foreach ($statusLabels as $key => $label): ?>
                    <option value="<?= e($key) ?>" <?= ($filters['status'] ?? '') === $key ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <label class="block">
            <span class="block text-[10px] font-semibold uppercase tracking-wide text-gray-400 mb-1">Severidad</span>
            <select name="severity" class="px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                <option value="">Todas</option>
                <?php foreach (['Critical', 'High', 'Medium', 'Low'] as $sev): ?>
                    <option value="<?= e($sev) ?>" <?= ($filters['severity'] ?? '') === $sev ? 'selected' : '' ?>><?= e($severityLabels[$sev]) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <label class="block">
            <span class="block text-[10px] font-semibold uppercase tracking-wide text-gray-400 mb-1">Buscar</span>
            <input type="search" name="q" value="<?= e((string)($filters['q'] ?? '')) ?>" placeholder="CVE, título, responsable"
                   class="w-48 px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
        </label>
        <label class="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-300 mt-5">
            <input type="checkbox" name="overdue" value="1" <?= !empty($filters['overdue']) ? 'checked' : '' ?> class="rounded border-gray-300 text-brand-500">
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
                    class="px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">
                Importar desde Defender
            </button>
        <?php endif; ?>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h2 class="text-sm font-semibold">Tareas</h2>
            <span class="text-[10px] text-gray-400"><?= count($tasks) ?></span>
        </div>
        <?php if ($tasks === []): ?>
            <p class="p-6 text-xs text-gray-500 text-center">No hay tareas con esos filtros.</p>
        <?php else: ?>
            <div class="max-h-[65vh] overflow-y-auto divide-y divide-gray-100 dark:divide-gray-800">
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
                                <span class="px-1.5 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 text-[10px] font-semibold">KEV</span>
                            <?php endif; ?>
                            <span class="ml-auto px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $statusClasses[$task['status']] ?? 'bg-gray-100 text-gray-600' ?>">
                                <?= e($statusLabels[$task['status']] ?? $task['status']) ?>
                            </span>
                        </div>
                        <p class="text-xs text-gray-500 truncate mt-1"><?= e((string)($task['title'] ?? '')) ?></p>
                        <div class="flex items-center gap-2 text-[10px] text-gray-400 mt-1 flex-wrap">
                            <?php if (!empty($task['due_at'])): ?>
                                <span class="<?= $overdue ? 'text-red-500 font-semibold' : '' ?>">Vence <?= e(format_date((string)$task['due_at'], 'd/m/Y')) ?></span>
                            <?php endif; ?>
                            <?php if (!empty($task['owner'])): ?><span>· <?= e((string)$task['owner']) ?></span><?php endif; ?>
                            <span>· <?= (int)$task['machine_count'] ?> equipos</span>
                        </div>
                    </a>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="lg:col-span-2">
        <?php if ($selectedTask === null): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-10 text-center">
                <p class="text-sm font-semibold">Ninguna tarea seleccionada</p>
                <p class="text-xs text-gray-500 mt-1">Elige una tarea de la lista o crea una nueva.</p>
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
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-4">
                <div class="flex items-start justify-between gap-3 flex-wrap">
                    <div class="min-w-0">
                        <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Tarea de remediación</p>
                        <h2 class="text-xl font-bold font-mono mt-0.5"><?= e((string)$task['cve_id']) ?></h2>
                        <p class="text-xs text-gray-500 mt-1"><?= e((string)($task['title'] ?? '')) ?></p>
                    </div>
                    <div class="flex items-center gap-2 flex-wrap">
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

                <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 text-xs">
                    <div><p class="text-gray-400">Responsable</p><p class="font-medium mt-0.5"><?= e((string)($task['owner'] ?? '—')) ?></p></div>
                    <div>
                        <p class="text-gray-400">Fecha límite</p>
                        <p class="font-medium mt-0.5 <?= $overdue ? 'text-red-500' : '' ?>">
                            <?= !empty($task['due_at']) ? e(format_date((string)$task['due_at'], 'd/m/Y')) : '—' ?>
                        </p>
                    </div>
                    <div><p class="text-gray-400">Equipos</p><p class="font-medium mt-0.5"><?= (int)$task['machine_count'] ?></p></div>
                    <div><p class="text-gray-400">Origen</p><p class="font-medium mt-0.5"><?= $task['source'] === 'defender' ? 'Defender' : 'Manual' ?></p></div>
                    <div><p class="text-gray-400">Parche/KB</p><p class="font-medium mt-0.5"><?= e((string)($task['patch_kb'] ?? '—')) ?></p></div>
                    <div><p class="text-gray-400">Versión corregida</p><p class="font-medium mt-0.5"><?= e((string)($task['fixed_version'] ?? '—')) ?></p></div>
                    <div><p class="text-gray-400">Creada</p><p class="font-medium mt-0.5"><?= e(format_date((string)$task['created_at'], 'd/m/Y')) ?></p></div>
                    <div><p class="text-gray-400">Resuelta</p><p class="font-medium mt-0.5"><?= !empty($task['resolved_at']) ? e(format_date((string)$task['resolved_at'], 'd/m/Y')) : '—' ?></p></div>
                </div>
            </div>

            <?php if ($catalog !== null): ?>
                <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-4">
                    <h3 class="text-sm font-semibold mb-3">Datos del CVE</h3>
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                        <div><p class="text-gray-400">CVSS</p><p class="text-base font-bold"><?= $catalog['cvss_v3_score'] !== null ? e(number_format((float)$catalog['cvss_v3_score'], 1, '.', '')) : '—' ?></p></div>
                        <div><p class="text-gray-400">EPSS</p><p class="text-base font-bold"><?= $epss !== null && $epss['epss'] !== null ? e(number_format((float)$epss['epss'] * 100, 2, ',', '')) . ' %' : '—' ?></p></div>
                        <div><p class="text-gray-400">CISA KEV</p><p class="text-base font-bold"><?= $kev !== null ? 'Sí' : 'No' ?></p></div>
                        <div><p class="text-gray-400">Publicado</p><p class="text-base font-bold"><?= e(format_date((string)($catalog['published_at'] ?? ''), 'd/m/Y')) ?></p></div>
                    </div>
                    <p class="text-[11px] font-mono text-gray-500 mt-3 break-all"><?= e((string)($catalog['cvss_v3_vector'] ?? '')) ?></p>
                    <p class="text-xs text-gray-600 dark:text-gray-300 mt-3 leading-relaxed"><?= e(CveReportAi::cleanTranslatedText((string)($catalog['description_es'] ?? '')) ?: (string)($catalog['description'] ?? '')) ?></p>
                    <?php if ($kev !== null && !empty($kev['required_action'])): ?>
                        <div class="mt-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-xs text-red-700 dark:text-red-300">
                            <strong>Acción CISA:</strong> <?= e(CveReportAi::cleanTranslatedText((string)($kev['required_action_es'] ?? '')) ?: (string)$kev['required_action']) ?>
                        </div>
                    <?php endif; ?>
                    <?php if (is_array($references) && $references !== []): ?>
                        <div class="mt-3">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Referencias</p>
                            <ul class="mt-1 space-y-1">
                                <?php foreach (array_slice($references, 0, 8) as $ref): ?>
                                    <?php $url = is_array($ref) ? (string)($ref['url'] ?? '') : (string)$ref; ?>
                                    <?php if ($url !== ''): ?>
                                        <li><a href="<?= e($url) ?>" target="_blank" rel="noopener noreferrer" class="text-xs text-brand-600 dark:text-brand-400 hover:underline break-all"><?= e($url) ?></a></li>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <?php if ($taskMachines !== []): ?>
                <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-4">
                    <h3 class="text-sm font-semibold mb-3">Equipos afectados</h3>
                    <div class="overflow-x-auto">
                        <table class="w-full text-xs">
                            <thead>
                                <tr class="text-[10px] uppercase text-gray-400 border-b border-gray-200 dark:border-gray-700">
                                    <th class="text-left py-1.5 pr-3">Equipo</th>
                                    <th class="text-left py-1.5 pr-3">SO</th>
                                    <th class="text-left py-1.5">Exposición</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
                                <?php foreach (array_slice($taskMachines, 0, 50) as $machine): ?>
                                    <tr>
                                        <td class="py-1.5 pr-3 font-medium"><?= e((string)($machine['name'] ?? '—')) ?></td>
                                        <td class="py-1.5 pr-3 text-gray-600 dark:text-gray-300"><?= e((string)($machine['os'] ?? '—')) ?></td>
                                        <td class="py-1.5 text-gray-600 dark:text-gray-300"><?= e((string)($machine['exposure'] ?? '—')) ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php if ((int)$task['machine_count'] > count($taskMachines)): ?>
                        <p class="text-[11px] text-gray-400 mt-1">… y <?= (int)$task['machine_count'] - count($taskMachines) ?> equipos más.</p>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <?php if (!empty($task['plan'])): ?>
                <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-4">
                    <h3 class="text-sm font-semibold mb-2">Plan guardado</h3>
                    <pre class="text-xs whitespace-pre-wrap text-gray-600 dark:text-gray-300 font-sans"><?= e((string)$task['plan']) ?></pre>
                </div>
            <?php endif; ?>

            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <h3 class="text-sm font-semibold mb-3">Actualizar tarea</h3>
                <form method="POST" action="<?= base_url('modules/remediation/tasks/save') ?>" class="space-y-3">
                    <?= Csrf::field() ?>
                    <input type="hidden" name="id" value="<?= (int)$task['id'] ?>">
                    <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Estado</span>
                            <select name="status" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                                <?php foreach ($statusLabels as $key => $label): ?>
                                    <option value="<?= e($key) ?>" <?= $task['status'] === $key ? 'selected' : '' ?>><?= e($label) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Responsable</span>
                            <input type="text" name="owner" value="<?= e((string)($task['owner'] ?? '')) ?>" maxlength="120"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Fecha límite</span>
                            <input type="date" name="due_at" value="<?= e((string)($task['due_at'] ?? '')) ?>"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Excepción hasta</span>
                            <input type="date" name="exception_until" value="<?= e((string)($task['exception_until'] ?? '')) ?>"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Parche/KB</span>
                            <input type="text" name="patch_kb" value="<?= e((string)($task['patch_kb'] ?? '')) ?>" maxlength="120"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                        </label>
                        <label class="block">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Versión corregida</span>
                            <input type="text" name="fixed_version" value="<?= e((string)($task['fixed_version'] ?? '')) ?>" maxlength="120"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                        </label>
                        <label class="block sm:col-span-2">
                            <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Evidencia</span>
                            <input type="text" name="evidence" value="<?= e((string)($task['evidence'] ?? '')) ?>" maxlength="500"
                                   class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                        </label>
                    </div>
                    <label class="block">
                        <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Notas</span>
                        <textarea name="notes" rows="3"
                                  class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs"><?= e((string)($task['notes'] ?? '')) ?></textarea>
                    </label>
                    <div class="flex items-center justify-between gap-3 flex-wrap">
                        <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">Guardar cambios</button>
                        <button type="button" onclick="document.getElementById('delete-task-form').classList.toggle('hidden')"
                                class="text-xs text-red-600 dark:text-red-400 hover:underline">Eliminar tarea</button>
                    </div>
                </form>
                <form method="POST" action="<?= base_url('modules/remediation/tasks/delete') ?>" id="delete-task-form"
                      class="hidden mt-3 pt-3 border-t border-gray-100 dark:border-gray-700"
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

<!-- Modal nueva tarea -->
<div id="task-modal" class="hidden fixed inset-0 z-50 no-print">
    <div class="absolute inset-0 bg-black/40" onclick="closeTaskModal()"></div>
    <div class="relative mx-auto mt-16 w-[calc(100%-2rem)] max-w-2xl bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 shadow-xl p-5">
        <div class="flex items-start justify-between gap-3">
            <div>
                <h3 class="text-sm font-semibold">Nueva tarea de remediación</h3>
                <p class="text-xs text-gray-500 mt-1">El CVE se busca en el catálogo; si no está, se descarga de NVD.</p>
            </div>
            <button type="button" onclick="closeTaskModal()" class="text-xs text-gray-400 hover:text-gray-600">Cerrar</button>
        </div>

        <form method="POST" action="<?= base_url('modules/remediation/tasks/save') ?>" class="mt-4 space-y-3">
            <?= Csrf::field() ?>
            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
            <label class="block relative">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">CVE</span>
                <input type="text" name="cve_id" id="new-cve" required autocomplete="off" placeholder="CVE-2024-38063"
                       oninput="searchCve(this.value)"
                       class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm font-mono">
                <div id="cve-results" class="hidden absolute left-0 right-0 mt-1 z-50 max-h-56 overflow-y-auto bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded-lg shadow-lg"></div>
            </label>
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <label class="block">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Responsable</span>
                    <input type="text" name="owner" maxlength="120" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Fecha límite</span>
                    <input type="date" name="due_at" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Parche/KB</span>
                    <input type="text" name="patch_kb" maxlength="120" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Versión corregida</span>
                    <input type="text" name="fixed_version" maxlength="120" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                </label>
                <label class="block sm:col-span-2">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Equipos afectados (uno por línea)</span>
                    <textarea name="machines" rows="3" placeholder="WEB-01&#10;PC-CONTABILIDAD"
                              class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs"></textarea>
                </label>
            </div>
            <label class="block">
                <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Notas</span>
                <textarea name="notes" rows="2" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs"></textarea>
            </label>
            <div class="flex items-center justify-end gap-2 pt-1">
                <button type="button" onclick="closeTaskModal()" class="px-3 py-2 border border-gray-300 dark:border-gray-600 text-xs font-medium rounded-lg">Cancelar</button>
                <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg">Crear tarea</button>
            </div>
        </form>
    </div>
</div>

<?php if (($org['kind'] ?? '') === 'tenant'): ?>
<!-- Modal importar -->
<div id="import-modal" class="hidden fixed inset-0 z-50 no-print">
    <div class="absolute inset-0 bg-black/40" onclick="closeImportModal()"></div>
    <div class="relative mx-auto mt-24 w-[calc(100%-2rem)] max-w-lg bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 shadow-xl p-5">
        <div class="flex items-start justify-between gap-3">
            <div>
                <h3 class="text-sm font-semibold">Importar desde Defender</h3>
                <p class="text-xs text-gray-500 mt-1">Crea tareas para los CVEs expuestos en el tenant «<?= e((string)($org['tenant_name'] ?? '')) ?>».</p>
            </div>
            <button type="button" onclick="closeImportModal()" class="text-xs text-gray-400 hover:text-gray-600">Cerrar</button>
        </div>
        <form method="POST" action="<?= base_url('modules/remediation/tasks/import') ?>" class="mt-4 space-y-3">
            <?= Csrf::field() ?>
            <input type="hidden" name="org_id" value="<?= (int)$selectedOrgId ?>">
            <div class="grid grid-cols-2 gap-3">
                <label class="block">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Severidad</span>
                    <select name="severity" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                        <option value="">Todas</option>
                        <option value="Critical">Crítica</option>
                        <option value="High">Alta</option>
                        <option value="Medium">Media</option>
                        <option value="Low">Baja</option>
                    </select>
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Máximo de tareas</span>
                    <input type="number" name="limit" min="1" max="200" value="50"
                           class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                </label>
                <label class="block">
                    <span class="block text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">Equipos mínimos</span>
                    <input type="number" name="min_machines" min="0" value="1"
                           class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-xs">
                </label>
                <label class="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 mt-5">
                    <input type="checkbox" name="exploited" value="1" class="rounded border-gray-300 text-brand-500">
                    Solo con exploit
                </label>
            </div>
            <div class="flex items-center justify-end gap-2 pt-1">
                <button type="button" onclick="closeImportModal()" class="px-3 py-2 border border-gray-300 dark:border-gray-600 text-xs font-medium rounded-lg">Cancelar</button>
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
                return '<button type="button" class="block w-full text-left px-3 py-2 hover:bg-gray-50 dark:hover:bg-gray-700 border-b border-gray-100 dark:border-gray-700" data-cve="' + escapeHtml(c.cve_id) + '">'
                    + '<span class="font-mono text-xs font-semibold">' + escapeHtml(c.cve_id) + '</span>'
                    + '<span class="ml-2 text-[10px] uppercase text-gray-500">' + escapeHtml(c.severity || '') + '</span>'
                    + '<span class="block text-[11px] text-gray-500 truncate">' + escapeHtml(c.summary || '') + '</span>'
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
