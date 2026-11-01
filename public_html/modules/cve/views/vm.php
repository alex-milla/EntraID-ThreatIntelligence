<?php
/**
 * Vista: CVE — Seguimiento de vulnerabilidades (v0.3.0).
 *
 * Variables: $isAdmin, $companyGroups, $vmCases, $vmKpis, $vmCase,
 *            $vmEvents, $vmEvidence, $vmFilters, $vmLastImport.
 *
 * El origen es la importación MANUAL del CSV de Defender TVM. El export es
 * agregado por CVE: no identifica equipos, así que el ámbito es empresa + CVE.
 */

$vmCases = is_array($vmCases ?? null) ? $vmCases : [];
$vmKpis = is_array($vmKpis ?? null) ? $vmKpis : [];
$vmCase = is_array($vmCase ?? null) ? $vmCase : null;
$vmEvents = is_array($vmEvents ?? null) ? $vmEvents : [];
$vmEvidence = is_array($vmEvidence ?? null) ? $vmEvidence : [];
$vmFilters = array_merge(
    ['company' => 0, 'status' => '', 'priority' => '', 'due' => '', 'q' => '', 'sort' => 'due'],
    is_array($vmFilters ?? null) ? $vmFilters : []
);
$vmLastImport = is_array($vmLastImport ?? null) ? $vmLastImport : null;
$companyGroups = is_array($companyGroups ?? null) ? $companyGroups : [];

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
$deadlineLabels = [
    'closed'            => 'Cerrado',
    'exception_expired' => 'Excepción caducada',
    'expired'           => 'Vencido',
    'due_soon'          => 'Próximo',
    'ok'                => 'En plazo',
    'none'              => 'Sin fecha',
];
$deadlineClasses = [
    'closed'            => 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
    'exception_expired' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'expired'           => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'due_soon'          => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    'ok'                => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'none'              => 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
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

$today = date('Y-m-d');
$selectedCompany = (int)$vmFilters['company'];
$companyName = '';
foreach ($companyGroups as $companyRow) {
    if ((int)$companyRow['id'] === $selectedCompany) {
        $companyName = (string)$companyRow['name'];
    }
}
$reportUrl = base_url('modules/cve/vm/report?company=' . $selectedCompany . '&days=30');
$importUrl = base_url('modules/cve?tab=import' . ($selectedCompany > 0 ? '&company=' . $selectedCompany : ''));
?>

<div class="no-print mb-4 flex items-end justify-between gap-3 flex-wrap">
    <div>
        <h2 class="text-lg font-bold">Seguimiento de vulnerabilidades</h2>
        <p class="text-xs text-ink-soft">
            Casos creados a partir de las importaciones manuales del CSV de Defender TVM.
            El export no identifica equipos: el seguimiento es por empresa + CVE.
        </p>
    </div>
    <div class="flex items-center gap-2">
        <a href="<?= $importUrl ?>"
           class="inline-flex items-center gap-2 px-3 py-2 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
            <i class="material-icons icon-14" aria-hidden="true">upload_file</i>
            Importar CSV
        </a>
        <a href="<?= $reportUrl ?>"
           class="inline-flex items-center gap-2 px-3 py-2 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
            <i class="material-icons icon-14" aria-hidden="true">summarize</i>
            Informe ejecutivo
        </a>
    </div>
</div>

<div class="mb-4 px-4 py-3 rounded-lg text-xs text-amber-700 bg-amber-50 dark:bg-amber-900/20 dark:text-amber-300 flex items-start gap-2">
    <i class="material-icons icon-16 shrink-0" aria-hidden="true">info</i>
    <span>
        Los datos proceden de importaciones manuales y pueden estar incompletos o desactualizados.
        Que un CVE no aparezca en una importación posterior <strong>no significa que esté corregido</strong>:
        un caso solo pasa a «Corregida y verificada» con verificación manual registrada.
    </span>
</div>

<?php if ($companyGroups === []): ?>
    <div class="card p-5">
        <p class="text-sm text-ink-muted">
            Todavía no hay empresas. Crea una en <strong>Mis CVE → Empresas</strong> e importa su CSV de Defender TVM.
        </p>
    </div>
<?php else: ?>

<!-- ============================================================
     Filtros de la cola
     ============================================================ -->
<form method="get" action="<?= base_url('modules/cve') ?>" class="card p-4 mb-4 no-print">
    <input type="hidden" name="tab" value="vm">
    <div class="grid grid-cols-2 md:grid-cols-6 gap-3 items-end">
        <div class="col-span-2 md:col-span-1">
            <label for="vm-company" class="block text-[11px] font-medium text-ink-muted mb-1">Empresa</label>
            <select id="vm-company" name="company"
                    class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="0">Todas</option>
                <?php foreach ($companyGroups as $companyRow): ?>
                    <option value="<?= (int)$companyRow['id'] ?>" <?= $selectedCompany === (int)$companyRow['id'] ? 'selected' : '' ?>>
                        <?= e((string)$companyRow['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label for="vm-status" class="block text-[11px] font-medium text-ink-muted mb-1">Estado</label>
            <select id="vm-status" name="vm_status"
                    class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="">Todos</option>
                <?php foreach ($statusLabels as $key => $label): ?>
                    <option value="<?= e($key) ?>" <?= $vmFilters['status'] === $key ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label for="vm-priority" class="block text-[11px] font-medium text-ink-muted mb-1">Prioridad</label>
            <select id="vm-priority" name="vm_priority"
                    class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="">Todas</option>
                <?php foreach ($priorityLabels as $key => $label): ?>
                    <option value="<?= e($key) ?>" <?= $vmFilters['priority'] === $key ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label for="vm-due" class="block text-[11px] font-medium text-ink-muted mb-1">Vencimiento</label>
            <select id="vm-due" name="vm_due"
                    class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="">Todos</option>
                <option value="overdue" <?= $vmFilters['due'] === 'overdue' ? 'selected' : '' ?>>Vencidos</option>
                <option value="due_soon" <?= $vmFilters['due'] === 'due_soon' ? 'selected' : '' ?>>Próximos a vencer</option>
                <option value="exception" <?= $vmFilters['due'] === 'exception' ? 'selected' : '' ?>>Excepciones caducadas</option>
            </select>
        </div>
        <div>
            <label for="vm-q" class="block text-[11px] font-medium text-ink-muted mb-1">Buscar</label>
            <input id="vm-q" type="search" name="vm_q" value="<?= e((string)$vmFilters['q']) ?>"
                   placeholder="CVE, producto o responsable"
                   class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <div class="flex items-center gap-2">
            <div class="flex-1">
                <label for="vm-sort" class="block text-[11px] font-medium text-ink-muted mb-1">Orden</label>
                <select id="vm-sort" name="vm_sort"
                        class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="due" <?= $vmFilters['sort'] === 'due' ? 'selected' : '' ?>>Vencimiento</option>
                    <option value="priority" <?= $vmFilters['sort'] === 'priority' ? 'selected' : '' ?>>Prioridad</option>
                    <option value="last_seen" <?= $vmFilters['sort'] === 'last_seen' ? 'selected' : '' ?>>Última observación</option>
                    <option value="created" <?= $vmFilters['sort'] === 'created' ? 'selected' : '' ?>>Alta</option>
                </select>
            </div>
            <button type="submit"
                    class="px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition-colors">
                Filtrar
            </button>
        </div>
    </div>
</form>

<!-- ============================================================
     Dashboard
     ============================================================ -->
<div class="grid grid-cols-2 md:grid-cols-6 gap-2 mb-4">
    <?php
    $cards = [
        ['label' => 'Casos con seguimiento', 'value' => (int)($vmKpis['total'] ?? 0), 'hint' => 'Creación manual desde importaciones'],
        ['label' => 'Abiertos', 'value' => (int)($vmKpis['open'] ?? 0), 'hint' => 'Sin cierre verificado'],
        ['label' => 'Vencidos', 'value' => (int)($vmKpis['overdue'] ?? 0), 'hint' => 'Fecha objetivo superada'],
        ['label' => 'Próximos a vencer', 'value' => (int)($vmKpis['due_soon'] ?? 0), 'hint' => 'Siete días o menos'],
        ['label' => 'Corregidos y verificados', 'value' => (int)($vmKpis['resolved_verified'] ?? 0), 'hint' => 'Con evidencia manual'],
        ['label' => 'Excepciones caducadas', 'value' => (int)($vmKpis['exception_expired'] ?? 0), 'hint' => 'Riesgo aceptado vencido'],
    ];
    ?>
    <?php foreach ($cards as $card): ?>
        <div class="card p-3">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft"><?= e($card['label']) ?></p>
            <p class="text-xl font-semibold mt-1"><?= (int)$card['value'] ?></p>
            <p class="text-[10px] text-ink-soft mt-0.5"><?= e($card['hint']) ?></p>
        </div>
    <?php endforeach; ?>
</div>

<div class="grid grid-cols-1 md:grid-cols-3 gap-3 mb-5">
    <div class="card p-4">
        <h3 class="text-xs font-semibold mb-2">Abiertos por prioridad</h3>
        <div class="space-y-1.5">
            <?php foreach ($priorityLabels as $key => $label): ?>
                <div class="flex items-center justify-between text-xs">
                    <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $priorityClasses[$key] ?? '' ?>"><?= e($label) ?></span>
                    <span class="font-mono"><?= (int)($vmKpis['by_priority'][$key] ?? 0) ?></span>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <div class="card p-4">
        <h3 class="text-xs font-semibold mb-2">Casos por estado</h3>
        <div class="space-y-1 max-h-40 overflow-y-auto pr-1">
            <?php foreach ($statusLabels as $key => $label): ?>
                <div class="flex items-center justify-between text-[11px]">
                    <span><?= e($label) ?></span>
                    <span class="font-mono"><?= (int)($vmKpis['by_status'][$key] ?? 0) ?></span>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <div class="card p-4">
        <h3 class="text-xs font-semibold mb-2">Última importación</h3>
        <?php if ($vmLastImport === null): ?>
            <p class="text-xs text-ink-soft">Sin importaciones registradas.</p>
        <?php else: ?>
            <p class="text-xs text-ink"><?= e((string)($vmLastImport['company_name'] ?? '—')) ?></p>
            <p class="text-[11px] text-ink-soft mt-0.5"><?= e($fmtDateTime((string)($vmLastImport['created_at'] ?? ''))) ?></p>
            <p class="text-[11px] text-ink-soft">
                <?= (int)($vmLastImport['rows_imported'] ?? 0) ?> CVEs · estado
                <span class="font-mono"><?= e((string)($vmLastImport['status'] ?? '—')) ?></span>
            </p>
            <a href="<?= base_url('modules/cve?tab=import&import=' . (int)$vmLastImport['id']) ?>"
               class="inline-flex items-center gap-1 mt-2 text-[11px] text-brand-600 dark:text-brand-300 hover:underline">
                Ver importación <i class="material-icons icon-12" aria-hidden="true">arrow_forward</i>
            </a>
        <?php endif; ?>
        <p class="text-[10px] text-ink-soft mt-3 border-t border-line pt-2">
            Los indicadores se calculan sobre los casos importados con seguimiento, no sobre todo el parque.
        </p>
    </div>
</div>

<!-- ============================================================
     Cola de trabajo
     ============================================================ -->
<div class="card overflow-hidden mb-6">
    <div class="p-4 border-b border-line flex items-center justify-between gap-3 flex-wrap">
        <div>
            <h3 class="text-sm font-semibold">Cola de trabajo</h3>
            <p class="text-[11px] text-ink-soft">
                <?= count($vmCases) ?> caso(s) con los filtros actuales<?= $companyName !== '' ? ' · ' . e($companyName) : '' ?>.
            </p>
        </div>
        <a href="<?= $importUrl ?>" class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline">
            Crear casos desde una importación
        </a>
    </div>
    <?php if ($vmCases === []): ?>
        <p class="p-5 text-sm text-ink-muted">
            No hay casos con estos filtros. Abre una importación y pulsa «Crear casos de seguimiento».
        </p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="w-full text-xs">
                <thead class="bg-muted text-ink-muted">
                    <tr>
                        <th class="px-3 py-2 text-left">CVE</th>
                        <th class="px-3 py-2 text-left">Empresa</th>
                        <th class="px-3 py-2 text-left">Prioridad</th>
                        <th class="px-3 py-2 text-left">Estado</th>
                        <th class="px-3 py-2 text-left">Responsable</th>
                        <th class="px-3 py-2 text-left">Vencimiento</th>
                        <th class="px-3 py-2 text-left">Última observación</th>
                        <th class="px-3 py-2"></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-line">
                    <?php foreach ($vmCases as $caseRow): ?>
                        <?php
                        $caseId = (int)$caseRow['id'];
                        $status = (string)$caseRow['status'];
                        $priority = (string)($caseRow['priority'] ?? '');
                        $deadline = VmCases::deadlineState(
                            (string)($caseRow['due_date'] ?? ''),
                            $status,
                            (string)($caseRow['accepted_until'] ?? ''),
                            $today
                        );
                        $caseUrl = base_url('modules/cve?tab=vm&company=' . (int)$caseRow['group_id'] . '&case=' . $caseId);
                        ?>
                        <tr class="hover:bg-muted/50">
                            <td class="px-3 py-2">
                                <a href="<?= $caseUrl ?>" class="font-mono font-medium text-brand-600 dark:text-brand-300 hover:underline">
                                    <?= e((string)$caseRow['cve_id']) ?>
                                </a>
                                <?php if (!empty($caseRow['kev_id'])): ?>
                                    <span class="ml-1 inline-flex px-1 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 text-[9px] font-semibold">KEV</span>
                                <?php endif; ?>
                            </td>
                            <td class="px-3 py-2 max-w-[160px] truncate" title="<?= e((string)($caseRow['company_name'] ?? '')) ?>">
                                <?= e((string)($caseRow['company_name'] ?? '—')) ?>
                            </td>
                            <td class="px-3 py-2">
                                <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $priorityClasses[$priority] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300' ?>">
                                    <?= e(VmCases::priorityLabel($priority)) ?>
                                </span>
                            </td>
                            <td class="px-3 py-2">
                                <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium <?= $statusClasses[$status] ?? '' ?>">
                                    <?= e($statusLabels[$status] ?? $status) ?>
                                </span>
                            </td>
                            <td class="px-3 py-2"><?= e((string)($caseRow['assignee_name'] ?? '—')) ?></td>
                            <td class="px-3 py-2">
                                <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium <?= $deadlineClasses[$deadline] ?? '' ?>">
                                    <?= e($deadlineLabels[$deadline] ?? $deadline) ?>
                                </span>
                                <span class="block text-[10px] text-ink-soft mt-0.5"><?= e($fmtDate((string)($caseRow['due_date'] ?? ''))) ?></span>
                            </td>
                            <td class="px-3 py-2 whitespace-nowrap">
                                <?= e($fmtDate((string)($caseRow['last_seen_at'] ?? ''))) ?>
                                <?php if (!empty($caseRow['import_filename'])): ?>
                                    <span class="block text-[10px] text-ink-soft max-w-[180px] truncate" title="<?= e((string)$caseRow['import_filename']) ?>">
                                        <?= e((string)$caseRow['import_filename']) ?>
                                    </span>
                                <?php endif; ?>
                            </td>
                            <td class="px-3 py-2 text-right">
                                <a href="<?= $caseUrl ?>" class="text-brand-600 dark:text-brand-300 hover:underline">Ver</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php if ($vmCase !== null): ?>
    <?php
    $case = $vmCase;
    $caseId = (int)$case['id'];
    $status = (string)$case['status'];
    $priority = (string)($case['priority'] ?? '');
    $factors = safe_json_decode((string)($case['priority_factors'] ?? ''), []);
    $factors = is_array($factors) ? $factors : [];
    $reasons = is_array($factors['reasons'] ?? null) ? $factors['reasons'] : [];
    $deadline = VmCases::deadlineState(
        (string)($case['due_date'] ?? ''),
        $status,
        (string)($case['accepted_until'] ?? ''),
        $today
    );
    $caseUrl = base_url('modules/cve?tab=vm&company=' . (int)$case['group_id'] . '&case=' . $caseId);
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
    $evidenceKinds = ['plan' => 'Plan de remediación', 'verification' => 'Verificación manual', 'note' => 'Nota'];
    ?>
    <div class="card overflow-hidden" id="vm-case">
        <div class="p-5 border-b border-line">
            <div class="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <div class="flex items-center gap-2 flex-wrap">
                        <h3 class="text-base font-bold font-mono"><?= e((string)$case['cve_id']) ?></h3>
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
                        · Ámbito: empresa + CVE (el CSV no identifica equipos)
                    </p>
                </div>
                <a href="<?= base_url('modules/cve/detail/' . urlencode((string)$case['cve_id'])) ?>"
                   class="inline-flex items-center gap-1 text-[11px] text-brand-600 dark:text-brand-300 hover:underline">
                    Ver ficha del CVE <i class="material-icons icon-12" aria-hidden="true">open_in_new</i>
                </a>
            </div>

            <?php if ($isReobserved && VmCases::isClosed($status)): ?>
                <div class="mt-3 px-3 py-2 rounded-lg text-[11px] text-amber-700 bg-amber-50 dark:bg-amber-900/20 dark:text-amber-300">
                    Este CVE ha vuelto a aparecer en una importación posterior. El caso sigue cerrado hasta que decidas reabrirlo.
                </div>
            <?php endif; ?>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mt-4">
                <div class="rounded-lg bg-muted px-3 py-2">
                    <p class="text-[10px] uppercase tracking-wide text-ink-soft">Primera observación</p>
                    <p class="text-sm font-medium"><?= e($fmtDate((string)($case['first_seen_at'] ?? ''))) ?></p>
                    <p class="text-[10px] text-ink-soft">Importación #<?= (int)($case['first_seen_import_id'] ?? 0) ?></p>
                </div>
                <div class="rounded-lg bg-muted px-3 py-2">
                    <p class="text-[10px] uppercase tracking-wide text-ink-soft">Última observación</p>
                    <p class="text-sm font-medium"><?= e($fmtDate((string)($case['last_seen_at'] ?? ''))) ?></p>
                    <p class="text-[10px] text-ink-soft">
                        <?= e((string)($case['import_filename'] ?? ('Importación #' . (int)($case['last_seen_import_id'] ?? 0)))) ?>
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
                    <p class="text-[10px] text-ink-soft"><?= e((string)($case['external_ticket'] ?? '')) !== '' ? 'Ticket: ' . e((string)$case['external_ticket']) : 'Sin ticket externo' ?></p>
                </div>
            </div>

            <?php if ($reasons !== []): ?>
                <div class="mt-3">
                    <p class="text-[10px] uppercase tracking-wide text-ink-soft mb-1">Motivo de la prioridad</p>
                    <div class="flex flex-wrap gap-1.5">
                        <?php foreach ($reasons as $reason): ?>
                            <span class="inline-flex px-2 py-0.5 rounded bg-muted text-[10px] text-ink-muted"><?= e((string)$reason) ?></span>
                        <?php endforeach; ?>
                    </div>
                    <p class="text-[10px] text-ink-soft mt-1">
                        Factores importados y calculados por la aplicación. No representan el riesgo total de la empresa.
                    </p>
                </div>
            <?php endif; ?>

            <?php if ($softwareLabels !== []): ?>
                <div class="mt-2 text-[11px] text-ink-soft">
                    Software del CSV:
                    <?php foreach (array_slice($softwareLabels, 0, 8) as $label): ?>
                        <span class="inline-flex px-1.5 py-0.5 rounded bg-muted text-[10px] mr-1"><?= e($label) ?></span>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <?php if ((string)($case['verification_kind'] ?? '') !== ''): ?>
                <p class="mt-2 text-[11px] text-green-700 dark:text-green-300">
                    Cierre verificado manualmente. Revisa la evidencia registrada más abajo.
                </p>
            <?php endif; ?>
        </div>

        <!-- Actualización del caso -->
        <div class="p-5 border-b border-line">
            <h4 class="text-sm font-semibold mb-3">Actualizar caso</h4>
            <form method="post" action="<?= base_url('modules/cve/vm/update') ?>" class="space-y-3">
                <?= Csrf::field() ?>
                <input type="hidden" name="case_id" value="<?= $caseId ?>">

                <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <div>
                        <label for="vm-status-update" class="block text-[11px] font-medium text-ink-muted mb-1">Estado</label>
                        <select id="vm-status-update" name="status"
                                class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                            <?php foreach ($statusLabels as $key => $label): ?>
                                <option value="<?= e($key) ?>" <?= $status === $key ? 'selected' : '' ?>><?= e($label) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div>
                        <label for="vm-priority-update" class="block text-[11px] font-medium text-ink-muted mb-1">Prioridad</label>
                        <select id="vm-priority-update" name="priority"
                                class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                            <option value="">Mantener (<?= e(VmCases::priorityLabel($priority)) ?>)</option>
                            <?php foreach ($priorityLabels as $key => $label): ?>
                                <option value="<?= e($key) ?>"><?= e($label) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div>
                        <label for="vm-assignee" class="block text-[11px] font-medium text-ink-muted mb-1">Responsable</label>
                        <input id="vm-assignee" type="text" name="assignee_name" maxlength="120"
                               value="<?= e((string)($case['assignee_name'] ?? '')) ?>"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <div>
                        <label for="vm-due-date" class="block text-[11px] font-medium text-ink-muted mb-1">Fecha objetivo</label>
                        <input id="vm-due-date" type="date" name="due_date" value="<?= e((string)($case['due_date'] ?? '')) ?>"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div>
                        <label for="vm-ticket" class="block text-[11px] font-medium text-ink-muted mb-1">Ticket externo (opcional)</label>
                        <input id="vm-ticket" type="text" name="external_ticket" maxlength="200"
                               value="<?= e((string)($case['external_ticket'] ?? '')) ?>"
                               placeholder="INC-1234, JIRA-…"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <div>
                        <label for="vm-risk-reason" class="block text-[11px] font-medium text-ink-muted mb-1">Motivo del riesgo aceptado</label>
                        <input id="vm-risk-reason" type="text" name="accepted_reason" maxlength="500"
                               value="<?= e((string)($case['accepted_reason'] ?? '')) ?>"
                               placeholder="Obligatorio si el estado es «Riesgo aceptado»"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <div>
                        <label for="vm-risk-until" class="block text-[11px] font-medium text-ink-muted mb-1">Caducidad del riesgo</label>
                        <input id="vm-risk-until" type="date" name="accepted_until"
                               value="<?= e((string)($case['accepted_until'] ?? '')) ?>"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                </div>

                <div>
                    <label for="vm-comment" class="block text-[11px] font-medium text-ink-muted mb-1">
                        Comentario del cambio (obligatorio para prórrogas)
                    </label>
                    <textarea id="vm-comment" name="comment" rows="2" maxlength="2000"
                              class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                        <label for="vm-verif-comment" class="block text-[11px] font-medium text-ink-muted mb-1">
                            Verificación manual (obligatoria para «Corregida y verificada»)
                        </label>
                        <textarea id="vm-verif-comment" name="verification_comment" rows="2" maxlength="2000"
                                  placeholder="Qué se comprobó y cómo"
                                  class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
                    </div>
                    <div>
                        <label for="vm-verif-ref" class="block text-[11px] font-medium text-ink-muted mb-1">
                            Referencia de la evidencia
                        </label>
                        <input id="vm-verif-ref" type="text" name="verification_reference" maxlength="500"
                               placeholder="Captura, ticket, fecha de parche, escaneo…"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                </div>

                <div class="flex items-center justify-between gap-3 flex-wrap">
                    <p class="text-[10px] text-ink-soft max-w-lg">
                        Cada cambio de estado, prioridad, responsable o fecha genera un evento de auditoría.
                        Una importación nueva nunca cierra este caso.
                    </p>
                    <button type="submit"
                            class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition-colors">
                        <i class="material-icons icon-14" aria-hidden="true">save</i>
                        Guardar cambios
                    </button>
                </div>
            </form>
        </div>

        <!-- Evidencias -->
        <div class="p-5 border-b border-line">
            <h4 class="text-sm font-semibold mb-3">Registrar evidencia</h4>
            <form method="post" action="<?= base_url('modules/cve/vm/evidence') ?>" class="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
                <?= Csrf::field() ?>
                <input type="hidden" name="case_id" value="<?= $caseId ?>">
                <div>
                    <label for="vm-evidence-kind" class="block text-[11px] font-medium text-ink-muted mb-1">Tipo</label>
                    <select id="vm-evidence-kind" name="kind"
                            class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                        <?php foreach ($evidenceKinds as $key => $label): ?>
                            <option value="<?= e($key) ?>"><?= e($label) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="md:col-span-2">
                    <label for="vm-evidence-comment" class="block text-[11px] font-medium text-ink-muted mb-1">Comentario</label>
                    <input id="vm-evidence-comment" type="text" name="comment" maxlength="2000" required
                           class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                </div>
                <div>
                    <label for="vm-evidence-ref" class="block text-[11px] font-medium text-ink-muted mb-1">Referencia</label>
                    <div class="flex gap-2">
                        <input id="vm-evidence-ref" type="text" name="reference" maxlength="500"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                        <button type="submit"
                                class="shrink-0 px-3 py-2 border border-line-strong text-ink text-xs font-medium rounded-lg hover:bg-muted transition-colors">
                            Añadir
                        </button>
                    </div>
                </div>
            </form>
        </div>

        <!-- Reabrir -->
        <?php if (in_array($status, ['resolved_verified', 'false_positive', 'risk_accepted'], true)): ?>
            <div class="p-5 border-b border-line">
                <form method="post" action="<?= base_url('modules/cve/vm/reopen') ?>" class="flex items-end gap-3 flex-wrap"
                      onsubmit="return confirm('¿Reabrir el caso? Se conservará todo el historial.');">
                    <?= Csrf::field() ?>
                    <input type="hidden" name="case_id" value="<?= $caseId ?>">
                    <div class="flex-1 min-w-[220px]">
                        <label for="vm-reopen-comment" class="block text-[11px] font-medium text-ink-muted mb-1">Motivo de la reapertura (opcional)</label>
                        <input id="vm-reopen-comment" type="text" name="comment" maxlength="500"
                               class="w-full px-2.5 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    </div>
                    <button type="submit"
                            class="inline-flex items-center gap-1.5 px-3 py-2 border border-amber-300 text-amber-700 dark:text-amber-300 text-xs font-medium rounded-lg hover:bg-amber-50 dark:hover:bg-amber-900/20 transition-colors">
                        <i class="material-icons icon-14" aria-hidden="true">replay</i>
                        Reabrir caso
                    </button>
                </form>
            </div>
        <?php endif; ?>

        <!-- Historial -->
        <div class="p-5">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div>
                    <h4 class="text-sm font-semibold mb-2">Historial de cambios</h4>
                    <?php if ($vmEvents === []): ?>
                        <p class="text-xs text-ink-soft">Sin eventos.</p>
                    <?php else: ?>
                        <ol class="space-y-2 max-h-[420px] overflow-y-auto pr-1">
                            <?php foreach ($vmEvents as $eventRow): ?>
                                <li class="border-l-2 border-line pl-3">
                                    <p class="text-[11px] font-medium">
                                        <?= e(VmCases::eventLabel((string)($eventRow['event_type'] ?? ''))) ?>
                                        <?php if ((string)($eventRow['old_value'] ?? '') !== '' || (string)($eventRow['new_value'] ?? '') !== ''): ?>
                                            <span class="text-ink-soft font-normal">
                                                <?= e((string)($eventRow['old_value'] ?? '')) ?>
                                                → <?= e((string)($eventRow['new_value'] ?? '')) ?>
                                            </span>
                                        <?php endif; ?>
                                    </p>
                                    <?php if ((string)($eventRow['comment'] ?? '') !== ''): ?>
                                        <p class="text-[11px] text-ink-muted"><?= e((string)$eventRow['comment']) ?></p>
                                    <?php endif; ?>
                                    <p class="text-[10px] text-ink-soft">
                                        <?= e($fmtDateTime((string)($eventRow['created_at'] ?? ''))) ?>
                                        · <?= e((string)($eventRow['username'] ?? 'sistema')) ?>
                                    </p>
                                </li>
                            <?php endforeach; ?>
                        </ol>
                    <?php endif; ?>
                </div>
                <div>
                    <h4 class="text-sm font-semibold mb-2">Evidencias</h4>
                    <?php if ($vmEvidence === []): ?>
                        <p class="text-xs text-ink-soft">Sin evidencias registradas.</p>
                    <?php else: ?>
                        <ul class="space-y-2 max-h-[420px] overflow-y-auto pr-1">
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
                                    <p class="text-[10px] text-ink-soft">
                                        <?= e($fmtDate((string)($evRow['occurred_at'] ?? ''))) ?>
                                        · <?= e((string)($evRow['username'] ?? 'sistema')) ?>
                                    </p>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
<?php endif; ?>

<?php endif; ?>
