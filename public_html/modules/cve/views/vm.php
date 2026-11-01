<?php
/**
 * Vista: CVE — Seguimiento de vulnerabilidades (v0.3.2).
 *
 * Variables: $isAdmin, $companyGroups, $vmCases, $vmKpis, $vmCase,
 *            $vmEvents, $vmEvidence, $vmFilters, $vmLastImport, $vmPending.
 *
 * Interfaz simplificada: barra de acciones única, KPIs compactos, cola con
 * filtros esenciales y ficha del CVE / detalle del caso en panel inline.
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
$vmPending = ($vmPending === null || $vmPending === false) ? null : (int)$vmPending;

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
$sourceLabels = ['defender-tvm' => 'CSV Defender TVM', 'catalog' => 'Mis CVE (catálogo)'];

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

$queryBase = [
    'tab' => 'vm',
    'company' => $selectedCompany,
    'vm_status' => (string)$vmFilters['status'],
    'vm_priority' => (string)$vmFilters['priority'],
    'vm_due' => (string)$vmFilters['due'],
    'vm_q' => (string)$vmFilters['q'],
    'vm_sort' => (string)$vmFilters['sort'],
];
$caseUrl = static function (int $caseId) use ($queryBase): string {
    $queryBase['case'] = $caseId;
    return base_url('modules/cve?' . http_build_query($queryBase));
};
?>

<div class="mb-4 flex items-start justify-between gap-3 flex-wrap">
    <div>
        <h2 class="text-lg font-bold">Seguimiento de vulnerabilidades</h2>
        <p class="text-[11px] text-ink-soft">
            Casos por empresa + CVE creados desde importaciones o desde Mis CVE. Origen manual y verificable.
        </p>
    </div>
    <div class="flex items-center gap-2 flex-wrap">
        <a href="<?= $importUrl ?>"
           class="inline-flex items-center gap-2 px-3 py-2 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
            <i class="material-icons icon-14" aria-hidden="true">upload_file</i>
            Importar CSV
        </a>
        <a href="<?= $reportUrl ?>"
           class="inline-flex items-center gap-2 px-3 py-2 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
            <i class="material-icons icon-14" aria-hidden="true">summarize</i>
            Informe
        </a>
    </div>
</div>

<?php if ($companyGroups === []): ?>
    <div class="card p-5">
        <p class="text-sm text-ink-muted">
            Todavía no hay empresas. Crea una en <strong>Mis CVE → Empresas</strong> e importa su CSV de Defender TVM.
        </p>
    </div>
<?php else: ?>

<!-- Barra de acciones única -->
<div class="card p-3 mb-3 flex items-end justify-between gap-3 flex-wrap">
    <?php if ($isAdmin): ?>
        <form method="post" action="<?= base_url('modules/cve/vm/create-from-group') ?>" class="flex items-end gap-2 flex-wrap">
            <?= Csrf::field() ?>
            <div>
                <label for="vm-create-company" class="block text-[10px] font-medium text-ink-muted mb-1">Crear casos desde Mis CVE</label>
                <select id="vm-create-company" name="company_id" required
                        class="px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="">Empresa…</option>
                    <?php foreach ($companyGroups as $companyRow): ?>
                        <option value="<?= (int)$companyRow['id'] ?>" <?= $selectedCompany === (int)$companyRow['id'] ? 'selected' : '' ?>>
                            <?= e((string)$companyRow['name']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button type="submit"
                    class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition-colors">
                Crear pendientes
            </button>
            <?php if ($vmPending !== null): ?>
                <span class="text-[11px] text-ink-soft pb-1">
                    <?= $vmPending ?> CVE(s) asignados sin caso
                </span>
            <?php endif; ?>
        </form>
    <?php endif; ?>
    <p class="text-[10px] text-ink-soft max-w-md">
        Los datos vienen de importaciones manuales: pueden estar incompletos. Un CVE ausente en un export
        <strong>no está corregido</strong>; el cierre exige verificación manual.
    </p>
</div>

<!-- Filtros esenciales + avanzados plegados -->
<form method="get" action="<?= base_url('modules/cve') ?>" class="card p-3 mb-3 no-print">
    <input type="hidden" name="tab" value="vm">
    <div class="grid grid-cols-2 md:grid-cols-5 gap-2 items-end">
        <div>
            <label for="vm-company" class="block text-[10px] font-medium text-ink-muted mb-1">Empresa</label>
            <select id="vm-company" name="company"
                    class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                <option value="0">Todas</option>
                <?php foreach ($companyGroups as $companyRow): ?>
                    <option value="<?= (int)$companyRow['id'] ?>" <?= $selectedCompany === (int)$companyRow['id'] ? 'selected' : '' ?>>
                        <?= e((string)$companyRow['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label for="vm-status" class="block text-[10px] font-medium text-ink-muted mb-1">Estado</label>
            <select id="vm-status" name="vm_status"
                    class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                <option value="">Todos</option>
                <?php foreach ($statusLabels as $key => $label): ?>
                    <option value="<?= e($key) ?>" <?= $vmFilters['status'] === $key ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label for="vm-due" class="block text-[10px] font-medium text-ink-muted mb-1">Vencimiento</label>
            <select id="vm-due" name="vm_due"
                    class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                <option value="">Todos</option>
                <option value="overdue" <?= $vmFilters['due'] === 'overdue' ? 'selected' : '' ?>>Vencidos</option>
                <option value="due_soon" <?= $vmFilters['due'] === 'due_soon' ? 'selected' : '' ?>>Próximos</option>
                <option value="exception" <?= $vmFilters['due'] === 'exception' ? 'selected' : '' ?>>Excepciones caducadas</option>
            </select>
        </div>
        <div>
            <label for="vm-q" class="block text-[10px] font-medium text-ink-muted mb-1">Buscar</label>
            <input id="vm-q" type="search" name="vm_q" value="<?= e((string)$vmFilters['q']) ?>"
                   placeholder="CVE, producto o responsable"
                   class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
        </div>
        <div class="flex items-center gap-2">
            <button type="submit"
                    class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition-colors">
                Filtrar
            </button>
            <a href="<?= base_url('modules/cve?tab=vm') ?>" class="text-[11px] text-ink-soft hover:underline">Limpiar</a>
        </div>
    </div>
    <details class="mt-2">
        <summary class="text-[10px] text-ink-soft cursor-pointer select-none">Más filtros</summary>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mt-2">
            <div>
                <label for="vm-priority" class="block text-[10px] font-medium text-ink-muted mb-1">Prioridad</label>
                <select id="vm-priority" name="vm_priority"
                        class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    <option value="">Todas</option>
                    <?php foreach ($priorityLabels as $key => $label): ?>
                        <option value="<?= e($key) ?>" <?= $vmFilters['priority'] === $key ? 'selected' : '' ?>><?= e($label) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label for="vm-sort" class="block text-[10px] font-medium text-ink-muted mb-1">Orden</label>
                <select id="vm-sort" name="vm_sort"
                        class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    <option value="due" <?= $vmFilters['sort'] === 'due' ? 'selected' : '' ?>>Vencimiento</option>
                    <option value="priority" <?= $vmFilters['sort'] === 'priority' ? 'selected' : '' ?>>Prioridad</option>
                    <option value="last_seen" <?= $vmFilters['sort'] === 'last_seen' ? 'selected' : '' ?>>Última observación</option>
                    <option value="created" <?= $vmFilters['sort'] === 'created' ? 'selected' : '' ?>>Alta</option>
                </select>
            </div>
        </div>
    </details>
</form>

<!-- KPIs -->
<div class="grid grid-cols-2 md:grid-cols-5 gap-2 mb-2">
    <?php
    $cards = [
        ['label' => 'Con seguimiento', 'value' => (int)($vmKpis['total'] ?? 0)],
        ['label' => 'Abiertos', 'value' => (int)($vmKpis['open'] ?? 0)],
        ['label' => 'Vencidos', 'value' => (int)($vmKpis['overdue'] ?? 0)],
        ['label' => 'Próximos (7 d)', 'value' => (int)($vmKpis['due_soon'] ?? 0)],
        ['label' => 'Verificados', 'value' => (int)($vmKpis['resolved_verified'] ?? 0)],
    ];
    ?>
    <?php foreach ($cards as $card): ?>
        <div class="card px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft"><?= e($card['label']) ?></p>
            <p class="text-lg font-semibold"><?= (int)$card['value'] ?></p>
        </div>
    <?php endforeach; ?>
</div>

<details class="card px-3 py-2 mb-4">
    <summary class="text-[11px] font-medium cursor-pointer select-none">
        Desglose, excepciones y última importación
    </summary>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-3 text-xs">
        <div>
            <p class="font-semibold mb-1">Por prioridad</p>
            <?php foreach ($priorityLabels as $key => $label): ?>
                <div class="flex items-center justify-between text-[11px]">
                    <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $priorityClasses[$key] ?? '' ?>"><?= e($label) ?></span>
                    <span class="font-mono"><?= (int)($vmKpis['by_priority'][$key] ?? 0) ?></span>
                </div>
            <?php endforeach; ?>
        </div>
        <div>
            <p class="font-semibold mb-1">Por estado</p>
            <div class="max-h-32 overflow-y-auto pr-1">
                <?php foreach ($statusLabels as $key => $label): ?>
                    <div class="flex items-center justify-between text-[11px]">
                        <span><?= e($label) ?></span>
                        <span class="font-mono"><?= (int)($vmKpis['by_status'][$key] ?? 0) ?></span>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        <div>
            <p class="font-semibold mb-1">Última importación</p>
            <?php if ($vmLastImport === null): ?>
                <p class="text-[11px] text-ink-soft">Sin importaciones.</p>
            <?php else: ?>
                <p class="text-[11px]"><?= e((string)($vmLastImport['company_name'] ?? '—')) ?> · <?= e($fmtDateTime((string)($vmLastImport['created_at'] ?? ''))) ?></p>
                <p class="text-[11px] text-ink-soft">
                    <?= (int)($vmLastImport['rows_imported'] ?? 0) ?> CVEs · <?= e((string)($vmLastImport['status'] ?? '—')) ?>
                </p>
                <a href="<?= base_url('modules/cve?tab=import&import=' . (int)$vmLastImport['id']) ?>"
                   class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline">Ver importación</a>
            <?php endif; ?>
            <p class="text-[10px] text-ink-soft mt-2">
                Hay <?= (int)($vmKpis['exception_expired'] ?? 0) ?> excepción(es) caducada(s). Los KPI miden solo casos importados, no todo el parque.
            </p>
        </div>
    </div>
</details>

<!-- Cola -->
<div class="card overflow-hidden mb-4">
    <div class="p-3 border-b border-line flex items-center justify-between gap-2 flex-wrap">
        <p class="text-xs font-semibold">
            Cola · <?= count($vmCases) ?> caso(s)<?= $companyName !== '' ? ' · ' . e($companyName) : '' ?>
        </p>
        <p class="text-[10px] text-ink-soft">Clic en el CVE o en «Ver» abre la ficha sin salir de esta pantalla.</p>
    </div>
    <?php if ($vmCases === []): ?>
        <p class="p-4 text-sm text-ink-muted">
            No hay casos con estos filtros. Crea casos desde una importación o desde el botón «Crear pendientes».
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
                        <th class="px-3 py-2 text-left">Vencimiento</th>
                        <th class="px-3 py-2 text-left">Responsable</th>
                        <th class="px-3 py-2 text-left">Última obs.</th>
                        <th class="px-3 py-2"></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-line">
                    <?php foreach ($vmCases as $caseRow): ?>
                        <?php
                        $rowId = (int)$caseRow['id'];
                        $rowStatus = (string)$caseRow['status'];
                        $rowPriority = (string)($caseRow['priority'] ?? '');
                        $rowDeadline = VmCases::deadlineState(
                            (string)($caseRow['due_date'] ?? ''),
                            $rowStatus,
                            (string)($caseRow['accepted_until'] ?? ''),
                            $today
                        );
                        $rowSource = (string)($caseRow['source'] ?? 'defender-tvm');
                        $panelUrl = base_url('modules/cve/vm/' . $rowId . '/panel');
                        ?>
                        <tr class="hover:bg-muted/50">
                            <td class="px-3 py-2">
                                <a href="<?= base_url('modules/cve/detail/' . urlencode((string)$caseRow['cve_id']) . '/panel') ?>"
                                   data-vm-panel data-vm-title="<?= e((string)$caseRow['cve_id']) ?>"
                                   class="font-mono font-medium text-brand-600 dark:text-brand-300 hover:underline">
                                    <?= e((string)$caseRow['cve_id']) ?>
                                </a>
                                <?php if (!empty($caseRow['kev_id'])): ?>
                                    <span class="ml-1 inline-flex px-1 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 text-[9px] font-semibold">KEV</span>
                                <?php endif; ?>
                                <span class="ml-1 inline-flex px-1 py-0.5 rounded text-[9px] <?= $rowSource === 'catalog' ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' : 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' ?>"
                                      title="<?= e($sourceLabels[$rowSource] ?? $rowSource) ?>">
                                    <?= $rowSource === 'catalog' ? 'Mis CVE' : 'TVM' ?>
                                </span>
                            </td>
                            <td class="px-3 py-2 max-w-[150px] truncate" title="<?= e((string)($caseRow['company_name'] ?? '')) ?>">
                                <?= e((string)($caseRow['company_name'] ?? '—')) ?>
                            </td>
                            <td class="px-3 py-2">
                                <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $priorityClasses[$rowPriority] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300' ?>">
                                    <?= e(VmCases::priorityLabel($rowPriority)) ?>
                                </span>
                            </td>
                            <td class="px-3 py-2">
                                <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium <?= $statusClasses[$rowStatus] ?? '' ?>">
                                    <?= e($statusLabels[$rowStatus] ?? $rowStatus) ?>
                                </span>
                            </td>
                            <td class="px-3 py-2 whitespace-nowrap">
                                <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium <?= $deadlineClasses[$rowDeadline] ?? '' ?>">
                                    <?= e($deadlineLabels[$rowDeadline] ?? $rowDeadline) ?>
                                </span>
                                <span class="block text-[10px] text-ink-soft"><?= e($fmtDate((string)($caseRow['due_date'] ?? ''))) ?></span>
                            </td>
                            <td class="px-3 py-2"><?= e((string)($caseRow['assignee_name'] ?? '—')) ?></td>
                            <td class="px-3 py-2 whitespace-nowrap"><?= e($fmtDate((string)($caseRow['last_seen_at'] ?? ''))) ?></td>
                            <td class="px-3 py-2 text-right">
                                <a href="<?= e($caseUrl($rowId)) ?>"
                                   data-vm-panel data-vm-title="Caso <?= e((string)$caseRow['cve_id']) ?>"
                                   data-vm-url="<?= e($panelUrl) ?>"
                                   class="text-brand-600 dark:text-brand-300 hover:underline">Ver</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php if ($vmCase !== null): ?>
    <div class="card p-4 mb-4" id="vm-case-inline">
        <?php require __DIR__ . '/_vm_case_panel.php'; ?>
    </div>
<?php endif; ?>

<!-- Panel inline (ficha del CVE y detalle del caso) -->
<div id="vm-drawer" class="fixed inset-0 z-50 hidden no-print" aria-hidden="true">
    <div class="absolute inset-0" style="background:rgba(0,0,0,.45)" data-vm-close></div>
    <aside class="absolute right-0 top-0 h-full w-full max-w-2xl bg-surface dark:bg-gray-900 shadow-2xl overflow-y-auto">
        <div class="sticky top-0 z-10 flex items-center justify-between gap-3 px-4 py-3 border-b border-line bg-surface dark:bg-gray-900">
            <p id="vm-drawer-title" class="text-sm font-semibold truncate">Detalle</p>
            <button type="button" data-vm-close
                    class="inline-flex items-center justify-center w-8 h-8 rounded-lg border border-line hover:bg-muted transition-colors"
                    aria-label="Cerrar">
                <i class="material-icons icon-16" aria-hidden="true">close</i>
            </button>
        </div>
        <div id="vm-drawer-body" class="p-4"></div>
    </aside>
</div>

<script>
(function () {
    var drawer = document.getElementById('vm-drawer');
    if (!drawer) { return; }
    var body = document.getElementById('vm-drawer-body');
    var title = document.getElementById('vm-drawer-title');

    function syncConditions(root) {
        if (!root) { return; }
        var selects = root.querySelectorAll('[data-vm-status]');
        Array.prototype.forEach.call(selects, function (select) {
            var form = select.closest('form');
            if (!form || form.getAttribute('data-vm-bound') === '1') { return; }
            form.setAttribute('data-vm-bound', '1');
            var apply = function () {
                var risk = form.querySelector('[data-vm-risk]');
                var verification = form.querySelector('[data-vm-verification]');
                if (risk) { risk.style.display = select.value === 'risk_accepted' ? '' : 'none'; }
                if (verification) { verification.style.display = select.value === 'resolved_verified' ? '' : 'none'; }
            };
            select.addEventListener('change', apply);
            apply();
            form.setAttribute('data-vm-apply', '1');
        });
    }

    function loadFragment(url, target, loadingText) {
        target.innerHTML = '<p class="text-[11px] text-ink-soft">' + (loadingText || 'Cargando…') + '</p>';
        return fetch(url, {
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (response) {
            if (!response.ok) { throw new Error('HTTP ' + response.status); }
            return response.text();
        }).then(function (html) {
            target.innerHTML = html;
            syncConditions(target);
            hydrateCvePanels(target);
            return true;
        });
    }

    function hydrateCvePanels(root) {
        if (!root || !root.querySelectorAll) { return; }
        Array.prototype.forEach.call(root.querySelectorAll('[data-vm-cve-panel]'), function (box) {
            if (box.getAttribute('data-vm-loaded') === '1') { return; }
            var url = box.getAttribute('data-vm-cve-url');
            if (!url) { return; }
            box.setAttribute('data-vm-loaded', '1');
            loadFragment(url, box, 'Cargando información del CVE…').catch(function () {
                box.innerHTML = '<p class="text-[11px] text-danger">No se pudo cargar la información del CVE.</p>';
            });
        });
    }

    function closeDrawer() {
        drawer.classList.add('hidden');
        drawer.setAttribute('aria-hidden', 'true');
        body.innerHTML = '';
    }

    document.addEventListener('click', function (event) {
        var closer = event.target.closest('[data-vm-close]');
        if (closer) {
            event.preventDefault();
            closeDrawer();
            return;
        }

        var scroller = event.target.closest('[data-vm-cve-scroll]');
        if (scroller) {
            event.preventDefault();
            var scope = event.target.closest('#vm-case-inline, #vm-drawer-body') || document;
            var section = scope.querySelector('[data-vm-cve-panel]');
            if (section) {
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            return;
        }

        var reportButton = event.target.closest('[data-vm-report-url]');
        if (reportButton) {
            event.preventDefault();
            var container = reportButton.closest('[data-vm-cve-panel]') || reportButton.parentElement;
            loadFragment(reportButton.getAttribute('data-vm-report-url'), container, 'Cargando informe…')
                .catch(function () {
                    container.innerHTML = '<p class="text-[11px] text-danger">No se pudo cargar el informe.</p>';
                });
            return;
        }

        var link = event.target.closest('[data-vm-panel]');
        if (!link) { return; }
        event.preventDefault();

        var url = link.getAttribute('data-vm-url') || link.getAttribute('href');
        title.textContent = link.getAttribute('data-vm-title') || 'Detalle';
        body.innerHTML = '<p class="text-xs text-ink-soft">Cargando…</p>';
        drawer.classList.remove('hidden');
        drawer.setAttribute('aria-hidden', 'false');

        loadFragment(url, body, 'Cargando…').catch(function () {
            body.innerHTML = '<p class="text-xs text-danger">No se pudo cargar el detalle. Recarga la página e inténtalo de nuevo.</p>';
        });
    });

    // El formulario de informe IA vive dentro de contenido inyectado: delegado.
    document.addEventListener('submit', function (event) {
        var form = event.target.closest('form[data-vm-ai-form]');
        if (!form) { return; }
        event.preventDefault();

        var container = form.closest('[data-vm-cve-panel]') || form.parentElement;
        var data = new FormData(form);
        if (event.submitter && event.submitter.name) {
            data.append(event.submitter.name, event.submitter.value);
        }

        container.innerHTML = '<p class="text-[11px] text-ink-soft">Generando informe… esto puede tardar un poco.</p>';
        fetch(form.getAttribute('action'), {
            method: 'POST',
            body: data,
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (response) {
            return response.text();
        }).then(function (html) {
            container.innerHTML = html;
        }).catch(function () {
            container.innerHTML = '<p class="text-[11px] text-danger">No se pudo generar el informe.</p>';
        });
    });

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') { closeDrawer(); }
    });

    syncConditions(document);
    hydrateCvePanels(document);
})();
</script>

<?php endif; ?>
