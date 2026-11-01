<?php
/**
 * Vista: CVE — Informe ejecutivo del seguimiento (v0.3.0).
 *
 * Todos los números vienen calculados en backend desde vm_cases y
 * vm_case_events. No se usa IA ni se afirma que un parche esté aplicado
 * sin evidencia de verificación manual.
 *
 * Variables: $vmCompany, $vmCompanyName, $vmDays, $vmCases, $vmKpis,
 *            $vmEvents, $tvmImports.
 */

$vmCases = is_array($vmCases ?? null) ? $vmCases : [];
$vmKpis = is_array($vmKpis ?? null) ? $vmKpis : [];
$vmEvents = is_array($vmEvents ?? null) ? $vmEvents : [];
$tvmImports = is_array($tvmImports ?? null) ? $tvmImports : [];
$vmCompanyName = trim((string)($vmCompanyName ?? ''));
$vmDays = max(1, (int)($vmDays ?? 30));
$today = date('Y-m-d');

$fmtDate = static function (?string $value): string {
    $value = trim((string)$value);
    if ($value === '') {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('d/m/Y', $ts);
};

$openCases = [];
$overdueCases = [];
$exceptionCases = [];
$verifiedCases = [];
foreach ($vmCases as $caseRow) {
    $status = (string)($caseRow['status'] ?? 'detected');
    if (!VmCases::isClosed($status)) {
        $openCases[] = $caseRow;
    }
    $deadline = VmCases::deadlineState(
        (string)($caseRow['due_date'] ?? ''),
        $status,
        (string)($caseRow['accepted_until'] ?? ''),
        $today
    );
    if ($deadline === 'expired' || $deadline === 'exception_expired') {
        $overdueCases[] = $caseRow;
    }
    if ($status === 'risk_accepted' && $deadline === 'exception_expired') {
        $exceptionCases[] = $caseRow;
    }
    if ($status === 'resolved_verified') {
        $verifiedCases[] = $caseRow;
    }
}
usort($overdueCases, static function (array $a, array $b): int {
    return strcmp((string)($a['due_date'] ?? ''), (string)($b['due_date'] ?? ''));
});

$changesByType = [];
foreach ($vmEvents as $eventRow) {
    $type = (string)($eventRow['event_type'] ?? '');
    $changesByType[$type] = ($changesByType[$type] ?? 0) + 1;
}
arsort($changesByType);

$lastImport = $tvmImports[0] ?? null;
$lastImportDate = $lastImport !== null ? (string)($lastImport['created_at'] ?? '') : '';
$lastImportAgo = null;
if ($lastImportDate !== '') {
    $ts = strtotime($lastImportDate);
    if ($ts !== false) {
        $lastImportAgo = (int)floor((time() - $ts) / 86400);
    }
}
?>

<div class="no-print mb-4 flex items-end justify-between gap-3 flex-wrap">
    <div>
        <h2 class="text-lg font-bold">Informe de seguimiento</h2>
        <p class="text-xs text-ink-soft">
            <?= $vmCompanyName !== '' ? e($vmCompanyName) : 'Todas las empresas' ?>
            · últimos <?= $vmDays ?> días · generado el <?= e(date('d/m/Y H:i')) ?>
        </p>
    </div>
    <div class="flex items-center gap-2">
        <a href="<?= base_url('modules/cve?tab=vm&company=' . (int)($vmCompany ?? 0)) ?>"
           class="inline-flex items-center gap-2 px-3 py-2 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
            <i class="material-icons icon-14" aria-hidden="true">arrow_back</i>
            Volver al seguimiento
        </a>
        <button type="button" onclick="window.print()"
                class="inline-flex items-center gap-2 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition-colors">
            <i class="material-icons icon-14" aria-hidden="true">print</i>
            Imprimir
        </button>
    </div>
</div>

<?php if ($lastImport !== null): ?>
    <div class="card p-5 mb-4">
        <h3 class="text-sm font-semibold mb-2">Cobertura de datos</h3>
        <p class="text-xs text-ink-muted">
            Última importación: <strong><?= e($fmtDate($lastImportDate)) ?></strong>
            <?= e((string)($lastImport['filename'] ?? '')) ?>
            · <?= (int)($lastImport['rows_imported'] ?? 0) ?> CVEs
            · estado <strong><?= e((string)($lastImport['status'] ?? '—')) ?></strong>
            <?php if ($lastImportAgo !== null): ?>
                · hace <?= $lastImportAgo ?> día(s)
            <?php endif; ?>
        </p>
        <?php if ($lastImportAgo !== null && $lastImportAgo > 30): ?>
            <p class="mt-2 text-[11px] text-amber-700 dark:text-amber-300">
                La última importación tiene más de 30 días: los datos pueden estar desactualizados.
            </p>
        <?php endif; ?>
        <?php if ((string)($lastImport['status'] ?? '') !== 'done'): ?>
            <p class="mt-2 text-[11px] text-red-700 dark:text-red-300">
                La última importación no terminó correctamente; este informe no debe usarse para decisiones de cierre.
            </p>
        <?php endif; ?>
        <p class="mt-2 text-[11px] text-ink-soft">
            El CSV de Defender TVM se importa manualmente y solo incluye los CVEs seleccionados en ese export.
            La ausencia de un CVE en una importación posterior no demuestra que esté corregido.
        </p>
    </div>
<?php endif; ?>

<div class="grid grid-cols-2 md:grid-cols-5 gap-2 mb-5">
    <?php
    $cards = [
        ['label' => 'Casos con seguimiento', 'value' => (int)($vmKpis['total'] ?? 0)],
        ['label' => 'Abiertos', 'value' => (int)($vmKpis['open'] ?? 0)],
        ['label' => 'Vencidos', 'value' => (int)($vmKpis['overdue'] ?? 0)],
        ['label' => 'Corregidos y verificados', 'value' => (int)($vmKpis['resolved_verified'] ?? 0)],
        ['label' => 'Excepciones caducadas', 'value' => (int)($vmKpis['exception_expired'] ?? 0)],
    ];
    ?>
    <?php foreach ($cards as $card): ?>
        <div class="card p-3">
            <p class="text-[10px] uppercase tracking-wide text-ink-soft"><?= e($card['label']) ?></p>
            <p class="text-xl font-semibold mt-1"><?= (int)$card['value'] ?></p>
        </div>
    <?php endforeach; ?>
</div>

<p class="text-[10px] text-ink-soft mb-5">
    Definición: estos porcentajes se calculan solo sobre los CVEs importados y con caso de seguimiento.
    <strong>No representan la cobertura total del parque</strong> ni un porcentaje de equipos seguros.
    «Corregido y verificado» exige evidencia manual registrada; no se deduce de que un CVE desaparezca del CSV.
</p>

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
    <div class="card p-5">
        <h3 class="text-sm font-semibold mb-2">Casos abiertos y prioridad</h3>
        <?php if ($openCases === []): ?>
            <p class="text-xs text-ink-soft">No hay casos abiertos.</p>
        <?php else: ?>
            <ul class="space-y-1.5">
                <?php foreach (array_slice($openCases, 0, 12) as $caseRow): ?>
                    <li class="flex items-center justify-between gap-2 text-xs">
                        <span class="font-mono"><?= e((string)$caseRow['cve_id']) ?></span>
                        <span class="text-ink-soft">
                            <?= e(VmCases::priorityLabel((string)($caseRow['priority'] ?? ''))) ?>
                            · <?= e(VmCases::statusLabel((string)($caseRow['status'] ?? ''))) ?>
                            · <?= e($fmtDate((string)($caseRow['due_date'] ?? ''))) ?>
                        </span>
                    </li>
                <?php endforeach; ?>
            </ul>
            <?php if (count($openCases) > 12): ?>
                <p class="text-[10px] text-ink-soft mt-2">… y <?= count($openCases) - 12 ?> más en la cola.</p>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <div class="card p-5">
        <h3 class="text-sm font-semibold mb-2">Vencidos y excepciones caducadas</h3>
        <?php if ($overdueCases === []): ?>
            <p class="text-xs text-ink-soft">No hay casos vencidos ni excepciones caducadas.</p>
        <?php else: ?>
            <ul class="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                <?php foreach ($overdueCases as $caseRow): ?>
                    <li class="flex items-center justify-between gap-2 text-xs">
                        <span class="font-mono"><?= e((string)$caseRow['cve_id']) ?></span>
                        <span class="text-red-700 dark:text-red-300">
                            <?= e((string)($caseRow['status'] === 'risk_accepted' ? 'Excepción hasta ' : 'Vencido ')) ?>
                            <?= e($fmtDate((string)($caseRow['due_date'] ?? ''))) ?>
                        </span>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
        <?php if ($exceptionCases !== []): ?>
            <p class="text-[11px] text-purple-700 dark:text-purple-300 mt-2">
                <?= count($exceptionCases) ?> riesgo(s) aceptado(s) fuera de plazo: requieren revisión.
            </p>
        <?php endif; ?>
    </div>
</div>

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
    <div class="card p-5">
        <h3 class="text-sm font-semibold mb-2">Cambios del periodo (<?= $vmDays ?> días)</h3>
        <?php if ($changesByType === []): ?>
            <p class="text-xs text-ink-soft">Sin cambios registrados en el periodo.</p>
        <?php else: ?>
            <ul class="space-y-1">
                <?php foreach ($changesByType as $type => $count): ?>
                    <li class="flex items-center justify-between text-xs">
                        <span><?= e(VmCases::eventLabel((string)$type)) ?></span>
                        <span class="font-mono"><?= (int)$count ?></span>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </div>

    <div class="card p-5">
        <h3 class="text-sm font-semibold mb-2">Casos verificados</h3>
        <?php if ($verifiedCases === []): ?>
            <p class="text-xs text-ink-soft">Todavía no hay casos cerrados con verificación manual.</p>
        <?php else: ?>
            <ul class="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                <?php foreach ($verifiedCases as $caseRow): ?>
                    <li class="flex items-center justify-between gap-2 text-xs">
                        <span class="font-mono"><?= e((string)$caseRow['cve_id']) ?></span>
                        <span class="text-green-700 dark:text-green-300"><?= e($fmtDate((string)($caseRow['resolved_at'] ?? ''))) ?></span>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </div>
</div>

<div class="card overflow-hidden">
    <div class="p-5 border-b border-line">
        <h3 class="text-sm font-semibold">Importaciones recientes</h3>
        <p class="text-[11px] text-ink-soft">Cada ejecución manual queda registrada con su resultado.</p>
    </div>
    <?php if ($tvmImports === []): ?>
        <p class="p-5 text-sm text-ink-muted">Sin importaciones registradas.</p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="w-full text-xs">
                <thead class="bg-muted text-ink-muted">
                    <tr>
                        <th class="px-3 py-2 text-left">Fecha</th>
                        <th class="px-3 py-2 text-left">Empresa</th>
                        <th class="px-3 py-2 text-left">Fichero</th>
                        <th class="px-3 py-2 text-right">CVEs</th>
                        <th class="px-3 py-2 text-left">Estado</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-line">
                    <?php foreach ($tvmImports as $item): ?>
                        <tr>
                            <td class="px-3 py-2 whitespace-nowrap"><?= e($fmtDate((string)($item['created_at'] ?? ''))) ?></td>
                            <td class="px-3 py-2"><?= e((string)($item['company_name'] ?? '—')) ?></td>
                            <td class="px-3 py-2 max-w-[240px] truncate" title="<?= e((string)($item['filename'] ?? '')) ?>">
                                <?= e((string)($item['filename'] ?? '')) ?>
                            </td>
                            <td class="px-3 py-2 text-right font-mono"><?= (int)($item['rows_imported'] ?? 0) ?></td>
                            <td class="px-3 py-2 font-mono"><?= e((string)($item['status'] ?? '—')) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>
