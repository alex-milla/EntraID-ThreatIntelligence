<?php
/**
 * Vista: CVE — Import Organización (CSV de Defender TVM).
 *
 * Variables: $isAdmin, $companyGroups, $tvmImports, $tvmImport, $tvmRows.
 */

$tvmImports = is_array($tvmImports ?? null) ? $tvmImports : [];
$tvmRows = is_array($tvmRows ?? null) ? $tvmRows : [];
$tvmImport = is_array($tvmImport ?? null) ? $tvmImport : null;
$companyGroups = is_array($companyGroups ?? null) ? $companyGroups : [];
$selectedCompanyId = (int)($tvmImport['company_id'] ?? ($_GET['company'] ?? 0));

$severityLabels = [
    'critical' => 'Crítica',
    'high'     => 'Alta',
    'medium'   => 'Media',
    'low'      => 'Baja',
    'info'     => 'Informativa',
];
$severityClasses = [
    'critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'high'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'info'     => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
];
$catalogSourceLabels = [
    'catalog' => 'En catálogo',
    'csv'     => 'Desde CSV',
    'nvd'     => 'NVD',
    'missing' => 'Sin catálogo',
];
$catalogSourceClasses = [
    'catalog' => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'csv'     => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    'nvd'     => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    'missing' => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
];

$formatDate = static function (?string $value): string {
    $value = trim((string)$value);
    if ($value === '') {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('d/m/Y H:i', $ts);
};

$pendingNvd = 0;
$rowsWithReport = 0;
foreach ($tvmRows as $row) {
    if ((string)($row['catalog_source'] ?? '') === 'csv') {
        $pendingNvd++;
    }
    if ((int)($row['report_exists'] ?? 0) > 0) {
        $rowsWithReport++;
    }
}
?>

<div class="no-print mb-4 flex items-center justify-between gap-3 flex-wrap">
    <div>
        <h2 class="text-lg font-bold">Import Organización</h2>
        <p class="text-xs text-ink-soft">
            Importa el export de vulnerabilidades de Microsoft Defender TVM, clasifícalo en un cliente
            y genera un informe de remediación por CVE.
        </p>
    </div>
    <a href="<?= base_url('modules/cve?tab=software') ?>"
       class="inline-flex items-center gap-2 px-3 py-2 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
        <i class="material-icons icon-14" aria-hidden="true">domain</i>
        Gestionar clientes
    </a>
</div>

<?php if (!$isAdmin): ?>
    <div class="card p-5">
        <p class="text-sm text-ink-muted">Solo un administrador puede importar vulnerabilidades de una organización.</p>
    </div>
<?php else: ?>

<?php if ($companyGroups === []): ?>
    <div class="mb-4 px-4 py-3 rounded-lg text-sm text-amber-700 bg-amber-50 dark:bg-amber-900/20 dark:text-amber-300">
        Todavía no hay clientes (empresas). Crea uno en <strong>Mis CVE → Empresas</strong> antes de importar.
    </div>
<?php endif; ?>

<!-- ============================================================
     Formulario de importación
     ============================================================ -->
<form method="post" action="<?= base_url('modules/cve/import/tvm') ?>" enctype="multipart/form-data"
      class="card p-5">
    <?= Csrf::field() ?>
    <div class="flex items-center gap-2 mb-4">
        <span class="inline-flex items-center justify-center w-7 h-7 rounded-lg bg-brand-100 dark:bg-brand-900/30 text-brand-600 dark:text-brand-300">
            <i class="material-icons icon-16" aria-hidden="true">upload_file</i>
        </span>
        <div>
            <h3 class="text-sm font-semibold">Importar CSV de Defender</h3>
            <p class="text-[11px] text-ink-soft">
                Vulnerabilidades → Exportar. Se aceptan hasta 5 MB y 5.000 CVEs por fichero.
            </p>
        </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
            <label for="tvm-company" class="block text-xs font-medium text-ink-muted mb-1">
                Cliente / empresa <span class="text-danger">*</span>
            </label>
            <select id="tvm-company" name="company_id" required
                    class="w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="">Selecciona un cliente…</option>
                <?php foreach ($companyGroups as $company): ?>
                    <option value="<?= (int)$company['id'] ?>" <?= $selectedCompanyId === (int)$company['id'] ? 'selected' : '' ?>>
                        <?= e((string)$company['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <p class="mt-1 text-[11px] text-ink-soft">
                Los CVEs se asignarán a este cliente y se cruzarán con su inventario de software.
            </p>
        </div>
        <div>
            <label for="tvm-file" class="block text-xs font-medium text-ink-muted mb-1">
                Fichero CSV <span class="text-danger">*</span>
            </label>
            <input id="tvm-file" type="file" name="csv" accept=".csv,.txt,text/csv" required
                   class="block w-full text-sm text-ink file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-brand-500 file:text-white file:text-xs file:font-semibold hover:file:bg-brand-600 border border-line-strong rounded-lg bg-input">
            <p class="mt-1 text-[11px] text-ink-soft">
                Columnas esperadas: Name, Severity, CVSS v3, Epss score, Related Software, Exposed Machines…
            </p>
        </div>
    </div>

    <div class="mt-4 flex items-center justify-between gap-3 flex-wrap">
        <p class="text-[11px] text-ink-soft max-w-xl">
            Los CVEs que no estén en el catálogo local se añaden con los datos del CSV.
            Después puedes completarlos desde NVD con un clic.
        </p>
        <button type="submit"
                class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-semibold rounded-lg transition-colors">
            <i class="material-icons icon-16" aria-hidden="true">cloud_upload</i>
            Importar CSV
        </button>
    </div>
</form>

<?php if ($tvmImport !== null): ?>
    <?php
    $importId = (int)$tvmImport['id'];
    $importCompany = (string)($tvmImport['company_name'] ?? 'Cliente sin asignar');
    ?>
    <!-- ============================================================
         Resultado de la importación seleccionada
         ============================================================ -->
    <div class="card mt-6 overflow-hidden">
        <div class="p-5 border-b border-line">
            <div class="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h3 class="text-sm font-semibold">Importación #<?= $importId ?> · <?= e($importCompany) ?></h3>
                    <p class="text-[11px] text-ink-soft mt-1">
                        <?= e((string)($tvmImport['filename'] ?? '')) ?>
                        · <?= e($formatDate((string)($tvmImport['created_at'] ?? ''))) ?>
                        <?php if (!empty($tvmImport['export_date'])): ?>
                            · Export del <?= e(date('d/m/Y', strtotime((string)$tvmImport['export_date'])) ?: (string)$tvmImport['export_date']) ?>
                        <?php endif; ?>
                    </p>
                </div>
                <form method="post" action="<?= base_url('modules/cve/import/delete') ?>"
                      onsubmit="return confirm('¿Eliminar esta importación? Los informes se conservan salvo que marques la casilla.');">
                    <?= Csrf::field() ?>
                    <input type="hidden" name="import_id" value="<?= $importId ?>">
                    <label class="inline-flex items-center gap-1.5 mr-2 text-[11px] text-ink-soft">
                        <input type="checkbox" name="delete_reports" value="1" class="rounded border-line-strong">
                        Borrar también informes
                    </label>
                    <button type="submit"
                            class="inline-flex items-center gap-1.5 px-2.5 py-1.5 border border-danger-border text-danger text-xs font-medium rounded-lg hover:bg-danger-bg transition-colors">
                        <i class="material-icons icon-14" aria-hidden="true">delete</i>
                        Eliminar
                    </button>
                </form>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-5 gap-2 mt-4">
                <div class="rounded-lg bg-muted px-3 py-2">
                    <p class="text-[10px] uppercase tracking-wide text-ink-soft">CVEs</p>
                    <p class="text-base font-semibold"><?= count($tvmRows) ?></p>
                </div>
                <div class="rounded-lg bg-muted px-3 py-2">
                    <p class="text-[10px] uppercase tracking-wide text-ink-soft">En catálogo</p>
                    <p class="text-base font-semibold"><?= (int)($tvmImport['rows_existing'] ?? 0) ?></p>
                </div>
                <div class="rounded-lg bg-muted px-3 py-2">
                    <p class="text-[10px] uppercase tracking-wide text-ink-soft">Añadidos del CSV</p>
                    <p class="text-base font-semibold"><?= (int)($tvmImport['rows_created'] ?? 0) ?></p>
                </div>
                <div class="rounded-lg bg-muted px-3 py-2">
                    <p class="text-[10px] uppercase tracking-wide text-ink-soft">Cruzados con inventario</p>
                    <p class="text-base font-semibold"><?= (int)($tvmImport['rows_matched'] ?? 0) ?></p>
                </div>
                <div class="rounded-lg bg-muted px-3 py-2">
                    <p class="text-[10px] uppercase tracking-wide text-ink-soft">Informes creados</p>
                    <p class="text-base font-semibold"><?= (int)($tvmImport['reports_created'] ?? 0) ?></p>
                </div>
            </div>

            <?php if ($pendingNvd > 0): ?>
                <div class="mt-3 flex items-center justify-between gap-3 flex-wrap rounded-lg border border-amber-200 dark:border-amber-900 bg-amber-50 dark:bg-amber-900/20 px-3 py-2">
                    <p class="text-[11px] text-amber-700 dark:text-amber-300">
                        <?= $pendingNvd ?> CVE(s) usan los datos del CSV. Puedes completarlos desde NVD (máx. 10 por clic).
                    </p>
                    <form method="post" action="<?= base_url('modules/cve/import/nvd') ?>">
                        <?= Csrf::field() ?>
                        <input type="hidden" name="import_id" value="<?= $importId ?>">
                        <button type="submit"
                                class="inline-flex items-center gap-1.5 px-2.5 py-1.5 border border-line-strong text-ink text-xs font-medium rounded-lg hover:bg-muted transition-colors">
                            <i class="material-icons icon-14" aria-hidden="true">cloud_download</i>
                            Completar desde NVD
                        </button>
                    </form>
                </div>
            <?php endif; ?>
        </div>

        <?php if ($tvmRows === []): ?>
            <p class="p-5 text-sm text-ink-muted">Esta importación no contiene filas.</p>
        <?php else: ?>
            <form method="post" action="<?= base_url('modules/cve/import/report') ?>" id="tvm-report-form">
                <?= Csrf::field() ?>
                <input type="hidden" name="import_id" value="<?= $importId ?>">

                <div class="p-4 border-b border-line flex items-end justify-between gap-3 flex-wrap">
                    <div class="flex items-end gap-3 flex-wrap">
                        <div>
                            <label for="tvm-mode" class="block text-xs font-medium text-ink-muted mb-1">Tipo de informe</label>
                            <select id="tvm-mode" name="mode"
                                    class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
                                <option value="extended">Extendido (remediación)</option>
                                <option value="summary">Resumen ejecutivo</option>
                            </select>
                        </div>
                        <label class="inline-flex items-center gap-2 px-3 py-2 border border-line rounded-lg text-xs text-ink">
                            <input type="checkbox" name="no_ai" value="1" class="rounded border-line-strong">
                            Solo datos locales (sin IA)
                        </label>
                    </div>
                    <div class="flex items-center gap-2">
                        <span id="tvm-selected-count" class="text-[11px] text-ink-soft"><?= count($tvmRows) ?> seleccionados</span>
                        <button type="submit"
                                class="inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-semibold rounded-lg transition-colors">
                            <i class="material-icons icon-16" aria-hidden="true">auto_awesome</i>
                            Generar informes por CVE
                        </button>
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-xs">
                        <thead class="bg-muted text-ink-muted">
                            <tr>
                                <th class="px-3 py-2 text-left w-8">
                                    <input type="checkbox" id="tvm-check-all" checked
                                           class="rounded border-line-strong" title="Seleccionar todos">
                                </th>
                                <th class="px-3 py-2 text-left">CVE</th>
                                <th class="px-3 py-2 text-left">Severidad</th>
                                <th class="px-3 py-2 text-right">CVSS</th>
                                <th class="px-3 py-2 text-right">EPSS</th>
                                <th class="px-3 py-2 text-right">Equipos</th>
                                <th class="px-3 py-2 text-left">Estado TVM</th>
                                <th class="px-3 py-2 text-left">Catálogo</th>
                                <th class="px-3 py-2 text-left">Inventario</th>
                                <th class="px-3 py-2 text-left">Informe</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-line">
                            <?php foreach ($tvmRows as $row): ?>
                                <?php
                                $cveId = (string)$row['cve_id'];
                                $severity = (string)($row['severity'] ?? '');
                                $source = (string)($row['catalog_source'] ?? 'missing');
                                $epss = $row['catalog_epss'] !== null ? (float)$row['catalog_epss'] : ($row['epss'] !== null ? (float)$row['epss'] : null);
                                $matchedIds = safe_json_decode((string)($row['matched_watchlist'] ?? ''), []);
                                $matchedCount = is_array($matchedIds) ? count($matchedIds) : 0;
                                $reportId = (int)($row['report_exists'] ?? 0);
                                ?>
                                <tr class="hover:bg-muted/50">
                                    <td class="px-3 py-2">
                                        <input type="checkbox" name="cve_ids[]" value="<?= e($cveId) ?>"
                                               class="tvm-row-check rounded border-line-strong" checked>
                                    </td>
                                    <td class="px-3 py-2">
                                        <a href="<?= base_url('modules/cve/detail/' . urlencode($cveId)) ?>"
                                           class="font-mono font-medium text-brand-600 dark:text-brand-300 hover:underline">
                                            <?= e($cveId) ?>
                                        </a>
                                        <?php if (!empty($row['kev_id'])): ?>
                                            <span class="ml-1 inline-flex items-center px-1 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 text-[9px] font-semibold">KEV</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="px-3 py-2">
                                        <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $severityClasses[$severity] ?? $severityClasses['info'] ?>">
                                            <?= e($severityLabels[$severity] ?? ($severity !== '' ? ucfirst($severity) : '—')) ?>
                                        </span>
                                    </td>
                                    <td class="px-3 py-2 text-right font-mono">
                                        <?= $row['cvss'] !== null ? number_format((float)$row['cvss'], 1) : '—' ?>
                                    </td>
                                    <td class="px-3 py-2 text-right font-mono">
                                        <?= $epss !== null ? number_format($epss, 4) : '—' ?>
                                    </td>
                                    <td class="px-3 py-2 text-right font-mono"><?= (int)($row['exposed_machines'] ?? 0) ?></td>
                                    <td class="px-3 py-2">
                                        <?= e((string)($row['tvm_status'] ?? '—')) ?>
                                        <?php if (!empty($row['has_exploit'])): ?>
                                            <span class="ml-1 inline-flex items-center px-1 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300 text-[9px] font-semibold">exploit</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="px-3 py-2">
                                        <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium <?= $catalogSourceClasses[$source] ?? $catalogSourceClasses['missing'] ?>">
                                            <?= e($catalogSourceLabels[$source] ?? $source) ?>
                                        </span>
                                    </td>
                                    <td class="px-3 py-2">
                                        <?php if ($matchedCount > 0): ?>
                                            <span class="inline-flex items-center gap-1 text-green-700 dark:text-green-300">
                                                <i class="material-icons icon-12" aria-hidden="true">check_circle</i>
                                                <?= $matchedCount ?> software
                                            </span>
                                        <?php else: ?>
                                            <span class="text-ink-soft">—</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="px-3 py-2">
                                        <?php if ($reportId > 0): ?>
                                            <a href="<?= base_url('modules/cve/report-ai/' . $reportId) ?>"
                                               class="inline-flex items-center gap-1 text-brand-600 dark:text-brand-300 hover:underline">
                                                <i class="material-icons icon-12" aria-hidden="true">description</i>
                                                Ver
                                            </a>
                                        <?php else: ?>
                                            <span class="text-ink-soft">—</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </form>
        <?php endif; ?>
    </div>
<?php endif; ?>

<!-- ============================================================
     Histórico de importaciones
     ============================================================ -->
<div class="card mt-6 overflow-hidden">
    <div class="p-5 border-b border-line">
        <h3 class="text-sm font-semibold">Importaciones recientes</h3>
        <p class="text-[11px] text-ink-soft mt-1">Cada importación queda clasificada en su cliente.</p>
    </div>
    <?php if ($tvmImports === []): ?>
        <p class="p-5 text-sm text-ink-muted">Todavía no hay importaciones.</p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="w-full text-xs">
                <thead class="bg-muted text-ink-muted">
                    <tr>
                        <th class="px-3 py-2 text-left">Fecha</th>
                        <th class="px-3 py-2 text-left">Cliente</th>
                        <th class="px-3 py-2 text-left">Fichero</th>
                        <th class="px-3 py-2 text-right">CVEs</th>
                        <th class="px-3 py-2 text-right">Cruzados</th>
                        <th class="px-3 py-2 text-right">Informes</th>
                        <th class="px-3 py-2 text-right"></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-line">
                    <?php foreach ($tvmImports as $item): ?>
                        <?php $itemId = (int)$item['id']; ?>
                        <tr class="hover:bg-muted/50 <?= ($tvmImport !== null && (int)$tvmImport['id'] === $itemId) ? 'bg-brand-50/60 dark:bg-brand-950/20' : '' ?>">
                            <td class="px-3 py-2 whitespace-nowrap"><?= e($formatDate((string)($item['created_at'] ?? ''))) ?></td>
                            <td class="px-3 py-2"><?= e((string)($item['company_name'] ?? '—')) ?></td>
                            <td class="px-3 py-2 max-w-[220px] truncate" title="<?= e((string)($item['filename'] ?? '')) ?>">
                                <?= e((string)($item['filename'] ?? '')) ?>
                            </td>
                            <td class="px-3 py-2 text-right font-mono"><?= (int)($item['rows_imported'] ?? 0) ?></td>
                            <td class="px-3 py-2 text-right font-mono"><?= (int)($item['rows_matched'] ?? 0) ?></td>
                            <td class="px-3 py-2 text-right font-mono"><?= (int)($item['reports_created'] ?? 0) ?></td>
                            <td class="px-3 py-2 text-right">
                                <a href="<?= base_url('modules/cve?tab=import&import=' . $itemId) ?>"
                                   class="inline-flex items-center gap-1 text-brand-600 dark:text-brand-300 hover:underline">
                                    Ver
                                </a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<script>
(function () {
    var all = document.getElementById('tvm-check-all');
    var checks = Array.prototype.slice.call(document.querySelectorAll('.tvm-row-check'));
    var counter = document.getElementById('tvm-selected-count');

    function refresh() {
        if (!counter) { return; }
        var selected = checks.filter(function (c) { return c.checked; }).length;
        counter.textContent = selected + ' seleccionados';
    }

    if (all) {
        all.addEventListener('change', function () {
            checks.forEach(function (c) { c.checked = all.checked; });
            refresh();
        });
    }
    checks.forEach(function (c) { c.addEventListener('change', refresh); });
    refresh();
})();
</script>

<?php endif; ?>
