<?php
/**
 * Parcial: consola de Equipos expuestos (v0.4.25).
 *
 * Vista de los filtros tipo portal de Defender sobre el snapshot del export
 * completo de TVM, la tabla de resultados y la creación de grupos de análisis.
 *
 * @var array $console
 * @var Module_ExposedReport $module
 * @var array $profiles
 */

$console = is_array($console ?? null) ? $console : [];
$snapshots = is_array($console['snapshots'] ?? null) ? $console['snapshots'] : [];
$snapshot = is_array($console['snapshot'] ?? null) ? $console['snapshot'] : null;
$snapshotId = (int)($console['snapshotId'] ?? 0);
$filters = is_array($console['filters'] ?? null) ? $console['filters'] : [];
$filterQuery = is_array($console['filterQuery'] ?? null) ? $console['filterQuery'] : [];
$rows = is_array($console['rows'] ?? null) ? $console['rows'] : [];
$stats = is_array($console['stats'] ?? null) ? $console['stats'] : null;
$facets = is_array($console['facets'] ?? null) ? $console['facets'] : [];
$groups = is_array($console['groups'] ?? null) ? $console['groups'] : [];
$counts = is_array($console['counts'] ?? null) ? $console['counts'] : ['total' => 0];
$total = (int)($console['total'] ?? 0);
$page = (int)($console['page'] ?? 1);
$pages = (int)($console['pages'] ?? 1);
$perPage = (int)($console['perPage'] ?? 100);

$base = base_url('modules/exposed_report');

$sevLabels = [
    'critical' => 'Crítica',
    'high'     => 'Alta',
    'medium'   => 'Media',
    'low'      => 'Baja',
    'info'     => 'Informativa',
];
$sevClasses = [
    'critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'high'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'info'     => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
];
$ageLabels = [
    '0-30'  => '0-30 days',
    '30-60' => '30-60 days',
    '60-90' => '60-90 days',
    '90+'   => '90 or more days',
];
$threatLabels = [
    'alert'    => 'Associated active alert',
    'exploit'  => 'Exploit is available',
    'known'    => 'Known threats',
    'verified' => 'Exploit is verified (description)',
    'kev'      => 'CISA KEV',
    'kit'      => 'Part of an exploit kit',
];
$tagLabels = [
    'zero_day'           => 'Zero-day (inferred)',
    'no_security_update' => 'No security update (inferred)',
    'security_update'    => 'Security update mentioned (inferred)',
];
$statusLabels = [
    'RemediationRequired' => 'Remediation required',
    'UnderException'      => 'Under exception',
    'NoActionRequired'    => 'No action required',
    'PartialException'    => 'Partial exception',
];

$machineOptions = [
    0   => 'All devices',
    10  => '>= 10 exposed devices',
    100 => '>= 100 exposed devices',
    500 => '>= 500 exposed devices',
];
$sortOptions = [
    'oldest'   => 'Más antiguo a más nuevo (Age desc)',
    'newest'   => 'Más nuevo a más antiguo (Age asc)',
    'machines' => 'Más equipos expuestos',
    'cvss'     => 'Mayor CVSS',
    'epss'     => 'Mayor EPSS',
];

$consoleUrl = static function (array $extra = []) use ($base, $snapshotId, $filterQuery): string {
    $query = array_merge(['snapshot' => $snapshotId], $filterQuery, $extra);
    return $base . '?' . http_build_query($query);
};
$fmtDate = static function (?string $value): string {
    $value = trim((string)$value);
    if ($value === '') {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('d/m/Y', $ts);
};

$flashData = function_exists('flash') ? flash() : [];
$flashData = is_array($flashData) ? $flashData : [];
?>

<div class="space-y-6">

    <?php foreach (['success' => 'alert-success', 'error' => 'alert-error', 'info' => 'alert-info', 'warning' => 'alert-warning'] as $flashKey => $flashClass): ?>
        <?php if (!empty($flashData[$flashKey])): ?>
            <div class="alert <?= $flashClass ?> no-print" role="status"><?= e((string)$flashData[$flashKey]) ?></div>
        <?php endif; ?>
    <?php endforeach; ?>

    <!-- ============================================================
         Carga del export completo
         ============================================================ -->
    <div class="card p-5">
        <div class="flex items-start justify-between gap-3 flex-wrap">
            <div class="min-w-0">
                <h2 class="text-sm font-semibold m-0">Cargar el export del tenant</h2>
                <p class="text-xs text-ink-muted mt-1 mb-0 max-w-2xl">
                    En <strong>Defender → Vulnerability management → Vulnerabilities</strong>, filtra por
                    <em>Exposed devices → Affects my organization</em> y pulsa <em>Export</em>. Sube aquí el
                    CSV completo: se guarda como snapshot y podrás filtrarlo en pantalla sin volver a subirlo.
                    Hasta <?= e((string)($console['maxBytesLabel'] ?? '30 MB')) ?> y
                    <?= (int)($console['maxRowsConsole'] ?? 20000) ?> CVE.
                    <?php if (!empty($console['iniLimited'])): ?>
                        <span class="block mt-1 text-amber-700 dark:text-amber-300">
                            El límite lo impone <code class="font-mono">php.ini</code> (post_max_size / upload_max_filesize).
                            Para subir el export completo, súbelo a 32 MB o más.
                        </span>
                    <?php endif; ?>
                </p>
            </div>
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-muted text-[11px] text-ink-muted">
                <i class="material-icons icon-14" aria-hidden="true">database</i>
                Snapshot en cve.sqlite
            </span>
        </div>

        <form method="POST" action="<?= e($base . '/upload') ?>" enctype="multipart/form-data"
              class="mt-4 grid grid-cols-1 md:grid-cols-[1fr_auto] gap-3 items-end">
            <?= Csrf::field() ?>
            <div>
                <label for="exposed-csv" class="block text-xs font-medium text-ink-muted mb-1">
                    CSV «Vulnerabilities Export» de Defender TVM
                </label>
                <input id="exposed-csv" type="file" name="csv" accept=".csv,.txt,text/csv,text/plain" required
                       class="block w-full text-sm text-ink file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-brand-500 file:text-white file:text-xs file:font-semibold hover:file:bg-brand-600 border border-line-strong rounded-lg bg-input">
            </div>
            <button type="submit" class="btn">
                <?= icon('cloud_upload', 16) ?> Importar snapshot
            </button>
        </form>
    </div>

<?php if ($snapshot !== null): ?>

    <!-- ============================================================
         Snapshot activo
         ============================================================ -->
    <div class="card p-4">
        <div class="flex items-start justify-between gap-3 flex-wrap">
            <div class="min-w-0">
                <p class="text-xs text-ink-soft m-0">Snapshot activo</p>
                <p class="text-sm font-semibold m-0 mt-0.5 truncate" title="<?= e((string)($snapshot['filename'] ?? '')) ?>">
                    #<?= (int)$snapshot['id'] ?> · <?= e((string)($snapshot['filename'] ?? '')) ?>
                </p>
                <p class="text-[11px] text-ink-soft mt-1 mb-0">
                    Export del <?= e($fmtDate((string)($snapshot['export_date'] ?? ''))) ?>
                    · importado el <?= e($fmtDate((string)($snapshot['created_at'] ?? ''))) ?>
                    · <?= (int)($snapshot['rows_imported'] ?? 0) ?> CVE
                    <?php if ((int)($snapshot['rows_skipped'] ?? 0) > 0): ?>
                        · <?= (int)$snapshot['rows_skipped'] ?> descartados
                    <?php endif; ?>
                    · <?= e(ExposedConsoleStore::formatBytes((int)($snapshot['bytes'] ?? 0))) ?>
                </p>
            </div>
            <div class="flex items-end gap-2 flex-wrap">
                <?php if (count($snapshots) > 1): ?>
                    <form method="GET" action="<?= e($base) ?>" class="flex items-end gap-2">
                        <div>
                            <label for="exposed-snapshot" class="block text-[10px] uppercase tracking-wide text-ink-soft mb-1">Otro snapshot</label>
                            <select id="exposed-snapshot" name="snapshot" onchange="this.form.submit()"
                                    class="px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                                <?php foreach ($snapshots as $item): ?>
                                    <option value="<?= (int)$item['id'] ?>" <?= (int)$item['id'] === $snapshotId ? 'selected' : '' ?>>
                                        #<?= (int)$item['id'] ?> · <?= e($fmtDate((string)($item['created_at'] ?? ''))) ?> · <?= (int)($item['rows_imported'] ?? 0) ?> CVE
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </form>
                <?php endif; ?>
                <form method="POST" action="<?= e($base . '/snapshot/delete') ?>"
                      onsubmit="return confirm('¿Eliminar este snapshot? Los grupos que lo usan deben borrarse antes.');">
                    <?= Csrf::field() ?>
                    <input type="hidden" name="snapshot_id" value="<?= $snapshotId ?>">
                    <button type="submit"
                            class="inline-flex items-center gap-1.5 px-2.5 py-1.5 border border-danger-border text-danger text-xs font-medium rounded-lg hover:bg-danger-bg transition-colors">
                        <?= icon('delete', 14) ?> Eliminar
                    </button>
                </form>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-1 xl:grid-cols-[300px_minmax(0,1fr)] gap-5 items-start">

        <!-- ========================================================
             Panel de filtros (equivalente al de Defender)
             ==================================================== -->
        <form method="GET" action="<?= e($base) ?>" id="exposed-filters"
              class="card p-4 space-y-4 xl:sticky xl:top-4">
            <input type="hidden" name="snapshot" value="<?= $snapshotId ?>">

            <div class="flex items-center justify-between gap-2">
                <h2 class="text-sm font-bold m-0 inline-flex items-center gap-1.5">
                    <?= icon('filter_alt', 16) ?> Filter
                </h2>
                <a href="<?= e($base . '?snapshot=' . $snapshotId) ?>"
                   class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline inline-flex items-center gap-1">
                    <?= icon('filter_alt_off', 13) ?> Clear filters
                </a>
            </div>

            <?php
            $blocks = [
                'severity' => ['title' => 'Severity', 'options' => $sevLabels, 'values' => (array)($filters['severity'] ?? [])],
                'age'      => ['title' => 'Age', 'options' => $ageLabels, 'values' => (array)($filters['age'] ?? [])],
                'threats'  => ['title' => 'Threats', 'options' => $threatLabels, 'values' => (array)($filters['threats'] ?? [])],
                'tags'     => ['title' => 'Tags', 'options' => $tagLabels, 'values' => (array)($filters['tags'] ?? [])],
                'status'   => ['title' => 'Status', 'options' => $statusLabels, 'values' => (array)($filters['status'] ?? [])],
            ];
            foreach ($blocks as $key => $block):
                $countsForBlock = is_array($facets[$key] ?? null) ? $facets[$key] : [];
                ?>
                <fieldset class="border-0 p-0 m-0">
                    <legend class="text-xs font-semibold text-ink mb-1.5"><?= e($block['title']) ?></legend>
                    <div class="space-y-1">
                        <?php foreach ($block['options'] as $value => $label): ?>
                            <?php $checked = in_array((string)$value, array_map('strval', $block['values']), true); ?>
                            <label class="flex items-center gap-2 text-xs text-ink-muted cursor-pointer hover:text-ink">
                                <input type="checkbox" name="<?= e($key) ?>[]" value="<?= e((string)$value) ?>"
                                       <?= $checked ? 'checked' : '' ?>
                                       class="rounded border-line-strong">
                                <span class="flex-1"><?= e((string)$label) ?></span>
                                <span class="text-[10px] text-ink-soft tabular-nums"><?= (int)($countsForBlock[$value] ?? 0) ?></span>
                            </label>
                        <?php endforeach; ?>
                    </div>
                </fieldset>
            <?php endforeach; ?>

            <fieldset class="border-0 p-0 m-0">
                <legend class="text-xs font-semibold text-ink mb-1.5">Exposed devices</legend>
                <div class="space-y-1">
                    <?php foreach ($machineOptions as $value => $label): ?>
                        <label class="flex items-center gap-2 text-xs text-ink-muted cursor-pointer hover:text-ink">
                            <input type="radio" name="machines" value="<?= (int)$value ?>"
                                   <?= (int)($filters['machines'] ?? 0) === (int)$value ? 'checked' : '' ?>>
                            <span><?= e($label) ?></span>
                        </label>
                    <?php endforeach; ?>
                </div>
                <p class="text-[10px] text-ink-soft mt-1 mb-0">
                    El export ya viene filtrado por «Affects my organization».
                </p>
            </fieldset>

            <div>
                <label for="exposed-software" class="block text-xs font-semibold text-ink mb-1">Software</label>
                <input id="exposed-software" type="search" name="software"
                       value="<?= e((string)($filters['software'] ?? '')) ?>"
                       placeholder="chrome, kernel, edge…"
                       class="w-full px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            </div>

            <div>
                <label for="exposed-q" class="block text-xs font-semibold text-ink mb-1">CVE</label>
                <input id="exposed-q" type="search" name="q"
                       value="<?= e((string)($filters['q'] ?? '')) ?>"
                       placeholder="CVE-2026-"
                       class="w-full px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs focus:ring-2 focus:ring-brand-500 outline-none">
            </div>

            <div>
                <label for="exposed-sort" class="block text-xs font-semibold text-ink mb-1">Orden</label>
                <select id="exposed-sort" name="sort" onchange="this.form.submit()"
                        class="w-full px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                    <?php foreach ($sortOptions as $value => $label): ?>
                        <option value="<?= e($value) ?>" <?= (string)($filters['sort'] ?? 'oldest') === $value ? 'selected' : '' ?>>
                            <?= e($label) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <button type="submit" class="btn w-full justify-center">
                <?= icon('check', 16) ?> Apply filters
            </button>
        </form>

        <!-- ========================================================
             Resultados
             ==================================================== -->
        <div class="space-y-4 min-w-0">

            <?php if ($stats !== null): ?>
                <div class="stat-strip">
                    <div class="stat">
                        <span class="stat-ico"><i class="material-icons icon-18" aria-hidden="true">bug_report</i></span>
                        <div class="min-w-0">
                            <p class="stat-num"><?= (int)$stats['total'] ?></p>
                            <p class="stat-label">CVE del filtro · <?= (int)$counts['total'] ?> en el snapshot</p>
                        </div>
                    </div>
                    <div class="stat">
                        <span class="stat-ico warn"><i class="material-icons icon-18" aria-hidden="true">warning</i></span>
                        <div class="min-w-0">
                            <p class="stat-num"><?= (int)$stats['critical'] ?></p>
                            <p class="stat-label">Críticas · <?= (int)$stats['high'] ?> altas</p>
                        </div>
                    </div>
                    <div class="stat">
                        <span class="stat-ico alert"><i class="material-icons icon-18" aria-hidden="true">bolt</i></span>
                        <div class="min-w-0">
                            <p class="stat-num"><?= (int)$stats['exploitable'] ?></p>
                            <p class="stat-label">Con exploit · <?= (int)$stats['threats'] ?> con amenazas</p>
                        </div>
                    </div>
                    <div class="stat">
                        <span class="stat-ico info"><i class="material-icons icon-18" aria-hidden="true">dns</i></span>
                        <div class="min-w-0">
                            <p class="stat-num"><?= (int)$stats['machines_max'] ?></p>
                            <p class="stat-label">Máx. equipos expuestos · <?= (int)$stats['older90'] ?> con +90 días</p>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <form method="POST" action="<?= e($base . '/groups/create') ?>" id="exposed-group-form">
                <?= Csrf::field() ?>
                <input type="hidden" name="snapshot_id" value="<?= $snapshotId ?>">
                <?php foreach ($filterQuery as $key => $value): ?>
                    <?php foreach ((array)$value as $item): ?>
                        <input type="hidden" name="<?= e((string)$key) ?>[]" value="<?= e((string)$item) ?>">
                    <?php endforeach; ?>
                <?php endforeach; ?>
                <input type="hidden" name="sort" value="<?= e((string)($filters['sort'] ?? 'oldest')) ?>">
                <input type="hidden" name="select_all" id="exposed-select-all-flag" value="0">

                <div class="card overflow-hidden">
                    <div class="px-4 py-3 border-b border-line flex items-center justify-between gap-3 flex-wrap">
                        <div class="min-w-0">
                            <h2 class="text-sm font-semibold m-0">Vulnerabilidades del tenant</h2>
                            <p class="text-[11px] text-ink-soft m-0 mt-0.5">
                                <?= $total ?> CVE · página <?= $page ?> de <?= $pages ?>
                                · elige filas y crea un grupo para analizarlo con IA
                            </p>
                        </div>
                        <label class="inline-flex items-center gap-2 text-xs text-ink-muted">
                            <input type="checkbox" id="exposed-check-all" class="rounded border-line-strong"
                                   onchange="exposedToggleAll(this)">
                            Seleccionar página
                        </label>
                    </div>

                    <?php if ($rows === []): ?>
                        <p class="p-6 text-sm text-ink-muted m-0">
                            Ningún CVE cumple el filtro actual.
                            <a class="underline" href="<?= e($base . '?snapshot=' . $snapshotId) ?>">Quitar filtros</a>.
                        </p>
                    <?php else: ?>
                        <div class="overflow-x-auto">
                            <table class="w-full text-xs">
                                <thead class="bg-muted text-ink-muted">
                                    <tr>
                                        <th class="px-3 py-2 text-left w-8"></th>
                                        <th class="px-3 py-2 text-left">CVE</th>
                                        <th class="px-3 py-2 text-left">Severity</th>
                                        <th class="px-3 py-2 text-right">CVSS</th>
                                        <th class="px-3 py-2 text-right">EPSS</th>
                                        <th class="px-3 py-2 text-right">Age</th>
                                        <th class="px-3 py-2 text-left">Detectado</th>
                                        <th class="px-3 py-2 text-right">Equipos</th>
                                        <th class="px-3 py-2 text-left">Threats / Tags</th>
                                        <th class="px-3 py-2 text-left">Software</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-line">
                                    <?php foreach ($rows as $row): ?>
                                        <?php
                                        $cveId = (string)($row['cve_id'] ?? '');
                                        $severity = (string)($row['severity'] ?? '');
                                        $badges = [];
                                        if ((int)($row['has_exploit'] ?? 0) === 1) {
                                            $badges[] = ['exploit', 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'];
                                        }
                                        if ((int)($row['has_known_threats'] ?? 0) === 1) {
                                            $badges[] = ['threat', 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'];
                                        }
                                        if ((int)($row['has_alerts'] ?? 0) === 1) {
                                            $badges[] = ['alert', 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'];
                                        }
                                        if ((int)($row['zero_day'] ?? 0) === 1) {
                                            $badges[] = ['zero-day', 'bg-fuchsia-100 text-fuchsia-700 dark:bg-fuchsia-900/30 dark:text-fuchsia-300'];
                                        }
                                        if ((int)($row['security_update'] ?? 0) === 1) {
                                            $badges[] = ['upd', 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'];
                                        }
                                        if ((int)($row['no_security_update'] ?? 0) === 1) {
                                            $badges[] = ['no upd', 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'];
                                        }
                                        ?>
                                        <tr class="hover:bg-muted/50">
                                            <td class="px-3 py-2">
                                                <input type="checkbox" name="cve_ids[]" value="<?= e($cveId) ?>"
                                                       class="exposed-row-check rounded border-line-strong">
                                            </td>
                                            <td class="px-3 py-2">
                                                <a href="<?= e(base_url('modules/cve/detail/' . urlencode($cveId))) ?>"
                                                   class="font-mono font-medium text-brand-600 dark:text-brand-300 hover:underline">
                                                    <?= e($cveId) ?>
                                                </a>
                                            </td>
                                            <td class="px-3 py-2">
                                                <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $sevClasses[$severity] ?? $sevClasses['info'] ?>">
                                                    <?= e($sevLabels[$severity] ?? ($severity !== '' ? ucfirst($severity) : '—')) ?>
                                                </span>
                                            </td>
                                            <td class="px-3 py-2 text-right font-mono">
                                                <?= $row['cvss'] !== null ? number_format((float)$row['cvss'], 1) : '—' ?>
                                            </td>
                                            <td class="px-3 py-2 text-right font-mono">
                                                <?= $row['epss'] !== null ? number_format((float)$row['epss'], 4) : '—' ?>
                                            </td>
                                            <td class="px-3 py-2 text-right font-mono whitespace-nowrap">
                                                <?= $row['age_days'] !== null ? (int)$row['age_days'] . ' d' : '—' ?>
                                            </td>
                                            <td class="px-3 py-2 whitespace-nowrap text-ink-soft">
                                                <?= e($fmtDate((string)($row['first_detected_at'] ?? ''))) ?>
                                            </td>
                                            <td class="px-3 py-2 text-right font-mono"><?= (int)($row['exposed_machines'] ?? 0) ?></td>
                                            <td class="px-3 py-2">
                                                <div class="flex flex-wrap gap-1">
                                                    <?php if ($badges === []): ?>
                                                        <span class="text-ink-soft">—</span>
                                                    <?php else: ?>
                                                        <?php foreach ($badges as [$label, $class]): ?>
                                                            <span class="inline-flex px-1 py-0.5 rounded text-[9px] font-semibold <?= $class ?>"><?= e($label) ?></span>
                                                        <?php endforeach; ?>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                            <td class="px-3 py-2 max-w-[240px]">
                                                <span class="text-ink-muted" title="<?= e((string)($row['related_software'] ?? '')) ?>">
                                                    <?= e((string)($row['software_labels'] ?? '—')) ?>
                                                </span>
                                                <?php if ((int)($row['software_total'] ?? 0) > 6): ?>
                                                    <span class="text-[10px] text-ink-soft">+<?= (int)$row['software_total'] - 6 ?></span>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>

                    <?php if ($rows !== []): ?>
                        <div class="px-4 py-3 border-t border-line flex items-end justify-between gap-3 flex-wrap bg-muted/40">
                            <div class="flex items-end gap-3 flex-wrap">
                                <div>
                                    <label for="exposed-group-name" class="block text-[10px] uppercase tracking-wide text-ink-soft mb-1">
                                        Nuevo grupo de análisis
                                    </label>
                                    <input id="exposed-group-name" type="text" name="group_name" maxlength="120"
                                           placeholder="Ej.: Críticos +90 días con exploit"
                                           class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs w-72 max-w-full">
                                </div>
                                <label class="inline-flex items-center gap-2 text-[11px] text-ink-muted pb-2">
                                    <input type="checkbox" id="exposed-select-all" class="rounded border-line-strong"
                                           onchange="exposedSelectAllFiltered(this)">
                                    Incluir los <?= $total ?> CVE del filtro actual
                                </label>
                            </div>
                            <div class="flex items-center gap-2">
                                <span id="exposed-selected-count" class="text-[11px] text-ink-soft">0 seleccionados</span>
                                <button type="submit" class="btn">
                                    <?= icon('group_add', 16) ?> Crear grupo
                                </button>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($pages > 1): ?>
                <div class="flex items-center justify-between gap-3 flex-wrap">
                    <p class="text-[11px] text-ink-soft m-0">
                        Mostrando <?= count($rows) ?> de <?= $total ?> CVE
                    </p>
                    <div class="flex items-center gap-1">
                        <?php if ($page > 1): ?>
                            <a href="<?= e($consoleUrl(['page' => 1])) ?>" class="btn btn-outline text-xs">«</a>
                            <a href="<?= e($consoleUrl(['page' => $page - 1])) ?>" class="btn btn-outline text-xs">Anterior</a>
                        <?php endif; ?>
                        <span class="px-2 text-xs text-ink-muted"><?= $page ?> / <?= $pages ?></span>
                        <?php if ($page < $pages): ?>
                            <a href="<?= e($consoleUrl(['page' => $page + 1])) ?>" class="btn btn-outline text-xs">Siguiente</a>
                            <a href="<?= e($consoleUrl(['page' => $pages])) ?>" class="btn btn-outline text-xs">»</a>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>

<?php endif; ?>

    <!-- ============================================================
         Grupos de análisis
         ============================================================ -->
    <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-line">
            <h2 class="text-sm font-semibold m-0">Grupos de análisis</h2>
            <p class="text-[11px] text-ink-soft m-0 mt-1">
                Cada grupo guarda los CVE que seleccionaste y su contexto TVM. Desde su ficha se generan
                los informes por CVE y el plan de actuación documentado.
            </p>
        </div>
        <?php if ($groups === []): ?>
            <p class="p-5 text-sm text-ink-muted m-0">
                Todavía no hay grupos. Filtra, selecciona los CVE que te interesen y pulsa
                <strong>Crear grupo</strong>.
            </p>
        <?php else: ?>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead class="bg-muted text-ink-muted">
                        <tr>
                            <th class="px-3 py-2 text-left">Grupo</th>
                            <th class="px-3 py-2 text-left">Snapshot</th>
                            <th class="px-3 py-2 text-right">CVE</th>
                            <th class="px-3 py-2 text-left">Plan de actuación</th>
                            <th class="px-3 py-2 text-left">Creado</th>
                            <th class="px-3 py-2"></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-line">
                        <?php foreach ($groups as $group): ?>
                            <?php $gid = (int)$group['id']; ?>
                            <tr class="hover:bg-muted/50">
                                <td class="px-3 py-2">
                                    <a href="<?= e($base . '/group/' . $gid) ?>"
                                       class="font-medium text-brand-600 dark:text-brand-300 hover:underline">
                                        <?= e((string)($group['name'] ?? ('Grupo #' . $gid))) ?>
                                    </a>
                                </td>
                                <td class="px-3 py-2 text-ink-soft">
                                    <?= !empty($group['filename']) ? e((string)$group['filename']) : '—' ?>
                                </td>
                                <td class="px-3 py-2 text-right font-mono"><?= (int)($group['cve_count'] ?? 0) ?></td>
                                <td class="px-3 py-2">
                                    <?php if (!empty($group['plan_generated_at'])): ?>
                                        <span class="inline-flex items-center gap-1 text-green-700 dark:text-green-300">
                                            <?= icon('check_circle', 13) ?>
                                            <?= e(date('d/m/Y H:i', strtotime((string)$group['plan_generated_at'])) ?: (string)$group['plan_generated_at']) ?>
                                        </span>
                                    <?php else: ?>
                                        <span class="text-ink-soft">Sin generar</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-3 py-2 text-ink-soft whitespace-nowrap">
                                    <?= e($fmtDate((string)($group['created_at'] ?? ''))) ?>
                                </td>
                                <td class="px-3 py-2 text-right">
                                    <a href="<?= e($base . '/group/' . $gid) ?>" class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline">
                                        Abrir
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>

<script>
(function () {
    function countSelected() {
        var checks = document.querySelectorAll('.exposed-row-check:checked');
        var label = document.getElementById('exposed-selected-count');
        if (label) {
            label.textContent = checks.length + ' seleccionados';
        }
        var flag = document.getElementById('exposed-select-all-flag');
        var all = document.getElementById('exposed-select-all');
        if (flag && all) {
            flag.value = all.checked ? '1' : '0';
        }
    }

    window.exposedToggleAll = function (source) {
        document.querySelectorAll('.exposed-row-check').forEach(function (box) {
            box.checked = source.checked;
        });
        var master = document.getElementById('exposed-select-all');
        if (!source.checked && master) {
            master.checked = false;
        }
        countSelected();
    };

    window.exposedSelectAllFiltered = function (source) {
        var flag = document.getElementById('exposed-select-all-flag');
        if (flag) {
            flag.value = source.checked ? '1' : '0';
        }
        if (source.checked) {
            var master = document.getElementById('exposed-check-all');
            if (master) {
                master.checked = true;
            }
            document.querySelectorAll('.exposed-row-check').forEach(function (box) {
                box.checked = true;
            });
        }
        countSelected();
    };

    document.addEventListener('change', function (event) {
        if (event.target && event.target.classList.contains('exposed-row-check')) {
            countSelected();
        }
    });

    countSelected();
})();
</script>
