<?php
/**
 * Vista: Equipos expuestos — CVEs relacionados de un CVE (sin IA).
 *
 * Tres bloques deterministas: menciones en la descripción de Defender, mismo
 * lote (software + fecha/equipos) y mismo software. Permite crear un grupo de
 * análisis o añadir la selección a uno existente.
 *
 * @var string $cveId
 * @var array $row
 * @var array $description
 * @var array $batch
 * @var array $software
 * @var array $groups
 * @var string $base
 */

$base = (string)($base ?? base_url('modules/exposed_report'));
$cveId = (string)($cveId ?? '');
$row = is_array($row ?? null) ? $row : [];
$description = is_array($description ?? null) ? $description : [];
$batch = is_array($batch ?? null) ? $batch : [];
$software = is_array($software ?? null) ? $software : [];
$groups = is_array($groups ?? null) ? $groups : [];

$sevClasses = [
    'critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'high'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'info'     => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
];
$sevLabels = [
    'critical' => 'Crítica',
    'high'     => 'Alta',
    'medium'   => 'Media',
    'low'      => 'Baja',
    'info'     => 'Informativa',
];
$fmtDate = static function (?string $value): string {
    $value = trim((string)$value);
    if ($value === '') {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('d/m/Y', $ts);
};

$totalRelated = count($description) + count($batch) + count($software);

$renderRows = static function (array $items, bool $checked, string $checkedSection) use ($sevClasses, $sevLabels, $fmtDate, $base): void {
    foreach ($items as $item) {
        $id = (string)($item['cve_id'] ?? '');
        $severity = (string)($item['severity'] ?? '');
        ?>
        <tr class="hover:bg-muted/50">
            <td class="px-3 py-2">
                <input type="checkbox" name="cve_ids[]" value="<?= e($id) ?>"
                       class="rounded border-line-strong" <?= $checked ? 'checked' : '' ?>>
            </td>
            <td class="px-3 py-2">
                <a href="<?= e($base . '/related/' . urlencode($id)) ?>"
                   class="font-mono font-medium text-brand-600 dark:text-brand-300 hover:underline">
                    <?= e($id) ?>
                </a>
            </td>
            <td class="px-3 py-2">
                <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $sevClasses[$severity] ?? $sevClasses['info'] ?>">
                    <?= e($sevLabels[$severity] ?? ($severity !== '' ? ucfirst($severity) : '—')) ?>
                </span>
            </td>
            <td class="px-3 py-2 text-right font-mono"><?= $item['cvss'] !== null ? number_format((float)$item['cvss'], 1) : '—' ?></td>
            <td class="px-3 py-2 text-right font-mono whitespace-nowrap"><?= $item['age_days'] !== null ? (int)$item['age_days'] . ' d' : '—' ?></td>
            <td class="px-3 py-2 text-right font-mono"><?= (int)($item['exposed_machines'] ?? 0) ?></td>
            <td class="px-3 py-2 whitespace-nowrap text-ink-soft"><?= e($fmtDate((string)($item['first_detected_at'] ?? ''))) ?></td>
            <td class="px-3 py-2 text-ink-muted"><?= e((string)($item['relation'] ?? $checkedSection)) ?></td>
            <td class="px-3 py-2 text-ink-muted max-w-[240px]"><?= e((string)($item['software_labels'] ?? '—')) ?></td>
        </tr>
        <?php
    }
};
?>

<div class="page-header no-print">
    <div class="min-w-0">
        <a href="<?= e($base) ?>" class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline inline-flex items-center gap-1 mb-1">
            <?= icon('arrow_back', 13) ?> Volver a la consola
        </a>
        <h1 class="truncate">CVEs relacionados · <?= e($cveId) ?></h1>
        <p class="subtitle">
            Solo con los datos importados de Defender: menciones en la descripción, mismo lote de parcheo
            y mismo software. <?= $totalRelated ?> relacionados en la base del tenant.
        </p>
    </div>
</div>

<!-- Ficha del CVE -->
<div class="card p-4 mb-5">
    <div class="flex items-start justify-between gap-3 flex-wrap">
        <div class="min-w-0">
            <p class="text-xs text-ink-soft m-0">CVE analizado</p>
            <p class="text-sm font-semibold m-0 mt-0.5">
                <span class="font-mono"><?= e($cveId) ?></span>
                <span class="ml-2 inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $sevClasses[(string)($row['severity'] ?? '')] ?? $sevClasses['info'] ?>">
                    <?= e($sevLabels[(string)($row['severity'] ?? '')] ?? '—') ?>
                </span>
                <?php if ((int)($row['has_exploit'] ?? 0) === 1): ?>
                    <span class="ml-1 inline-flex px-1 py-0.5 rounded text-[9px] font-semibold bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300">exploit</span>
                <?php endif; ?>
            </p>
            <p class="text-[11px] text-ink-soft mt-1 mb-0">
                CVSS <?= $row['cvss'] !== null ? number_format((float)$row['cvss'], 1) : '—' ?>
                · EPSS <?= $row['epss'] !== null ? number_format((float)$row['epss'], 4) : '—' ?>
                · <?= (int)($row['age_days'] ?? 0) ?> días
                · <?= (int)($row['exposed_machines'] ?? 0) ?> equipos expuestos
                · detectado <?= e($fmtDate((string)($row['first_detected_at'] ?? ''))) ?>
                · <?= e((string)($row['software_labels'] ?? '')) ?>
            </p>
        </div>
        <a href="<?= e(base_url('modules/cve/detail/' . urlencode($cveId))) ?>"
           class="btn btn-outline text-xs">
            <?= icon('open_in_new', 14) ?> Ficha del CVE
        </a>
    </div>
</div>

<form method="POST" action="<?= e($base . '/groups/create') ?>">
    <?= Csrf::field() ?>
    <input type="hidden" name="cve_ids[]" value="<?= e($cveId) ?>">

    <?php
    $sections = [
        [
            'title'    => 'Mencionados en la descripción (mismo boletín)',
            'hint'     => 'CVEs de tu base que aparecen citados en la descripción de Defender de este CVE, o que lo citan a él. Es la relación más fuerte y no depende de IA.',
            'items'    => $description,
            'checked'  => true,
            'relation' => 'cita',
        ],
        [
            'title'    => 'Mismo lote de parcheo en el tenant',
            'hint'     => 'Mismo software principal y misma fecha de detección o mismo número de equipos expuestos: se corrigen en la misma ventana.',
            'items'    => $batch,
            'checked'  => true,
            'relation' => 'mismo lote',
        ],
        [
            'title'    => 'Mismo software afectado',
            'hint'     => 'Resto de CVEs importados que afectan al mismo producto principal. Útil para agrupar un ciclo de parcheo completo.',
            'items'    => $software,
            'checked'  => false,
            'relation' => 'mismo software',
        ],
    ];
    ?>

    <?php foreach ($sections as $section): ?>
        <?php $items = (array)$section['items']; ?>
        <div class="card overflow-hidden mb-4">
            <div class="px-4 py-3 border-b border-line">
                <h2 class="text-sm font-semibold m-0">
                    <?= e((string)$section['title']) ?>
                    <span class="ml-1 text-[11px] font-normal text-ink-soft">(<?= count($items) ?>)</span>
                </h2>
                <p class="text-[11px] text-ink-soft m-0 mt-1"><?= e((string)$section['hint']) ?></p>
            </div>
            <?php if ($items === []): ?>
                <p class="p-4 text-xs text-ink-soft m-0">Sin coincidencias en la base del tenant.</p>
            <?php else: ?>
                <div class="overflow-x-auto">
                    <table class="w-full text-xs">
                        <thead class="bg-muted text-ink-muted">
                            <tr>
                                <th class="px-3 py-2 text-left w-8"></th>
                                <th class="px-3 py-2 text-left">CVE</th>
                                <th class="px-3 py-2 text-left">Severity</th>
                                <th class="px-3 py-2 text-right">CVSS</th>
                                <th class="px-3 py-2 text-right">Age</th>
                                <th class="px-3 py-2 text-right">Equipos</th>
                                <th class="px-3 py-2 text-left">Detectado</th>
                                <th class="px-3 py-2 text-left">Relación</th>
                                <th class="px-3 py-2 text-left">Software</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-line">
                            <?php $renderRows($items, (bool)$section['checked'], (string)$section['relation']); ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>

    <div class="card p-4">
        <div class="flex items-end justify-between gap-3 flex-wrap">
            <div class="flex items-end gap-3 flex-wrap">
                <div>
                    <label for="related-group-target" class="block text-[10px] uppercase tracking-wide text-ink-soft mb-1">
                        Grupo destino
                    </label>
                    <select id="related-group-target" name="group_id"
                            class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs w-64 max-w-full">
                        <option value="0">+ Crear un grupo nuevo</option>
                        <?php foreach ($groups as $groupOption): ?>
                            <option value="<?= (int)$groupOption['id'] ?>">
                                <?= e((string)($groupOption['name'] ?? ('Grupo #' . (int)$groupOption['id']))) ?>
                                (<?= (int)($groupOption['cve_count'] ?? 0) ?> CVE)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label for="related-group-name" class="block text-[10px] uppercase tracking-wide text-ink-soft mb-1">
                        Nombre del grupo nuevo
                    </label>
                    <input id="related-group-name" type="text" name="group_name" maxlength="120"
                           value="<?= e('Relacionados ' . $cveId) ?>"
                           class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs w-72 max-w-full">
                </div>
            </div>
            <div class="flex items-center gap-2">
                <button type="button" class="btn btn-outline" onclick="exposedRelatedSelectAll()">
                    Seleccionar todo
                </button>
                <button type="submit" class="btn">
                    <?= icon('group_add', 16) ?> Enviar a grupo
                </button>
            </div>
        </div>
        <p class="text-[11px] text-ink-soft mt-2 mb-0">
            El CVE analizado se añade siempre al grupo junto con los seleccionados.
        </p>
    </div>
</form>

<script>
function exposedRelatedSelectAll() {
    document.querySelectorAll('input[name="cve_ids[]"]').forEach(function (box) {
        box.checked = true;
        box.disabled = false;
    });
}
</script>
