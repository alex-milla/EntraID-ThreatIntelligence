<?php
/**
 * Vista de resultados de una búsqueda — Seguimiento TI.
 *
 * @var Module_TiTracker $module
 * @var array $search
 * @var array $exec
 * @var array $rows
 * @var int $displayLimit
 * @var array $history
 * @var array $formats
 * @var array|null $notice
 */

$base = base_url('modules/ti_tracker');
$fmt = static fn(int|float $n): string => number_format((float)$n, 0, ',', '.');
$short = static fn(?string $date): string => $date === null || trim($date) === ''
    ? '—'
    : substr(trim($date), 0, 16);

$total = (int)($exec['result']['rows'] ?? 0);
$newCount = (int)($exec['result']['new'] ?? 0);
$tracked = (int)($exec['result']['tracked'] ?? 0);
$source = ((string)($exec['source'] ?? 'db')) === 'api' ? 'API en vivo' : 'Base local';

$newKeys = [];
foreach ((array)($exec['result']['new_iocs'] ?? []) as $ioc) {
    $newKeys[(string)$ioc] = true;
}

$describe = static function (array $f): string {
    $bits = [];
    $bits[] = ($f['source'] ?? 'db') === 'api' ? 'API' : 'BBDD';
    if (($f['mode'] ?? 'auto') !== 'auto') {
        $bits[] = (string)$f['mode'];
    }
    if (($f['term'] ?? '') !== '') {
        $bits[] = '«' . (string)$f['term'] . '»';
    }
    if ((int)($f['days'] ?? 0) > 0) {
        $bits[] = (int)$f['days'] . ' d';
    }
    if (($f['ioc_type'] ?? '') !== '') {
        $bits[] = (string)$f['ioc_type'];
    }
    if (($f['threat_type'] ?? '') !== '') {
        $bits[] = (string)$f['threat_type'];
    }
    if (($f['malware'] ?? '') !== '') {
        $bits[] = (string)$f['malware'];
    }
    if (($f['tag'] ?? '') !== '') {
        $bits[] = '#' . (string)$f['tag'];
    }
    if ((int)($f['conf'] ?? 0) > 0) {
        $bits[] = 'conf ≥ ' . (int)$f['conf'];
    }
    if (!empty($f['ref_only'])) {
        $bits[] = 'con referencia';
    }

    return implode(' · ', $bits);
};

$formatsForSearch = array_values(array_intersect(array_keys($formats), (array)$search['formats']));
?>

<?php if (!empty($notice) && is_array($notice)): ?>
    <div class="alert alert-<?= e((string)($notice['type'] ?? 'info')) ?>" role="status">
        <?= e((string)($notice['text'] ?? '')) ?>
    </div>
<?php endif; ?>

<div class="page-header">
    <h1><?= e((string)$search['name']) ?></h1>
    <p class="subtitle"><?= e($describe($search['filters'])) ?></p>
    <span class="spacer"></span>
    <?php foreach ($formatsForSearch as $format): ?>
        <button type="button" class="btn-outline btn"
                data-tt-export="<?= e($format) ?>"
                data-tt-url="<?= e($base . '/export/' . (int)$search['id']) ?>">
            <?= icon('download', 18) ?> <?= e(strtoupper($format)) ?>
        </button>
    <?php endforeach; ?>
    <a class="btn-flat btn" href="<?= e($base . '/edit/' . (int)$search['id']) ?>">
        <?= icon('edit', 18) ?> Editar
    </a>
    <a class="btn-flat btn" href="<?= e($base) ?>">
        <?= icon('arrow_back', 18) ?> Volver
    </a>
</div>

<div class="stat-strip">
    <div class="stat">
        <span class="stat-ico"><?= icon('search', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt($total) ?></div>
            <div class="stat-label">IOCs en esta ejecución</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico <?= $newCount > 0 ? 'ok' : '' ?>"><?= icon('new_releases', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt($newCount) ?></div>
            <div class="stat-label">Novedades</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico"><?= icon('track_changes', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt($tracked) ?></div>
            <div class="stat-label">IOCs en seguimiento</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico"><?= icon('storage', 18) ?></span>
        <div>
            <div class="stat-num text-base"><?= e($source) ?></div>
            <div class="stat-label">Fuente consultada</div>
        </div>
    </div>
</div>

<?php if ($newCount > 0): ?>
    <div class="alert alert-success mt-4" role="status">
        <strong><?= $fmt($newCount) ?> IOCs nuevos</strong> desde la última ejecución de esta búsqueda.
        Puedes exportarlos a STIX, MISP o TXT con los botones de arriba.
    </div>
<?php elseif ($total > 0): ?>
    <div class="alert alert-info mt-4" role="status">
        Sin novedades: los <?= $fmt($total) ?> IOCs de esta ejecución ya estaban en el seguimiento.
    </div>
<?php endif; ?>

<div class="card p-0 mt-6 overflow-hidden">
    <div class="overflow-x-auto">
        <table class="data-table w-full">
            <thead>
                <tr>
                    <th>IOC</th>
                    <th>Tipo</th>
                    <th>Conf.</th>
                    <th class="col-secondary">Primera vez</th>
                    <th class="text-right">Estado</th>
                </tr>
            </thead>
            <tbody>
            <?php if ($rows === []): ?>
                <tr>
                    <td colspan="5" class="text-sm text-ink-muted">
                        La búsqueda no devuelve IOCs ahora mismo. Revisa los filtros o espera a la próxima ingesta.
                    </td>
                </tr>
            <?php else: ?>
                <?php foreach ($rows as $row):
                    $ioc = (string)($row['ioc'] ?? '');
                    $isNew = isset($newKeys[$ioc]);
                    ?>
                    <tr>
                        <td class="font-mono break-all"><?= e($ioc) ?></td>
                        <td><?= e((string)($row['ioc_type'] ?? '')) ?></td>
                        <td><?= (int)($row['confidence_level'] ?? 0) ?></td>
                        <td class="col-secondary whitespace-nowrap text-xs"><?= e((string)($row['first_seen'] ?? '')) ?></td>
                        <td class="text-right whitespace-nowrap">
                            <?php if ($isNew): ?>
                                <span class="tag-chip good">Nuevo</span>
                            <?php else: ?>
                                <span class="tag-chip excluded">Ya visto</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php if ($total > $displayLimit): ?>
    <p class="text-sm text-ink-muted mt-2">
        Mostrando los primeros <?= $fmt($displayLimit) ?> de <?= $fmt($total) ?> IOCs.
        La exportación incluye el conjunto completo (máximo <?= $fmt((int)TI_TRACKER_MAX_ROWS) ?>).
    </p>
<?php endif; ?>

<div class="card mt-6">
    <div class="card-head">
        <h2>Historial reciente</h2>
    </div>
    <div class="overflow-x-auto">
        <table class="data-table w-full">
            <thead>
                <tr>
                    <th>Fecha</th>
                    <th>Tipo</th>
                    <th>Filas</th>
                    <th>Novedades</th>
                    <th class="col-secondary">Detalle</th>
                </tr>
            </thead>
            <tbody>
            <?php if ($history === []): ?>
                <tr>
                    <td colspan="5" class="text-sm text-ink-muted">Sin actividad registrada.</td>
                </tr>
            <?php else: ?>
                <?php foreach ($history as $item):
                    $isRun = (string)$item['kind'] === 'run';
                    $detail = (string)($item['detail'] ?? '');
                    if (str_contains($detail, '|')) {
                        $detail = (string)str_replace('|', ' · ', $detail);
                    }
                    ?>
                    <tr>
                        <td class="whitespace-nowrap text-xs"><?= e($short((string)$item['created_at'])) ?></td>
                        <td><?= $isRun ? 'Ejecución' : 'Exportación' ?></td>
                        <td><?= $fmt((int)$item['rows']) ?></td>
                        <td>
                            <?php if ($isRun && (int)$item['new_rows'] > 0): ?>
                                <span class="tag-chip good">+<?= $fmt((int)$item['new_rows']) ?></span>
                            <?php else: ?>
                                <span class="text-ink-muted">—</span>
                            <?php endif; ?>
                        </td>
                        <td class="col-secondary text-xs text-ink-muted"><?= e($detail) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<script>
(function () {
    'use strict';
    if (window.__tiTrackerExportBound) { return; }
    window.__tiTrackerExportBound = true;

    document.addEventListener('click', function (event) {
        var button = event.target.closest('[data-tt-export]');
        if (!button) { return; }

        var format = button.getAttribute('data-tt-export');
        var url = button.getAttribute('data-tt-url');
        button.disabled = true;
        toast('Generando exportación ' + format.toUpperCase() + '…', 'info');

        api('POST', url, { format: format })
            .then(function (res) {
                if (!res.success) {
                    toast('Error: ' + (res.error || 'no se pudo generar la exportación'), 'error');
                    return;
                }
                (res.files || []).forEach(function (file) {
                    downloadFile(file.content, file.filename, file.mime);
                });
                toast('Descargados ' + (res.count || 0) + ' IOCs', 'success');
            })
            .catch(function (err) {
                toast('Error al exportar: ' + (err && err.message ? err.message : 'conexión'), 'error');
            })
            .then(function () {
                button.disabled = false;
            });
    });
})();
</script>
