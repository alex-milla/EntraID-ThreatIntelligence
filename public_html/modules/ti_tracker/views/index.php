<?php
/**
 * Vista índice — Seguimiento TI.
 *
 * @var Module_TiTracker $module
 * @var array $searches
 * @var array $totals
 * @var array $formats
 * @var array|null $notice
 */

$base = base_url('modules/ti_tracker');
$fmt = static fn(int|float $n): string => number_format((float)$n, 0, ',', '.');
$short = static fn(?string $date): string => $date === null || trim($date) === ''
    ? '—'
    : substr(trim($date), 0, 16);

/** Resumen legible de los filtros guardados. */
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
?>

<?php if (!empty($notice) && is_array($notice)): ?>
    <div class="alert alert-<?= e((string)($notice['type'] ?? 'info')) ?>" role="status">
        <?= e((string)($notice['text'] ?? '')) ?>
    </div>
<?php endif; ?>

<div class="page-header">
    <h1>Seguimiento TI</h1>
    <p class="subtitle">
        Búsquedas de IOCs guardadas con memoria de lo ya visto: cada ejecución
        marca las novedades y permite exportarlas a STIX, MISP o TXT.
    </p>
    <span class="spacer"></span>
    <a class="btn" href="<?= e($base . '/new') ?>">
        <?= icon('add', 18) ?> Nueva búsqueda
    </a>
</div>

<div class="alert alert-info" role="status">
    Las búsquedas se ejecutan contra la base local de IOCs ThreatFox
    (refrescada por su cron diario). El cron <code>ti-tracker-run.php</code>
    actualiza todas las búsquedas sin abrir la interfaz.
</div>

<div class="stat-strip mt-4">
    <div class="stat">
        <span class="stat-ico"><?= icon('radar', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($totals['searches'] ?? 0)) ?></div>
            <div class="stat-label">Búsquedas guardadas</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico ok"><?= icon('track_changes', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($totals['tracked'] ?? 0)) ?></div>
            <div class="stat-label">IOCs en seguimiento</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico"><?= icon('new_releases', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($totals['new_last'] ?? 0)) ?></div>
            <div class="stat-label">Novedades última ejecución</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico"><?= icon('download', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($totals['exports'] ?? 0)) ?></div>
            <div class="stat-label">Exportaciones</div>
        </div>
    </div>
</div>

<?php if ($searches === []): ?>
    <div class="card mt-6">
        <h2>Todavía no hay búsquedas guardadas</h2>
        <p class="text-sm text-ink-muted">
            Crea una búsqueda con los filtros que te interesen (malware, tipo de
            IOC, tag, confianza…) y ejecútala periódicamente. Los IOCs que
            aparezcan por primera vez se marcarán como novedad.
        </p>
        <a class="btn" href="<?= e($base . '/new') ?>">
            <?= icon('add', 18) ?> Crear la primera búsqueda
        </a>
    </div>
<?php else: ?>
    <div class="card p-0 mt-6 overflow-hidden">
        <div class="overflow-x-auto">
            <table class="data-table w-full">
                <thead>
                    <tr>
                        <th>Búsqueda</th>
                        <th class="col-secondary">Filtros</th>
                        <th>Seguimiento</th>
                        <th>Novedades</th>
                        <th class="col-secondary">Última ejecución</th>
                        <th>Exportar</th>
                        <th class="text-right">Acciones</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($searches as $search):
                    $id = (int)$search['id'];
                    $lastNew = $search['last_new'] !== null ? (int)$search['last_new'] : null;
                    $formatsForSearch = array_values(array_intersect(array_keys($formats), (array)$search['formats']));
                    ?>
                    <tr>
                        <td>
                            <strong><?= e((string)$search['name']) ?></strong>
                            <?php if (trim((string)$search['notes']) !== ''): ?>
                                <div class="text-xs text-ink-muted"><?= e(truncate((string)$search['notes'], 90)) ?></div>
                            <?php endif; ?>
                        </td>
                        <td class="col-secondary text-xs text-ink-muted">
                            <?= e($describe($search['filters'])) ?>
                        </td>
                        <td class="whitespace-nowrap">
                            <?= $fmt((int)$search['tracked']) ?> IOCs
                        </td>
                        <td class="whitespace-nowrap">
                            <?php if ($lastNew === null): ?>
                                <span class="text-ink-muted">—</span>
                            <?php elseif ($lastNew > 0): ?>
                                <span class="tag-chip good">+<?= $fmt($lastNew) ?></span>
                            <?php else: ?>
                                <span class="tag-chip excluded">0</span>
                            <?php endif; ?>
                        </td>
                        <td class="col-secondary whitespace-nowrap text-xs">
                            <?= e($short($search['last_run_at'] ?? null)) ?>
                            <?php if (!empty($search['last_export_at'])): ?>
                                <div class="text-ink-muted">export <?= e($short((string)$search['last_export_at'])) ?></div>
                            <?php endif; ?>
                        </td>
                        <td class="whitespace-nowrap">
                            <?php foreach ($formatsForSearch as $format): ?>
                                <button type="button" class="btn-tiny btn-outline btn"
                                        data-tt-export="<?= e($format) ?>"
                                        data-tt-url="<?= e($base . '/export/' . $id) ?>"
                                        title="Descargar <?= e($formats[$format] ?? strtoupper($format)) ?>">
                                    <?= e(strtoupper($format)) ?>
                                </button>
                            <?php endforeach; ?>
                        </td>
                        <td class="text-right whitespace-nowrap">
                            <form method="POST" action="<?= e($base . '/run/' . $id) ?>" class="inline">
                                <?= Csrf::field() ?>
                                <button type="submit" class="btn-tiny btn" title="Ejecutar y actualizar novedades">
                                    <?= icon('play_arrow', 16) ?> Ejecutar
                                </button>
                            </form>
                            <a class="btn-tiny btn-outline btn" href="<?= e($base . '/edit/' . $id) ?>">Editar</a>
                            <form method="POST" action="<?= e($base . '/delete/' . $id) ?>" class="inline"
                                  data-confirm="¿Eliminar la búsqueda «<?= e((string)$search['name']) ?>» y su seguimiento?"
                                  data-confirm-danger>
                                <?= Csrf::field() ?>
                                <button type="submit" class="btn-tiny btn-outline btn">Borrar</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
<?php endif; ?>

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
