<?php
/**
 * Vista de resultados de una búsqueda — Seguimiento TI TF.
 *
 * @var Module_TiTracker $module
 * @var array $search
 * @var array $exec
 * @var array $rows
 * @var array $details
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

/* Modo lectura: datos del snapshot de la última ejecución (sin red). */
$exec = is_array($exec ?? null) ? $exec : [];
$readonly = (bool)($readonly ?? false);
$runAt = trim((string)($runAt ?? ''));

$total = (int)($exec['result']['rows'] ?? 0);
$newCount = (int)($exec['result']['new'] ?? 0);
$tracked = (int)($exec['result']['tracked'] ?? 0);
$source = ((string)($exec['source'] ?? 'db')) === 'api' ? 'API en vivo' : 'Base local';
if ($readonly) {
    $source .= ' (guardado)';
}

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

<?php if ($readonly): ?>
    <div class="alert alert-info" role="status">
        <?php if ($exec === []): ?>
            Esta búsqueda todavía no tiene resultados guardados. Pulsa «Ejecutar ahora» para generarlos.
        <?php else: ?>
            Resultados de la última ejecución<?= $runAt !== '' ? ' (' . e($runAt) . ')' : '' ?>.
            No se ha consultado la fuente: esta vista muestra lo guardado en esa ejecución.
        <?php endif; ?>
    </div>
<?php endif; ?>

<div class="page-header">
    <h1><?= e((string)$search['name']) ?></h1>
    <p class="subtitle">
        <?= e($describe($search['filters'])) ?>
        <?php if ($readonly && $runAt !== ''): ?>
            · Última ejecución: <?= e($runAt) ?>
        <?php endif; ?>
    </p>
    <span class="spacer"></span>
    <?php if ($readonly): ?>
        <form method="POST" action="<?= e($base . '/run/' . (int)$search['id']) ?>" class="inline">
            <?= Csrf::field() ?>
            <button type="submit" class="btn-outline btn" title="Volver a consultar y actualizar novedades">
                <?= icon('play_arrow', 18) ?> Ejecutar ahora
            </button>
        </form>
    <?php endif; ?>
    <?php foreach ($formatsForSearch as $format): ?>
        <button type="button" class="btn-outline btn"
                data-tt-export="<?= e($format) ?>"
                data-tt-search="<?= (int)$search['id'] ?>"
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
        <strong><?= $fmt($newCount) ?> IOCs nuevos</strong>
        <?= $readonly ? 'en esa ejecución' : 'desde la última ejecución de esta búsqueda' ?>.
        Puedes exportarlos a STIX, MISP o TXT con los botones de arriba.
        <?php
            $newIocsJson = json_encode(
                array_values((array)($exec['result']['new_iocs'] ?? [])),
                JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
            );
        ?>
        <button type="button" class="btn-outline btn btn-small ml-2"
                data-tt-export="stix"
                data-tt-search="<?= (int)$search['id'] ?>"
                data-tt-scope="new"
                data-tt-new='<?= e((string)$newIocsJson) ?>'>
            <?= icon('new_releases', 16) ?> Exportar solo los <?= $fmt($newCount) ?> nuevos
        </button>
    </div>
<?php elseif ($total > 0): ?>
    <div class="alert alert-info mt-4" role="status">
        <?php if ($readonly): ?>
            En esa ejecución los <?= $fmt($total) ?> IOCs ya estaban en el seguimiento.
        <?php else: ?>
            Sin novedades: los <?= $fmt($total) ?> IOCs de esta ejecución ya estaban en el seguimiento.
        <?php endif; ?>
    </div>
<?php endif; ?>

<div class="card p-0 mt-6 overflow-hidden">
    <div class="overflow-x-auto">
        <table class="data-table w-full">
            <thead>
                <tr>
                    <th>IOC</th>
                    <th>Tipo</th>
                    <th class="col-secondary">Amenaza</th>
                    <th class="col-secondary">Malware</th>
                    <th>Conf.</th>
                    <th>Primera vez</th>
                    <th class="col-secondary">Tags</th>
                    <th class="col-secondary">Referencia</th>
                    <th class="text-right">Detalle</th>
                    <th class="text-right">Estado</th>
                </tr>
            </thead>
            <tbody>
            <?php if ($rows === []): ?>
                <tr>
                    <td colspan="10" class="text-sm text-ink-muted">
                        <?php if ($readonly): ?>
                            Todavía no hay resultados guardados para esta búsqueda. Pulsa «Ejecutar ahora» para generarlos.
                        <?php else: ?>
                            La búsqueda no devuelve IOCs ahora mismo. Revisa los filtros o espera a la próxima ingesta.
                        <?php endif; ?>
                    </td>
                </tr>
            <?php else: ?>
                <?php foreach ($rows as $index => $row):
                    $ioc = (string)($row['ioc'] ?? '');
                    $conf = (int)($row['confidence_level'] ?? 0);
                    $confClass = $conf >= 75 ? 'good' : ($conf >= 50 ? 'observing' : 'excluded');
                    $reference = (string)($row['reference'] ?? '');
                    $detailId = 'tt-detail-' . $index;
                    $isNew = isset($newKeys[$ioc]);
                    ?>
                    <tr>
                        <td class="font-mono break-all"><?= e($ioc) ?></td>
                        <td><?= e((string)($row['ioc_type'] ?? '')) ?></td>
                        <td class="col-secondary"><?= e((string)($row['threat_type'] ?? '')) ?></td>
                        <td class="col-secondary"><?= e((string)($row['malware_printable'] ?? $row['malware'] ?? '')) ?></td>
                        <td><span class="tag-chip <?= $confClass ?>"><?= $conf ?></span></td>
                        <td class="whitespace-nowrap text-xs"><?= e((string)($row['first_seen'] ?? '')) ?></td>
                        <td class="col-secondary">
                            <?php foreach (array_slice((array)($row['tags_list'] ?? []), 0, 3) as $tag): ?>
                                <span class="tag-chip excluded"><?= e((string)$tag) ?></span>
                            <?php endforeach; ?>
                        </td>
                        <td class="col-secondary text-xs">
                            <?php if ($reference !== '' && filter_var($reference, FILTER_VALIDATE_URL)): ?>
                                <a href="<?= e($reference) ?>" target="_blank" rel="noopener noreferrer"
                                   title="<?= e($reference) ?>">abrir</a>
                            <?php else: ?>
                                —
                            <?php endif; ?>
                        </td>
                        <td class="text-right whitespace-nowrap">
                            <button type="button" class="btn-tiny btn-outline btn"
                                    data-tt-detail="<?= e($detailId) ?>"
                                    data-tt-title="<?= e(truncate($ioc, 60)) ?>"
                                    title="Ver la ficha completa del IOC">
                                Ver
                            </button>
                        </td>
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

<!-- Datos de la ficha de detalle (una sola serialización, igual que ThreatFox) -->
<?php if (!empty($details)): ?>
    <script type="application/json" id="tt-detail-data"><?= json_encode(
        $details,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    ) ?></script>
<?php endif; ?>

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
                    $kindLabel = $isRun ? 'Ejecución'
                        : ((string)$item['kind'] === 'api_pull' ? 'Consulta API' : 'Exportación');
                    $detail = (string)($item['detail'] ?? '');
                    if (str_contains($detail, '|')) {
                        $detail = (string)str_replace('|', ' · ', $detail);
                    }
                    ?>
                    <tr>
                        <td class="whitespace-nowrap text-xs"><?= e($short((string)$item['created_at'])) ?></td>
                        <td><?= e($kindLabel) ?></td>
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

<!-- Modal de detalle (misma ficha que IOCs ThreatFox) -->
<div class="tdl-modal-overlay" id="tt-detail-overlay" hidden>
    <div class="tdl-modal" role="dialog" aria-modal="true" aria-labelledby="tt-detail-title">
        <div class="tdl-modal-head">
            <?= icon('fingerprint', 20) ?>
            <span id="tt-detail-title">Detalle del IOC</span>
        </div>
        <div class="tdl-modal-body" id="tt-detail-body"></div>
        <div class="tdl-modal-actions">
            <button type="button" class="btn-outline btn btn-small" data-tt-close>Volver</button>
        </div>
    </div>
</div>

<script>
(function () {
    'use strict';

    var overlay = document.getElementById('tt-detail-overlay');
    if (!overlay) { return; }

    var body = document.getElementById('tt-detail-body');
    var title = document.getElementById('tt-detail-title');
    var dataEl = document.getElementById('tt-detail-data');
    var details = {};
    try {
        details = dataEl ? JSON.parse(dataEl.textContent) : {};
    } catch (e) {
        details = {};
    }

    function closeDetail() {
        overlay.hidden = true;
        body.innerHTML = '';
    }

    /* Misma ficha que ThreatFox: DOM con textContent, nunca HTML del JSON. */
    function renderDetail(key) {
        var fields = details[key] || {};
        body.innerHTML = '';

        var list = document.createElement('dl');
        list.className = 'grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm';

        Object.keys(fields).forEach(function (label) {
            var value = fields[label];
            if (!value) { return; }

            var wrap = document.createElement('div');
            var term = document.createElement('dt');
            term.className = 'text-xs text-ink-muted';
            term.textContent = label;

            var desc = document.createElement('dd');
            desc.className = 'm-0 break-all' + (label === 'IOC' ? ' font-mono' : '');

            if (label === 'Referencia' && /^https?:\/\//i.test(value)) {
                var link = document.createElement('a');
                link.href = value;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.textContent = value;
                desc.appendChild(link);
            } else {
                desc.textContent = value;
            }

            wrap.appendChild(term);
            wrap.appendChild(desc);
            list.appendChild(wrap);
        });

        body.appendChild(list);

        var actions = document.createElement('div');
        actions.className = 'mt-3';
        var copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'btn-outline btn btn-small';
        copy.setAttribute('data-tt-copy', fields['IOC'] || '');
        copy.textContent = 'Copiar IOC';
        actions.appendChild(copy);
        body.appendChild(actions);
    }

    document.addEventListener('click', function (event) {
        var trigger = event.target.closest('[data-tt-detail]');
        if (trigger) {
            renderDetail(trigger.getAttribute('data-tt-detail'));
            title.textContent = trigger.getAttribute('data-tt-title') || 'Detalle del IOC';
            overlay.hidden = false;
            return;
        }

        if (event.target.closest('[data-tt-close]') || event.target === overlay) {
            closeDetail();
            return;
        }

        var copy = event.target.closest('[data-tt-copy]');
        if (copy) {
            var value = copy.getAttribute('data-tt-copy') || '';
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(value).then(function () {
                    toast('IOC copiado al portapapeles', 'success');
                }).catch(function () {
                    toast('No se pudo copiar el IOC', 'error');
                });
            } else {
                toast('El portapapeles no está disponible en este navegador', 'warning');
            }
        }
    });

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') { closeDetail(); }
    });
})();
</script>

<script>
(function () {
    'use strict';
    if (window.__tiTrackerExportBound) { return; }
    window.__tiTrackerExportBound = true;

    document.addEventListener('click', function (event) {
        var button = event.target.closest('[data-tt-export]');
        if (!button) { return; }

        var format = button.getAttribute('data-tt-export');
        var searchId = parseInt(button.getAttribute('data-tt-search') || '0', 10);
        if (!searchId || typeof IOCExtractor === 'undefined') {
            toast('El asistente de IOCs no está disponible.', 'error');
            return;
        }

        var opts = {
            source: 'ti_tracker',
            searchId: searchId,
            format: format,
            scope: button.getAttribute('data-tt-scope') || 'all'
        };
        if (opts.scope === 'new') {
            try {
                opts.newIocs = JSON.parse(button.getAttribute('data-tt-new') || '[]');
            } catch (e) {
                opts.newIocs = [];
            }
        }
        IOCExtractor.open(opts);
    });
})();
</script>
