<?php
/**
 * Vista índice del módulo IOCs ThreatFox.
 *
 * Componentes: md/ESPECIFICACION-UI.md §6 (page-header, stat-strip, chip-tabs,
 * input-field, alert, data-table, pager, modal).
 *
 * @var Module_Threatfox $module
 * @var array $filters
 * @var array $result
 * @var array $stats
 * @var array $ingests
 * @var array $catalogs
 * @var bool  $hasKey
 * @var bool  $keyEnv
 * @var array|null $backfill
 * @var array|null $notice
 * @var bool  $isAdmin
 */

$base = base_url('modules/threatfox');

/** Construye la URL del módulo conservando los filtros y cambiando $overrides. */
$urlWith = static function (array $overrides = [], string $path = '') use ($filters, $base): string {
    $query = [
        'source'      => $filters['source'],
        'mode'        => $filters['mode'],
        'search_term' => $filters['term'],
        'days'        => $filters['days'],
        'exact'       => $filters['exact'] ? 1 : 0,
        'limit'       => $filters['limit'],
        'f_malware'   => $filters['malware'],
        'f_ioc_type'  => $filters['ioc_type'],
        'f_threat'    => $filters['threat_type'],
        'f_tag'       => $filters['tag'],
        'f_conf'      => $filters['conf'],
        'f_ref'       => $filters['ref_only'] ? 1 : 0,
    ];
    $query = array_merge($query, $overrides);
    foreach ($query as $key => $value) {
        if ($value === '' || $value === null || $value === 0 || $value === false) {
            unset($query[$key]);
        }
    }
    return $base . $path . ($query ? '?' . http_build_query($query) : '');
};

$statusOk = ($result['status'] ?? '') === 'ok';
$fmt = static fn(int|float $n): string => number_format((float)$n, 0, ',', '.');
$perPage = max(1, (int)($result['perPage'] ?? 50));
$page = max(1, (int)($result['page'] ?? 1));
$totalPages = max(1, (int)($result['totalPages'] ?? 1));
$totalRows = (int)($result['total'] ?? 0);
$firstRow = $totalRows > 0 ? (($page - 1) * $perPage) + 1 : 0;
$lastRow = $totalRows > 0 ? min($totalRows, $page * $perPage) : 0;
?>

<?php if (!empty($notice) && is_array($notice)): ?>
    <div class="alert alert-<?= e((string)($notice['type'] ?? 'info')) ?>" role="status">
        <?= e((string)($notice['text'] ?? '')) ?>
    </div>
<?php endif; ?>

<?php if (!$hasKey): ?>
    <div class="alert alert-warning" role="status">
        No hay Auth-Key de abuse.ch configurada: solo puedes consultar la base local.
        <?php if ($isAdmin): ?>
            <a href="<?= e(base_url('admin/apis')) ?>#threatfox">Configúrala en Administración → APIs</a>.
        <?php endif; ?>
    </div>
<?php endif; ?>

<div class="page-header">
    <h1>IOCs ThreatFox</h1>
    <span class="count-chip"><?= $fmt((int)($stats['total'] ?? 0)) ?></span>
    <p class="subtitle">Indicadores de compromiso publicados por abuse.ch (ThreatFox).</p>
    <span class="spacer"></span>
    <a class="btn-outline btn" href="<?= e($urlWith([], '/export')) ?>">
        <?= icon('download', 18) ?>
        Configurar exportación
    </a>
    <?php if ($isAdmin): ?>
        <a class="btn-flat btn" href="<?= e(base_url('admin/apis')) ?>#threatfox">
            <?= icon('settings', 18) ?>
            Ajustes
        </a>
    <?php endif; ?>
</div>

<!-- KPIs de la base local -->
<div class="stat-strip">
    <div class="stat">
        <span class="stat-ico"><?= icon('bug_report', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($stats['total'] ?? 0)) ?></div>
            <div class="stat-label">IOCs en la base local</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico ok"><?= icon('update', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($stats['last24h'] ?? 0)) ?></div>
            <div class="stat-label">Ingestados en 24 h</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico info"><?= icon('coronavirus', 18) ?></span>
        <div>
            <div class="stat-num"><?= $fmt((int)($stats['malware'] ?? 0)) ?></div>
            <div class="stat-label">Familias de malware</div>
        </div>
    </div>
    <div class="stat">
        <span class="stat-ico warn"><?= icon('schedule', 18) ?></span>
        <div>
            <div class="stat-num text-base"><?= e((string)($ingests['daily']['finished_at'] ?? 'Sin ingesta')) ?></div>
            <div class="stat-label">Última ingesta diaria</div>
        </div>
    </div>
</div>

<!-- Fuente de datos -->
<div class="chip-tabs mt-4">
    <?php foreach (ThreatfoxQuery::SOURCES as $sourceKey => $sourceLabel): ?>
        <a class="chip<?= $filters['source'] === $sourceKey ? ' active' : '' ?>"
           href="<?= e($urlWith(['source' => $sourceKey, 'page' => 0])) ?>">
            <?= $sourceKey === 'db' ? icon('storage', 16) : icon('cloud', 16) ?>
            <?= e($sourceLabel) ?>
            <?php if ($sourceKey === 'db'): ?>
                <span class="chip-count"><?= $fmt((int)($stats['total'] ?? 0)) ?></span>
            <?php endif; ?>
        </a>
    <?php endforeach; ?>
</div>

<!-- Base local: ingesta y estado -->
<div class="card mt-4">
    <div class="card-head">
        <h2>Base local</h2>
        <span class="card-sub">
            <?= $fmt((int)($stats['total'] ?? 0)) ?> IOCs ·
            <?= e((string)(($stats['oldest'] ?? '') !== '' ? $stats['oldest'] : 'sin datos')) ?>
            →
            <?= e((string)(($stats['newest'] ?? '') !== '' ? $stats['newest'] : 'sin datos')) ?>
        </span>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
            <h3 class="text-sm font-semibold mb-2">Actualizar</h3>
            <p class="text-sm text-ink-muted mt-0 mb-3">
                La ingesta diaria pide a la API los IOCs de los últimos días y los guarda
                sin duplicar. Es la única llamada recurrente (fair use de abuse.ch).
            </p>
            <?php if ($isAdmin): ?>
                <form method="POST" action="<?= e($base) ?>/ingest" class="flex flex-wrap items-end gap-3">
                    <?= Csrf::field() ?>
                    <div class="input-field mb-0">
                        <label for="tf-ingest-days">Días a descargar</label>
                        <select id="tf-ingest-days" name="days">
                            <?php for ($d = 1; $d <= THREATFOX_DAYS_MAX; $d++): ?>
                                <option value="<?= $d ?>" <?= $d === THREATFOX_DEFAULT_DAYS ? 'selected' : '' ?>>
                                    <?= $d ?> día<?= $d === 1 ? '' : 's' ?>
                                </option>
                            <?php endfor; ?>
                        </select>
                    </div>
                    <button type="submit" class="btn mb-3"><?= icon('sync', 18) ?> Actualizar base local</button>
                </form>

                <form method="POST" action="<?= e($base) ?>/backfill/start" class="mt-3"
                      data-confirm="Se descargará el histórico completo (~6 meses) y se importará por bloques. ¿Continuar?">
                    <?= Csrf::field() ?>
                    <button type="submit" class="btn-outline btn">
                        <?= icon('cloud_download', 18) ?> Descargar histórico completo
                    </button>
                </form>
            <?php else: ?>
                <p class="text-sm text-ink-muted">Solo un administrador puede lanzar la ingesta.</p>
            <?php endif; ?>
        </div>

        <div>
            <h3 class="text-sm font-semibold mb-2">Últimas ingestas</h3>
            <table class="data-table w-full text-sm">
                <thead>
                    <tr>
                        <th>Tipo</th>
                        <th>Filas</th>
                        <th>Total</th>
                        <th>Terminada</th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($ingests)): ?>
                    <tr><td colspan="4" class="text-ink-muted">Sin ingestas registradas.</td></tr>
                <?php else: ?>
                    <?php foreach ($ingests as $type => $row): ?>
                        <tr>
                            <td><?= e($type === 'full' ? 'Histórico completo' : 'Diaria') ?></td>
                            <td><?= $fmt((int)($row['rows'] ?? 0)) ?></td>
                            <td><?= $fmt((int)($row['total'] ?? 0)) ?></td>
                            <td class="whitespace-nowrap text-xs"><?= e((string)($row['finished_at'] ?? '')) ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <?php if (!empty($backfill)): ?>
        <div class="alert alert-info mt-4" id="tf-backfill">
            <p class="m-0 mb-2">
                Importando el histórico completo:
                <strong id="tf-backfill-done"><?= $fmt((int)($backfill['rows_done'] ?? 0)) ?></strong>
                de <strong id="tf-backfill-total"><?= $fmt((int)($backfill['rows_total'] ?? 0)) ?></strong> filas.
            </p>
            <div class="progress">
                <?php $pct = ((int)($backfill['rows_total'] ?? 0) > 0)
                    ? min(100, (int)round(((int)$backfill['rows_done'] / (int)$backfill['rows_total']) * 100))
                    : 0; ?>
                <div class="determinate" id="tf-backfill-bar" style="width: <?= $pct ?>%"></div>
            </div>
            <p class="text-xs text-ink-muted m-0">
                La importación continúa sola; puedes cerrar la página y volver más tarde.
            </p>
        </div>
    <?php endif; ?>
</div>

<!-- Filtros -->
<form method="GET" action="<?= e($base) ?>" class="card p-5 mt-6">
    <input type="hidden" name="source" value="<?= e($filters['source']) ?>">

    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-x-4">
        <div class="input-field xl:col-span-2">
            <label for="tf-mode">Modo de búsqueda</label>
            <select id="tf-mode" name="mode">
                <?php foreach (ThreatfoxQuery::MODES as $modeKey => $modeLabel): ?>
                    <option value="<?= e($modeKey) ?>" <?= $filters['mode'] === $modeKey ? 'selected' : '' ?>>
                        <?= e($modeLabel) ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <span class="helper-text">Automático detecta el tipo del indicador por su forma.</span>
        </div>

        <div class="input-field xl:col-span-2">
            <label for="tf-term">Término de búsqueda</label>
            <input type="search" id="tf-term" name="search_term" maxlength="300"
                   value="<?= e($filters['term']) ?>"
                   placeholder="dominio, url, ip:puerto, hash, familia o tag">
            <span class="helper-text">Varios términos separados por comas se combinan con AND.</span>
        </div>

        <div class="input-field">
            <label for="tf-days">Días (solo recientes)</label>
            <select id="tf-days" name="days">
                <option value="0" <?= $filters['days'] === 0 ? 'selected' : '' ?>>Todos</option>
                <?php for ($d = 1; $d <= THREATFOX_DAYS_MAX; $d++): ?>
                    <option value="<?= $d ?>" <?= $filters['days'] === $d ? 'selected' : '' ?>>
                        Últimos <?= $d ?> día<?= $d === 1 ? '' : 's' ?>
                    </option>
                <?php endfor; ?>
            </select>
        </div>

        <div class="input-field">
            <label for="tf-limit">Límite en la API</label>
            <input type="number" id="tf-limit" name="limit" min="1" max="1000" step="1"
                   value="<?= (int)$filters['limit'] ?>">
        </div>

        <div class="input-field">
            <label for="tf-malware">Familia de malware</label>
            <input type="text" id="tf-malware" name="f_malware" maxlength="120"
                   value="<?= e($filters['malware']) ?>" placeholder="ej. win.cobalt_strike">
        </div>

        <div class="input-field">
            <label for="tf-ioc-type">Tipo de IOC</label>
            <select id="tf-ioc-type" name="f_ioc_type">
                <option value="">Todos</option>
                <?php foreach ($catalogs['ioc_type'] as $type): ?>
                    <option value="<?= e((string)$type) ?>" <?= $filters['ioc_type'] === (string)$type ? 'selected' : '' ?>>
                        <?= e((string)$type) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="input-field">
            <label for="tf-threat">Tipo de amenaza</label>
            <select id="tf-threat" name="f_threat">
                <option value="">Todos</option>
                <?php foreach ($catalogs['threat_type'] as $type): ?>
                    <option value="<?= e((string)$type) ?>" <?= $filters['threat_type'] === (string)$type ? 'selected' : '' ?>>
                        <?= e((string)$type) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="input-field">
            <label for="tf-tag">Tag</label>
            <input type="text" id="tf-tag" name="f_tag" maxlength="80"
                   value="<?= e($filters['tag']) ?>" placeholder="ej. Magecart">
        </div>

        <div class="input-field">
            <label for="tf-conf">Confianza mínima</label>
            <input type="number" id="tf-conf" name="f_conf" min="0" max="100" step="1"
                   value="<?= (int)$filters['conf'] ?>">
        </div>

        <div class="input-field">
            <label>Opciones</label>
            <div class="flex flex-wrap items-center gap-4 pt-2">
                <label class="check-inline" for="tf-exact">
                    <input type="checkbox" id="tf-exact" name="exact" value="1" <?= $filters['exact'] ? 'checked' : '' ?>>
                    <span class="text-sm">Coincidencia exacta</span>
                </label>
                <label class="check-inline" for="tf-ref">
                    <input type="checkbox" id="tf-ref" name="f_ref" value="1" <?= $filters['ref_only'] ? 'checked' : '' ?>>
                    <span class="text-sm">Solo con referencia</span>
                </label>
            </div>
        </div>
    </div>

    <div class="flex flex-wrap items-center gap-3 mt-2">
        <button type="submit" class="btn"><?= icon('search', 18) ?> Buscar</button>
        <a class="btn-outline btn" href="<?= e($base) ?>">Limpiar</a>
        <span class="text-xs text-ink-muted">
            El filtro de días solo se aplica en el modo «Recientes», igual que en la API.
        </span>
    </div>
</form>

<!-- Estado de la consulta -->
<div class="hint-bar mt-4">
    <span class="hint">
        <?= icon('info', 16) ?>
        <?= e((string)($result['message'] ?? '')) ?>
    </span>
    <?php if ($statusOk): ?>
        <span class="hint">
            <?= icon('format_list_numbered', 16) ?>
            <?= $fmt($firstRow) ?>–<?= $fmt($lastRow) ?> de <?= $fmt($totalRows) ?>
        </span>
        <?php if (($result['api_count'] ?? null) !== null && (int)$result['api_count'] > 0): ?>
            <span class="hint">
                <?= icon('cloud_download', 16) ?>
                La API devolvió <?= $fmt((int)$result['api_count']) ?>
            </span>
        <?php endif; ?>
        <?php if (!empty($result['detected'])): ?>
            <span class="hint">
                <?= icon('label', 16) ?>
                Tipo detectado: <strong><?= e((string)$result['detected']) ?></strong>
            </span>
        <?php endif; ?>
        <?php if (!empty($result['relay'])): ?>
            <span class="hint">
                <?= icon('sync_alt', 16) ?>
                Relé automático a la API
            </span>
        <?php endif; ?>
    <?php endif; ?>
</div>

<!-- Resultados -->
<div class="card p-0 overflow-hidden">
    <div class="overflow-x-auto">
        <table class="data-table w-full">
            <thead>
                <tr>
                    <th>IOC</th>
                    <th>Tipo</th>
                    <th class="col-secondary">Amenaza</th>
                    <th class="col-secondary">Malware</th>
                    <th>Conf.</th>
                    <th class="col-secondary">Primera vez</th>
                    <th class="col-secondary">Tags</th>
                    <th class="col-secondary">Referencia</th>
                    <th class="text-right">Detalle</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!$statusOk || empty($result['rows'])): ?>
                <tr>
                    <td colspan="9" class="text-sm text-ink-muted">
                        <?= e((string)($result['message'] ?? 'Sin resultados.')) ?>
                    </td>
                </tr>
            <?php else: ?>
                <?php $details = []; ?>
                <?php foreach ($result['rows'] as $index => $row):
                    $ioc = (string)($row['ioc'] ?? '');
                    $conf = (int)($row['confidence_level'] ?? 0);
                    $confClass = $conf >= 75 ? 'good' : ($conf >= 50 ? 'observing' : 'excluded');
                    $reference = (string)($row['reference'] ?? '');
                    $detailId = 'tf-detail-' . $index;

                    /* Ficha completa: se serializa una sola vez y el modal la
                       pinta con DOM (sin duplicar markup por fila). */
                    $details[$detailId] = array_filter([
                        'IOC'               => $ioc,
                        'Tipo de IOC'       => (string)($row['ioc_type'] ?? ''),
                        'Tipo de amenaza'   => (string)($row['threat_type'] ?? ''),
                        'Malware'           => (string)($row['malware'] ?? ''),
                        'Malware (legible)' => (string)($row['malware_printable'] ?? ''),
                        'Alias'             => (string)($row['malware_alias'] ?? ''),
                        'Confianza'         => (string)$conf,
                        'Primera vez'       => (string)($row['first_seen'] ?? ''),
                        'Última vez'        => (string)($row['last_seen'] ?? ''),
                        'Reporter'          => (string)($row['reporter'] ?? ''),
                        'Tags'              => implode(', ', (array)($row['tags_list'] ?? [])),
                        'Referencia'        => $reference,
                        'Ingestado'         => (string)($row['ingested_at'] ?? ''),
                    ], static fn($value) => trim((string)$value) !== '');
                    ?>
                    <tr>
                        <td class="font-mono break-all"><?= e($ioc) ?></td>
                        <td><?= e((string)($row['ioc_type'] ?? '')) ?></td>
                        <td class="col-secondary"><?= e((string)($row['threat_type'] ?? '')) ?></td>
                        <td class="col-secondary"><?= e((string)($row['malware_printable'] ?? $row['malware'] ?? '')) ?></td>
                        <td><span class="tag-chip <?= $confClass ?>"><?= $conf ?></span></td>
                        <td class="col-secondary whitespace-nowrap text-xs"><?= e((string)($row['first_seen'] ?? '')) ?></td>
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
                                    data-tf-detail="<?= e($detailId) ?>"
                                    data-tf-title="<?= e(truncate($ioc, 60)) ?>"
                                    title="Ver la ficha completa del IOC">
                                Ver
                            </button>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Datos de la ficha de detalle (una sola serialización) -->
<?php if (!empty($details)): ?>
    <script type="application/json" id="tf-detail-data"><?= json_encode(
        $details,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    ) ?></script>
<?php endif; ?>

<!-- Paginación -->
<?php if ($statusOk && $totalPages > 1): ?>
    <div class="pager">
        <span class="pagination-info">
            Mostrando <?= $fmt($firstRow) ?>–<?= $fmt($lastRow) ?> de <?= $fmt($totalRows) ?>
        </span>
        <div class="flex items-center gap-2">
            <?php if ($page > 1): ?>
                <a class="btn-outline btn btn-small" href="<?= e($urlWith(['page' => $page - 1])) ?>">Anterior</a>
            <?php endif; ?>
            <span class="text-sm text-ink-muted">Página <?= $page ?> de <?= $totalPages ?></span>
            <?php if ($page < $totalPages): ?>
                <a class="btn-outline btn btn-small" href="<?= e($urlWith(['page' => $page + 1])) ?>">Siguiente</a>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

<!-- Modal de detalle (se rellena con el bloque que ya pintó el servidor) -->
<div class="tdl-modal-overlay" id="tf-detail-overlay" hidden>
    <div class="tdl-modal" role="dialog" aria-modal="true" aria-labelledby="tf-detail-title">
        <div class="tdl-modal-head">
            <?= icon('fingerprint', 20) ?>
            <span id="tf-detail-title">Detalle del IOC</span>
        </div>
        <div class="tdl-modal-body" id="tf-detail-body"></div>
        <div class="tdl-modal-actions">
            <button type="button" class="btn-outline btn btn-small" data-tf-close>Volver</button>
        </div>
    </div>
</div>

<script>
(function () {
    'use strict';

    var overlay = document.getElementById('tf-detail-overlay');
    var body = document.getElementById('tf-detail-body');
    var title = document.getElementById('tf-detail-title');
    var dataEl = document.getElementById('tf-detail-data');
    var details = {};
    try {
        details = dataEl ? JSON.parse(dataEl.textContent) : {};
    } catch (e) {
        details = {};
    }

    function closeDetail() {
        if (!overlay) { return; }
        overlay.hidden = true;
        body.innerHTML = '';
    }

    /* Pinta la ficha con DOM (textContent): el JSON del servidor nunca se
       interpreta como HTML. */
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
        copy.setAttribute('data-tf-copy', fields['IOC'] || '');
        copy.textContent = 'Copiar IOC';
        actions.appendChild(copy);
        body.appendChild(actions);
    }

    document.addEventListener('click', function (event) {
        var trigger = event.target.closest('[data-tf-detail]');
        if (trigger) {
            if (!overlay) { return; }
            renderDetail(trigger.getAttribute('data-tf-detail'));
            title.textContent = trigger.getAttribute('data-tf-title') || 'Detalle del IOC';
            overlay.hidden = false;
            return;
        }

        if (event.target.closest('[data-tf-close]') || event.target === overlay) {
            closeDetail();
            return;
        }

        var copy = event.target.closest('[data-tf-copy]');
        if (copy) {
            var value = copy.getAttribute('data-tf-copy') || '';
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

    /* Progreso del histórico completo: pide bloques hasta terminar (solo admin). */
    var progress = <?= $isAdmin ? "document.getElementById('tf-backfill')" : 'null' ?>;
    if (progress) {
        var doneEl = document.getElementById('tf-backfill-done');
        var barEl = document.getElementById('tf-backfill-bar');
        var url = <?= json_encode($base . '/backfill/chunk') ?>;

        var step = function () {
            fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (res) { return res.json(); })
                .then(function (data) {
                    if (data.error) {
                        toast('Error en la importación: ' + data.error, 'error');
                        return;
                    }
                    if (doneEl) { doneEl.textContent = new Intl.NumberFormat('es-ES').format(data.rows_done); }
                    if (barEl && data.rows_total > 0) {
                        barEl.style.width = Math.min(100, Math.round((data.rows_done / data.rows_total) * 100)) + '%';
                    }
                    if (data.done) {
                        toast('Histórico completo importado', 'success');
                        window.location.reload();
                        return;
                    }
                    window.setTimeout(step, 400);
                })
                .catch(function () {
                    toast('Se perdió la conexión durante la importación', 'error');
                });
        };
        window.setTimeout(step, 600);
    }
})();
</script>
